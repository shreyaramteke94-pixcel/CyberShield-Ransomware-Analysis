"""
Sandbox Execution Manager.

Manages dynamic sandbox analysis jobs using isolated container environments.
Ensures strict defensive isolation:
- Network disabled (--network none)
- Non-root unprivileged execution (--user 1000:1000)
- Read-only root filesystem (--read-only)
- Read-only sample mount (-v sample:ro)
- Isolated output directory mount
- Writable tmpfs for /tmp (--tmpfs /tmp:rw,noexec,nosuid,size=64m)
- Capabilities dropped (--cap-drop ALL)
- No new privileges (--security-opt no-new-privileges:true)
- Resource caps (--cpus 1.0, --memory 512m, --pids-limit 64)
- Strict execution timeouts with automated cleanup (--rm)

CRITICAL SAFETY POLICY:
If the isolated container runtime (Docker) or verified sandbox image is unavailable,
the job status is set to UNAVAILABLE with full diagnostics. Execution directly
on the host machine (via subprocess, os.system, or shell) is STRICTLY PROHIBITED.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import subprocess
import tempfile
import threading
from typing import Any, Optional
import uuid

from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import SessionLocal
from app.repositories.sandbox_job_repository import SandboxJobRepository
from app.sandbox.detector import (
    DEFAULT_SANDBOX_IMAGE,
    get_sandbox_status,
)
from app.sandbox.schemas import (
    SandboxJobResponse,
    SandboxStatus,
)

logger = logging.getLogger(__name__)

IMAGE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-./:]{1,128}$")


class SandboxManager:
    """
    Thread-safe orchestrator for dynamic sandbox analysis jobs.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, SandboxJobResponse] = {}

    def _persist_job(self, job: SandboxJobResponse, db: Optional[Session] = None) -> None:
        """Persist or update job in SQLite database safely."""
        if db is not None:
            try:
                SandboxJobRepository.create_or_update(db, job)
            except Exception as e:
                logger.error("Failed to persist sandbox job %s with provided db session: %s", job.job_id, e)
            return

        try:
            session = SessionLocal()
            try:
                SandboxJobRepository.create_or_update(session, job)
            finally:
                session.close()
        except Exception as e:
            logger.error("Failed to persist sandbox job %s with SessionLocal: %s", job.job_id, e)

    def create_job(
        self,
        sample_id: str,
        filename: str,
        sample_path: Optional[Path] = None,
        confirm_dynamic_execution: bool = True,
        timeout_seconds: int = 60,
        db: Optional[Session] = None,
    ) -> SandboxJobResponse:
        """
        Create and dispatch a dynamic analysis sandbox job.

        If Docker or the required image is not ready, sets status to UNAVAILABLE
        without running any command on the host.
        """
        job_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        if not confirm_dynamic_execution:
            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=SandboxStatus.FAILED,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=[],
                error_message="Dynamic execution was rejected because explicit confirmation was not provided.",
                process_tree=[],
                network_beacons=[],
                runtime_events=[],
                security_verifications={},
                execution_summary="Dynamic analysis rejected: confirmation flag was false.",
            )
            with self._lock:
                self._jobs[job_id] = job
            self._persist_job(job, db=db)
            return job

        # Check Docker environment readiness
        detector_status = get_sandbox_status()

        if not detector_status.dynamic_analysis_ready:
            # Container isolation is unavailable; strictly refuse host execution
            diag_str = "; ".join(detector_status.diagnostics)
            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=SandboxStatus.UNAVAILABLE,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=["pre_flight_environment_check"],
                error_message=(
                    f"Dynamic container execution is unavailable. {diag_str}. "
                    "Host execution is strictly prohibited."
                ),
                process_tree=[],
                network_beacons=[],
                runtime_events=[],
                security_verifications={
                    "network_disabled": True,
                    "non_root_enforced": True,
                    "read_only_rootfs": True,
                    "read_only_sample_mount": True,
                    "host_execution_prevented": True,
                },
                execution_summary=(
                    "Dynamic analysis was not executed because the isolated container runtime "
                    "is not available on this host. Subprocess execution on the host machine is prohibited."
                ),
            )
            with self._lock:
                self._jobs[job_id] = job
            self._persist_job(job, db=db)
            logger.warning(
                "Sandbox job %s rejected: container runtime unavailable (%s)",
                job_id,
                diag_str,
            )
            return job

        # Container runtime is available - execute isolated container
        return self._execute_container_job(
            job_id=job_id,
            sample_id=sample_id,
            filename=filename,
            sample_path=sample_path,
            timeout_seconds=timeout_seconds,
            image_name=detector_status.sandbox_image,
            db=db,
        )

    def _execute_container_job(
        self,
        job_id: str,
        sample_id: str,
        filename: str,
        sample_path: Optional[Path],
        timeout_seconds: int,
        image_name: str,
        db: Optional[Session] = None,
    ) -> SandboxJobResponse:
        """
        Execute sample within isolated container with hard security boundaries.
        """
        created_at = datetime.now(timezone.utc).isoformat()

        # Validate sample path and storage containment
        if not sample_path or not sample_path.exists():
            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=SandboxStatus.FAILED,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=["pre_flight_sample_check"],
                error_message="Target sample file does not exist on disk.",
                process_tree=[],
                network_beacons=[],
                runtime_events=[],
                security_verifications={},
                execution_summary="Failed to locate sample file for container mounting.",
            )
            with self._lock:
                self._jobs[job_id] = job
            self._persist_job(job, db=db)
            return job

        # Defense-in-depth: Assert sample_path resides strictly within UPLOAD_DIR
        upload_dir = Path(settings.UPLOAD_DIR).resolve()
        resolved_sample = sample_path.resolve()
        try:
            resolved_sample.relative_to(upload_dir)
        except ValueError:
            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=SandboxStatus.FAILED,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=["containment_verification"],
                error_message="Security violation: sample path outside upload repository.",
                process_tree=[],
                network_beacons=[],
                runtime_events=[],
                security_verifications={"host_execution_prevented": True},
                execution_summary="Sample path rejected due to storage containment violation.",
            )
            with self._lock:
                self._jobs[job_id] = job
            self._persist_job(job, db=db)
            return job

        # Validate image name format
        if not image_name or not IMAGE_NAME_REGEX.match(image_name):
            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=SandboxStatus.FAILED,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=["image_provenance_check"],
                error_message="Invalid container image name.",
                process_tree=[],
                network_beacons=[],
                runtime_events=[],
                security_verifications={},
                execution_summary="Container execution aborted: invalid image name specification.",
            )
            with self._lock:
                self._jobs[job_id] = job
            self._persist_job(job, db=db)
            return job

        # Register running state so concurrent GET /jobs/{job_id} sees RUNNING
        running_job = SandboxJobResponse(
            job_id=job_id,
            sample_id=sample_id,
            filename=filename,
            status=SandboxStatus.RUNNING,
            created_at=created_at,
            completed_at=None,
            operations_run=["container_boundary_setup"],
            error_message=None,
            process_tree=[],
            network_beacons=[],
            runtime_events=[],
            security_verifications={
                "network_disabled": True,
                "non_root_enforced": True,
                "read_only_rootfs": True,
                "read_only_sample_mount": True,
                "host_execution_prevented": True,
            },
            execution_summary="Dynamic analysis in progress within isolated container...",
        )
        with self._lock:
            self._jobs[job_id] = running_job
        self._persist_job(running_job, db=db)

        container_name = f"cybershield-sandbox-{job_id[:8]}"
        posix_sample_path = resolved_sample.as_posix()

        # Isolated output directory
        temp_dir = tempfile.TemporaryDirectory(prefix="cs_sandbox_")
        output_dir = Path(temp_dir.name).resolve()
        posix_output_path = output_dir.as_posix()

        docker_cmd = [
            "docker", "run",
            "--name", container_name,
            "--rm",
            "--network", "none",
            "--user", "1000:1000",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--cpus", "1.0",
            "--memory", "512m",
            "--pids-limit", "64",
            "-v", f"{posix_sample_path}:/sandbox/sample:ro",
            "-v", f"{posix_output_path}:/sandbox/output:rw",
            image_name,
        ]

        try:
            res = subprocess.run(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )

            status = SandboxStatus.COMPLETED if res.returncode == 0 else SandboxStatus.FAILED
            error_msg = None if res.returncode == 0 else f"Container exited with code {res.returncode}: {res.stderr[:500]}"

            # Safely retrieve real telemetry output if written by container
            process_tree: list[dict[str, Any]] = []
            network_beacons: list[dict[str, Any]] = []
            runtime_events: list[dict[str, Any]] = []
            telemetry_data: dict[str, Any] = {}

            telemetry_path = output_dir / "telemetry.json"
            if telemetry_path.is_file() and telemetry_path.stat().st_size <= 1024 * 1024:
                try:
                    loaded = json.loads(telemetry_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        telemetry_data = loaded
                        process_tree = telemetry_data.get("process_tree", [])
                        network_beacons = telemetry_data.get("network_beacons", [])
                        runtime_events = telemetry_data.get("runtime_events", [])
                except Exception as json_err:
                    logger.warning("Failed to parse sandbox telemetry output: %s", json_err)

            sec_verifs = {
                "network_disabled": True,
                "non_root_enforced": True,
                "read_only_rootfs": True,
                "read_only_sample_mount": True,
                "host_execution_prevented": True,
            }
            if isinstance(telemetry_data.get("security_verifications"), dict):
                sec_verifs.update(telemetry_data["security_verifications"])

            exec_summary = str(
                telemetry_data.get("execution_summary")
                or f"Container execution completed with return code {res.returncode}."
            )

            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=status,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=[
                    "container_boundary_setup",
                    "sample_ro_mount",
                    "isolated_detonation",
                    "telemetry_collection",
                ],
                error_message=error_msg,
                process_tree=process_tree,
                network_beacons=network_beacons,
                runtime_events=runtime_events,
                security_verifications=sec_verifs,
                execution_summary=exec_summary,
            )
        except subprocess.TimeoutExpired:
            # Force kill the timed out container
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass
            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=SandboxStatus.TIMED_OUT,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=[
                    "container_boundary_setup",
                    "sample_ro_mount",
                    "isolated_detonation",
                ],
                error_message=f"Container execution exceeded safety timeout of {timeout_seconds} seconds.",
                process_tree=[],
                network_beacons=[],
                runtime_events=[],
                security_verifications={
                    "network_disabled": True,
                    "non_root_enforced": True,
                    "read_only_rootfs": True,
                    "read_only_sample_mount": True,
                    "host_execution_prevented": True,
                },
                execution_summary=f"Sandbox terminated after exceeding execution limit of {timeout_seconds}s.",
            )
        except Exception as exc:
            job = SandboxJobResponse(
                job_id=job_id,
                sample_id=sample_id,
                filename=filename,
                status=SandboxStatus.FAILED,
                created_at=created_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                operations_run=["container_boundary_setup"],
                error_message=f"Container invocation error: {str(exc)}",
                process_tree=[],
                network_beacons=[],
                runtime_events=[],
                security_verifications={
                    "network_disabled": True,
                    "non_root_enforced": True,
                    "read_only_rootfs": True,
                    "read_only_sample_mount": True,
                    "host_execution_prevented": True,
                },
                execution_summary=f"Container invocation failed: {str(exc)}",
            )
        finally:
            # Defensive container removal
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass

            try:
                temp_dir.cleanup()
            except Exception:
                pass

        with self._lock:
            self._jobs[job_id] = job
        self._persist_job(job, db=db)
        return job

    def get_job(self, job_id: str, db: Optional[Session] = None) -> Optional[SandboxJobResponse]:
        """Retrieve an existing sandbox job by UUID, checking memory then database."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                return job

        # Fallback to database
        try:
            if db is not None:
                job_db = SandboxJobRepository.get_by_id(db, job_id)
            else:
                session = SessionLocal()
                try:
                    job_db = SandboxJobRepository.get_by_id(session, job_id)
                finally:
                    session.close()

            if job_db is not None:
                with self._lock:
                    self._jobs[job_id] = job_db
                return job_db
        except Exception as exc:
            logger.error("Error retrieving sandbox job %s from database: %s", job_id, exc)

        return None

    def list_jobs(self, db: Optional[Session] = None) -> list[SandboxJobResponse]:
        """List all sandbox jobs ordered newest first, querying database with in-memory fallback."""
        try:
            if db is not None:
                db_jobs = SandboxJobRepository.get_all(db)
            else:
                session = SessionLocal()
                try:
                    db_jobs = SandboxJobRepository.get_all(session)
                finally:
                    session.close()

            if db_jobs:
                with self._lock:
                    for j in db_jobs:
                        if j.job_id not in self._jobs:
                            self._jobs[j.job_id] = j
                return db_jobs
        except Exception as exc:
            logger.error("Error listing sandbox jobs from database: %s", exc)

        with self._lock:
            return list(reversed(list(self._jobs.values())))


# Global singleton instance
sandbox_manager = SandboxManager()
