"""
Targeted tests for Stage 3: Real Docker Sandbox Foundation.

Covers:
  - Truthful Docker CLI & daemon readiness reporting (GET /api/v1/sandbox/status)
  - Security policies and diagnostic messaging
  - Rejection of dynamic analysis when confirm_dynamic_execution is False (HTTP 400)
  - Validation of sample_id format and path traversal rejection (HTTP 400)
  - Handling of non-existent sample_id (HTTP 404)
  - Job creation on host without Docker: status UNAVAILABLE, no host execution
  - Job retrieval (GET /api/v1/sandbox/jobs/{job_id}) and listing (GET /api/v1/sandbox/jobs)
  - Mocked container execution: validates exact defensive CLI flags
  - Timeout handling: validates TIMED_OUT status and cleanup
"""

from datetime import datetime, timezone
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database.database import Base, get_db
from app.main import app
from app.models.sample import Sample
from app.repositories.sample_repository import SampleRepository
from app.sandbox.detector import (
    get_sandbox_status,
    is_docker_cli_present,
    is_docker_daemon_reachable,
    is_sandbox_image_available,
)
from app.sandbox.manager import SandboxManager, sandbox_manager
from app.sandbox.schemas import SandboxStatus


@pytest.fixture(scope="function")
def test_db_session():
    """Create an isolated in-memory SQLite database for sandbox tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db_session, tmp_path):
    """Provide a TestClient with temporary upload directory and isolated DB."""
    test_upload_dir = tmp_path / "test_uploads"
    test_upload_dir.mkdir(parents=True, exist_ok=True)

    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    original_upload_dir = settings.UPLOAD_DIR
    settings.UPLOAD_DIR = str(test_upload_dir)

    with TestClient(app) as test_client:
        yield test_client

    settings.UPLOAD_DIR = original_upload_dir
    app.dependency_overrides.clear()


@pytest.fixture
def sample_record(test_db_session, tmp_path):
    """Create a legitimate sample record and file for testing."""
    upload_dir = Path(settings.UPLOAD_DIR)
    stored_name = "test_sample_uuid_123.bin"
    file_path = upload_dir / stored_name
    file_path.write_bytes(b"TEST_MALWARE_PAYLOAD_CONTENT_FOR_SANDBOX")

    sample = Sample(
        id="SMP-TEST-001",
        original_filename="sample_target.bin",
        stored_filename=stored_name,
        file_extension=".bin",
        file_size=len(b"TEST_MALWARE_PAYLOAD_CONTENT_FOR_SANDBOX"),
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        status="ANALYZED",
        uploaded_at=datetime.now(timezone.utc),
    )
    test_db_session.add(sample)
    test_db_session.commit()
    test_db_session.refresh(sample)
    return sample


# ---------------------------------------------------------------------------
# Detector Unit Tests
# ---------------------------------------------------------------------------

def test_detector_reports_unavailable_on_host_without_docker():
    """Verify detector reports truthful UNAVAILABLE when Docker CLI is absent."""
    with patch("app.sandbox.detector.is_docker_cli_present", return_value=False):
        status = get_sandbox_status()
        assert status.docker_cli_available is False
        assert status.dynamic_analysis_ready is False
        assert status.sandbox_status == "UNAVAILABLE"
        assert any("Docker CLI" in d for d in status.diagnostics)


def test_detector_security_policies():
    """Verify security policies dictionary lists air-gapping and unprivileged flags."""
    status = get_sandbox_status()
    policies = status.security_policies
    assert "none" in policies["network_mode"]
    assert policies["non_root_execution"] is True
    assert policies["read_only_rootfs"] is True
    assert policies["read_only_sample_mount"] is True
    assert policies["privileged_mode"] is False


def test_detector_mocked_states():
    """Test detector logic under simulated CLI and daemon availability."""
    # When CLI is missing
    with patch("shutil.which", return_value=None):
        assert is_docker_cli_present() is False
        assert is_docker_daemon_reachable() is False
        res = get_sandbox_status()
        assert res.docker_cli_available is False
        assert res.sandbox_status == "UNAVAILABLE"

    # When CLI is present but daemon fails
    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run", return_value=MagicMock(returncode=1)):
        assert is_docker_cli_present() is True
        assert is_docker_daemon_reachable() is False
        res = get_sandbox_status()
        assert res.docker_cli_available is True
        assert res.docker_daemon_reachable is False
        assert res.sandbox_status == "UNAVAILABLE"


# ---------------------------------------------------------------------------
# API Endpoint Tests
# ---------------------------------------------------------------------------

def test_api_sandbox_status(client):
    """GET /api/v1/sandbox/status returns accurate diagnostic response."""
    response = client.get("/api/v1/sandbox/status")
    assert response.status_code == 200
    data = response.json()
    assert "sandbox_status" in data
    assert "dynamic_analysis_ready" in data
    assert "security_policies" in data
    assert "diagnostics" in data
    assert "prerequisites" in data


def test_api_submit_missing_sample_404(client):
    """POST /api/v1/sandbox/jobs returns 404 for unknown sample."""
    response = client.post(
        "/api/v1/sandbox/jobs",
        json={"sample_id": "non-existent-id", "confirm_dynamic_execution": True},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_submit_invalid_sample_id_400(client):
    """POST /api/v1/sandbox/jobs returns 400 for path traversal sample ID."""
    response = client.post(
        "/api/v1/sandbox/jobs",
        json={"sample_id": "../../etc/shadow", "confirm_dynamic_execution": True},
    )
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


def test_api_submit_without_opt_in_400(client, sample_record):
    """POST /api/v1/sandbox/jobs returns 400 when confirm_dynamic_execution is false."""
    response = client.post(
        "/api/v1/sandbox/jobs",
        json={"sample_id": sample_record.id, "confirm_dynamic_execution": False},
    )
    assert response.status_code == 400
    assert "confirmation" in response.json()["detail"].lower()


def test_api_submit_job_without_docker_creates_unavailable_job(client, sample_record):
    """
    POST /api/v1/sandbox/jobs on host without Docker creates an UNAVAILABLE job.
    Never executes the sample on the host.
    """
    mock_unavailable = MagicMock(
        dynamic_analysis_ready=False,
        diagnostics=["Docker container runtime is not available on this host."],
        security_policies={},
    )
    with patch("app.sandbox.manager.get_sandbox_status", return_value=mock_unavailable):
        response = client.post(
            "/api/v1/sandbox/jobs",
            json={
                "sample_id": sample_record.id,
                "confirm_dynamic_execution": True,
                "timeout_seconds": 60,
            },
        )
        assert response.status_code == 201
        job_data = response.json()
        assert job_data["sample_id"] == sample_record.id
        assert job_data["filename"] == sample_record.original_filename
        assert job_data["status"] == "UNAVAILABLE"
        assert "host execution is strictly prohibited" in job_data["error_message"].lower()
        assert job_data["security_verifications"]["host_execution_prevented"] is True

        # Retrieve job by ID
        job_id = job_data["job_id"]
        get_res = client.get(f"/api/v1/sandbox/jobs/{job_id}")
        assert get_res.status_code == 200
        assert get_res.json()["job_id"] == job_id
        assert get_res.json()["status"] == "UNAVAILABLE"


@pytest.mark.skipif(
    not is_docker_daemon_reachable() or not is_sandbox_image_available(),
    reason="Requires live Docker daemon and sandbox image",
)
def test_api_submit_job_with_real_docker_container(client, sample_record):
    """
    POST /api/v1/sandbox/jobs with real Docker executes sample inside container
    and produces verified COMPLETED telemetry.
    """
    response = client.post(
        "/api/v1/sandbox/jobs",
        json={
            "sample_id": sample_record.id,
            "confirm_dynamic_execution": True,
            "timeout_seconds": 60,
        },
    )
    assert response.status_code == 201
    job_data = response.json()
    assert job_data["sample_id"] == sample_record.id
    assert job_data["status"] == "COMPLETED"
    assert job_data["error_message"] is None
    assert job_data["security_verifications"]["network_disabled"] is True
    assert job_data["security_verifications"]["non_root_enforced"] is True
    assert job_data["security_verifications"]["read_only_rootfs"] is True
    assert job_data["network_beacons"] == []
    assert len(job_data["process_tree"]) >= 1
    assert job_data["process_tree"][0]["status"] == "ANALYZED"


def test_api_get_nonexistent_job_404(client):
    """GET /api/v1/sandbox/jobs/{job_id} returns 404 for unknown job ID."""
    response = client.get("/api/v1/sandbox/jobs/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_list_jobs(client, sample_record):
    """GET /api/v1/sandbox/jobs returns list containing submitted jobs."""
    # Submit a job
    submit_res = client.post(
        "/api/v1/sandbox/jobs",
        json={"sample_id": sample_record.id, "confirm_dynamic_execution": True},
    )
    assert submit_res.status_code == 201

    list_res = client.get("/api/v1/sandbox/jobs")
    assert list_res.status_code == 200
    jobs = list_res.json()
    assert isinstance(jobs, list)
    assert len(jobs) >= 1
    assert any(j["sample_id"] == sample_record.id for j in jobs)


# ---------------------------------------------------------------------------
# Manager Defensive Execution & Mock Tests
# ---------------------------------------------------------------------------

def test_manager_container_command_arguments(tmp_path):
    """
    Verify SandboxManager invokes docker run with mandatory security arguments:
    --network none, --user 1000:1000, --read-only, --cap-drop ALL, sample:ro mount.
    """
    manager = SandboxManager()
    upload_dir = Path(settings.UPLOAD_DIR).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    dummy_sample = upload_dir / "sample.bin"
    dummy_sample.write_bytes(b"SAFE_FIXTURE_BYTES")

    mock_detector_response = MagicMock(
        dynamic_analysis_ready=True,
        sandbox_image="cybershield/analysis-sandbox:latest",
    )

    with patch("app.sandbox.manager.get_sandbox_status", return_value=mock_detector_response), \
         patch("subprocess.run") as mock_subproc:

        mock_subproc.return_value = MagicMock(returncode=0, stdout="OK", stderr="")

        job = manager.create_job(
            sample_id="SMP-MOCK-1",
            filename="sample.bin",
            sample_path=dummy_sample,
            confirm_dynamic_execution=True,
            timeout_seconds=45,
        )

        assert job.status == SandboxStatus.COMPLETED
        assert mock_subproc.called

        # Inspect the command arguments passed to docker run (first call)
        docker_cmd = mock_subproc.call_args_list[0][0][0]
        assert docker_cmd[0] == "docker"
        assert docker_cmd[1] == "run"
        assert "--network" in docker_cmd
        assert "none" in docker_cmd
        assert "--user" in docker_cmd
        assert "1000:1000" in docker_cmd
        assert "--read-only" in docker_cmd
        assert "--cap-drop" in docker_cmd
        assert "ALL" in docker_cmd
        assert "--security-opt" in docker_cmd
        assert "no-new-privileges:true" in docker_cmd
        assert "--cpus" in docker_cmd
        assert "--memory" in docker_cmd
        assert any(":ro" in arg for arg in docker_cmd)

        # Verify defensive cleanup was also called (second call)
        assert len(mock_subproc.call_args_list) >= 2
        cleanup_cmd = mock_subproc.call_args_list[1][0][0]
        assert cleanup_cmd[:3] == ["docker", "rm", "-f"]


def test_manager_timeout_handling(tmp_path):
    """
    Verify SandboxManager terminates the container and sets TIMED_OUT status
    when container exceeds execution time.
    """
    manager = SandboxManager()
    upload_dir = Path(settings.UPLOAD_DIR).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    dummy_sample = upload_dir / "sample_timeout.bin"
    dummy_sample.write_bytes(b"SAFE_FIXTURE_BYTES")

    mock_detector_response = MagicMock(
        dynamic_analysis_ready=True,
        sandbox_image="cybershield/analysis-sandbox:latest",
    )

    with patch("app.sandbox.manager.get_sandbox_status", return_value=mock_detector_response), \
         patch("subprocess.run", side_effect=[subprocess.TimeoutExpired(cmd="docker run", timeout=10), MagicMock(returncode=0)]):

        job = manager.create_job(
            sample_id="SMP-TIMEOUT-1",
            filename="sample_timeout.bin",
            sample_path=dummy_sample,
            confirm_dynamic_execution=True,
            timeout_seconds=10,
        )

        assert job.status == SandboxStatus.TIMED_OUT
        assert job.error_message is not None
        assert "exceeded safety timeout" in job.error_message.lower()
        assert job.security_verifications["host_execution_prevented"] is True


def test_manager_rejects_sample_outside_upload_dir(tmp_path):
    """
    Verify SandboxManager rejects sample_path located outside settings.UPLOAD_DIR.
    """
    manager = SandboxManager()
    outside_sample = tmp_path / "outside_sample.bin"
    outside_sample.write_bytes(b"OUTSIDE_BYTES")

    mock_detector_response = MagicMock(
        dynamic_analysis_ready=True,
        sandbox_image="cybershield/analysis-sandbox:latest",
    )

    with patch("app.sandbox.manager.get_sandbox_status", return_value=mock_detector_response):
        job = manager.create_job(
            sample_id="SMP-CONTAINMENT-1",
            filename="outside.bin",
            sample_path=outside_sample,
            confirm_dynamic_execution=True,
        )

        assert job.status == SandboxStatus.FAILED
        assert "containment" in job.execution_summary.lower()
        assert job.security_verifications["host_execution_prevented"] is True
