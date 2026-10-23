"""
Docker Environment Detector & Readiness Assessor.

Accurately interrogates the host operating environment for:
1. Docker CLI availability in system PATH.
2. Docker daemon responsiveness.
3. Sandbox analysis image availability.

Crucial security policy:
- If Docker is missing or unreachable, report UNAVAILABLE truthfully.
- Never claim dynamic container execution is ready when it is not.
- Never substitute an insecure host subprocess for container execution.
"""

import logging
import re
import shutil
import subprocess
from typing import Any

from app.sandbox.schemas import SandboxDetectorResponse

logger = logging.getLogger(__name__)

DEFAULT_SANDBOX_IMAGE = "cybershield/analysis-sandbox:latest"
IMAGE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-./:]{1,128}$")
DEFAULT_DOCKER_TIMEOUT = 10.0

SANDBOX_SECURITY_POLICIES = {
    "network_mode": "none (air-gapped)",
    "non_root_execution": True,
    "user": "1000:1000 (unprivileged)",
    "read_only_rootfs": True,
    "read_only_sample_mount": True,
    "isolated_output_dir": True,
    "security_opt": ["no-new-privileges:true"],
    "capabilities_dropped": ["ALL"],
    "host_socket_mounted": False,
    "privileged_mode": False,
    "resource_caps": {
        "cpus": "1.0",
        "memory": "512m",
        "pids_limit": 64,
        "max_execution_time_seconds": 120,
    },
}


def get_docker_executable() -> str:
    """Return the absolute path to the Docker executable, or 'docker' fallback."""
    return shutil.which("docker") or "docker"


def is_docker_cli_present() -> bool:
    """Return True if the 'docker' executable is found in system PATH."""
    return shutil.which("docker") is not None


def is_docker_daemon_reachable(timeout_seconds: float = DEFAULT_DOCKER_TIMEOUT) -> bool:
    """
    Return True if the Docker daemon responds successfully to a ping or version check.
    Returns False if CLI is missing, daemon is stopped, or query times out.
    """
    if not is_docker_cli_present():
        return False

    docker_bin = get_docker_executable()

    # Try fast 'docker version' first, with fallback to 'docker info'
    for cmd in (
        [docker_bin, "version", "--format", "{{.Server.Version}}"],
        [docker_bin, "info", "--format", "{{.ServerVersion}}"],
    ):
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return True
            if res.stderr:
                logger.debug(
                    "Docker daemon check %s failed (code %s): %s",
                    cmd,
                    res.returncode,
                    res.stderr.strip()[:200],
                )
        except subprocess.TimeoutExpired:
            logger.warning(
                "Docker daemon check %s timed out after %.1f seconds",
                cmd,
                timeout_seconds,
            )
        except OSError as exc:
            logger.warning("Docker daemon check %s failed with OS error: %s", cmd, exc)

    return False


def is_sandbox_image_available(
    image_name: str = DEFAULT_SANDBOX_IMAGE,
    timeout_seconds: float = DEFAULT_DOCKER_TIMEOUT,
    check_daemon: bool = True,
) -> bool:
    """
    Return True if the specified sandbox image is present locally in Docker.
    """
    if not image_name or not IMAGE_NAME_REGEX.match(image_name):
        return False

    if check_daemon and not is_docker_daemon_reachable(timeout_seconds=timeout_seconds):
        return False

    docker_bin = get_docker_executable()
    try:
        res = subprocess.run(
            [docker_bin, "image", "inspect", image_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return res.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning(
            "Docker image inspect for '%s' timed out after %.1f seconds",
            image_name,
            timeout_seconds,
        )
        return False
    except OSError as exc:
        logger.warning("Docker image inspect for '%s' failed: %s", image_name, exc)
        return False


def is_docker_available() -> bool:
    """Convenience check: True only if Docker CLI and daemon are operational."""
    return is_docker_daemon_reachable()


def get_sandbox_status(
    image_name: str = DEFAULT_SANDBOX_IMAGE,
    timeout_seconds: float = DEFAULT_DOCKER_TIMEOUT,
) -> SandboxDetectorResponse:
    """
    Produce a complete, truthful diagnostic assessment of the sandbox environment.
    """
    cli_ok = is_docker_cli_present()
    daemon_ok = is_docker_daemon_reachable(timeout_seconds=timeout_seconds) if cli_ok else False
    image_ok = (
        is_sandbox_image_available(image_name, timeout_seconds=timeout_seconds, check_daemon=False)
        if daemon_ok
        else False
    )

    is_ready = cli_ok and daemon_ok and image_ok

    diagnostics: list[str] = []
    prerequisites: list[str] = []

    if not cli_ok:
        diagnostics.append("Docker CLI ('docker') was not found in the system PATH.")
        prerequisites.append("Install Docker Desktop for Windows or Docker Engine.")
    elif not daemon_ok:
        diagnostics.append("Docker CLI is installed, but the Docker daemon/service is not reachable.")
        prerequisites.append("Ensure the Docker Desktop application or Docker service is started.")
    elif not image_ok:
        diagnostics.append(f"Docker is operational, but required image '{image_name}' is not present.")
        prerequisites.append(f"Build or pull the vetted sandbox image: 'docker pull {image_name}'.")

    if not is_ready:
        diagnostics.append(
            "Dynamic analysis is safely disabled. Un-isolated execution on the host machine is strictly prohibited."
        )

    return SandboxDetectorResponse(
        docker_cli_available=cli_ok,
        docker_daemon_reachable=daemon_ok,
        sandbox_image_available=image_ok,
        dynamic_analysis_ready=is_ready,
        sandbox_status="AVAILABLE" if is_ready else "UNAVAILABLE",
        sandbox_image=image_name,
        security_policies=SANDBOX_SECURITY_POLICIES,
        diagnostics=diagnostics,
        prerequisites=prerequisites,
    )
