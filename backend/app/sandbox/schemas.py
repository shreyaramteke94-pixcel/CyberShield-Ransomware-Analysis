"""
Pydantic schemas for the CyberShield Sandbox Subsystem.

These models define requests, responses, and state machines for dynamic
sandbox analysis jobs.
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class SandboxStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    UNAVAILABLE = "UNAVAILABLE"


class SandboxDetectorResponse(BaseModel):
    """
    Diagnostic status of the sandbox execution environment.
    """
    docker_cli_available: bool = Field(
        description="True if the 'docker' executable is found in system PATH."
    )
    docker_daemon_reachable: bool = Field(
        description="True if the Docker daemon responds to health/info queries."
    )
    sandbox_image_available: bool = Field(
        description="True if the verified sandbox image exists in local container cache."
    )
    dynamic_analysis_ready: bool = Field(
        description="True only when CLI, daemon, and verified image are ready."
    )
    sandbox_status: str = Field(
        description="'AVAILABLE' if ready to execute isolated jobs; otherwise 'UNAVAILABLE'."
    )
    sandbox_image: str = Field(
        default="cybershield/analysis-sandbox:latest",
        description="Designated container image for analysis."
    )
    security_policies: dict[str, Any] = Field(
        description="Active sandbox security restrictions (network, caps, limits)."
    )
    diagnostics: list[str] = Field(
        default_factory=list,
        description="Diagnostic explanations if any component is missing or disabled."
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Prerequisites required to enable container dynamic analysis."
    )
    disclaimer: str = Field(
        default=(
            "Containers significantly isolate processes but do not guarantee complete protection "
            "against all hypervisor/kernel escapes. Host execution is strictly prohibited when "
            "container runtime is absent."
        )
    )


class SandboxJobRequest(BaseModel):
    """
    Request body for submitting a sample to dynamic sandbox analysis.
    """
    sample_id: str = Field(
        ...,
        description="UUID of an existing uploaded and statically analyzed sample.",
    )
    confirm_dynamic_execution: bool = Field(
        ...,
        description=(
            "Explicit confirmation and consent to detonate sample within the isolated sandbox. "
            "Dynamic analysis will not execute without this explicit opt-in flag."
        ),
    )
    timeout_seconds: Optional[int] = Field(
        default=60,
        ge=10,
        le=180,
        description="Execution timeout in seconds (10s to 180s, default 60s).",
    )


class SandboxJobResponse(BaseModel):
    """
    State, configuration, and observed runtime telemetry for a sandbox job.
    """
    job_id: str = Field(description="Unique UUID for this sandbox execution job.")
    sample_id: str = Field(description="Reference to the analyzed sample.")
    filename: str = Field(description="Original filename of the target sample.")
    status: SandboxStatus = Field(
        description="Job state: QUEUED, RUNNING, COMPLETED, FAILED, TIMED_OUT, UNAVAILABLE."
    )
    created_at: str = Field(description="ISO-8601 UTC timestamp of submission.")
    completed_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 UTC timestamp of job completion or termination.",
    )
    operations_run: list[str] = Field(
        default_factory=list,
        description="List of analysis operations that actually ran during this job.",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Diagnostic error message if status is FAILED, TIMED_OUT, or UNAVAILABLE.",
    )
    process_tree: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Observed process hierarchy from dynamic execution (empty if unexecuted).",
    )
    network_beacons: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Captured outbound attempts blocked by air-gap (empty if unexecuted).",
    )
    runtime_events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Filesystem and registry activity observed during runtime.",
    )
    security_verifications: dict[str, bool] = Field(
        default_factory=dict,
        description="Verification flags for enforced security boundaries.",
    )
    execution_summary: str = Field(
        description="Human-readable summary of the sandbox execution outcome."
    )
