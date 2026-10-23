"""
CyberShield Sandbox Subsystem
==============================

Provides isolated, containerized dynamic malware analysis:
- Truthful Docker CLI and daemon availability detection
- Per-job isolated containers with disabled networking, non-root execution,
  read-only sample mounts, and strict resource caps
- Strict UNAVAILABLE state when container isolation is not present
- Strict prohibition against fallback to host execution
"""

from app.sandbox.detector import get_sandbox_status, is_docker_available
from app.sandbox.manager import sandbox_manager
from app.sandbox.router import router as sandbox_router

__all__ = [
    "get_sandbox_status",
    "is_docker_available",
    "sandbox_manager",
    "sandbox_router",
]
