# ==============================================================================
# CyberShield Defensive Malware Analysis Sandbox Container
#
# Minimal, hardened execution image for isolated sample inspection.
#
# Security Specifications:
# - Minimal base image (Alpine 3.20)
# - Unprivileged user: UID 1000, GID 1000 (no root runtime)
# - Compatible with:
#   * --network none (air-gapped)
#   * --read-only rootfs
#   * --tmpfs /tmp:rw,noexec,nosuid,size=64m
#   * --cap-drop ALL
#   * --security-opt no-new-privileges:true
#   * Resource limits (--cpus 1.0, --memory 512m, --pids-limit 64)
# ==============================================================================

FROM alpine:3.20

LABEL maintainer="CyberShield Security Team" \
      description="Isolated defensive container sandbox for sample inspection" \
      security.unprivileged="true" \
      security.network="none"

# Install minimal required runtime (Python 3 standard library only; no third-party packages)
RUN apk add --no-cache python3 && \
    rm -rf /var/cache/apk/*

# Create unprivileged user with explicit UID 1000 and GID 1000
RUN addgroup -g 1000 sandboxgroup && \
    adduser -u 1000 -G sandboxgroup -D -s /bin/sh sandboxuser

# Create workspace and output directory with non-root ownership
RUN mkdir -p /sandbox/output && \
    chown -R 1000:1000 /sandbox && \
    chmod 755 /sandbox && \
    chmod 777 /sandbox/output

WORKDIR /sandbox

# Copy the isolated entrypoint script
COPY entrypoint.py /sandbox/entrypoint.py
RUN chown 1000:1000 /sandbox/entrypoint.py && \
    chmod 555 /sandbox/entrypoint.py

# Switch permanently to unprivileged user
USER 1000:1000

# Strict entrypoint execution
ENTRYPOINT ["python3", "/sandbox/entrypoint.py"]
