"""
Pydantic schemas for the CyberShield Decryption & Recovery Engine API.

These models define the request and response contracts for the decryption
router (added in Stage C).  They are defined here — in the isolated module —
so that the business logic layer can reference them without importing from
the API layer.

Key-safety rule
---------------
Cryptographic key material must never appear in:
  - JobStatusResponse (job polling endpoint)
  - EligibilityResponse
  - RegistryResponse or DecryptorInfo

Keys appear ONLY in DemoEncryptResponse, and only for the single response
to the encrypt request.  They are not stored server-side after that point.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------
# Demo — encrypt
# ---------------------------------------------------------------


class DemoEncryptRequest(BaseModel):
    """Request body for encrypting a demo file."""

    demo_filename: str = Field(
        ...,
        description=(
            "Base filename of a plaintext demo file in the server-side "
            "demo_files/ directory. Must not contain path separators."
        ),
        examples=["quarterly_report_demo.txt"],
    )


class DemoEncryptResponse(BaseModel):
    """
    Response from the demo encrypt endpoint.

    The *key_b64* field is the ONLY time the key is transmitted.
    It is not stored on the server.  Losing the key means the
    encrypted demo file cannot be recovered.
    """

    encrypted_filename: str = Field(
        description="Filename of the encrypted blob stored in demo_files/encrypted/."
    )
    key_b64: str = Field(
        description=(
            "URL-safe base64-encoded 256-bit AES key. "
            "Store this securely — it is not retained by the server."
        )
    )
    plaintext_sha256: str = Field(
        description="Hex SHA-256 of the original plaintext, for reference."
    )
    original_filename: str = Field(
        description="The source demo file that was encrypted."
    )
    file_size_bytes: int = Field(
        description="Size of the original plaintext in bytes."
    )
    encrypted_at: str = Field(
        description="ISO-8601 UTC timestamp of when the encryption was performed."
    )
    warning: str = Field(
        default=(
            "This is a CONTROLLED DEMO only. "
            "The key above is not stored. Save it now if you want to demonstrate decryption."
        )
    )


# ---------------------------------------------------------------
# Demo — job creation
# ---------------------------------------------------------------


class DemoDecryptRequest(BaseModel):
    """Request body for starting a demo decryption job."""

    encrypted_filename: str = Field(
        ...,
        description=(
            "Filename of the encrypted blob in demo_files/encrypted/ "
            "(returned by the encrypt endpoint)."
        ),
    )
    key_b64: str = Field(
        ...,
        description="URL-safe base64-encoded 256-bit AES key.",
    )
    sample_id: Optional[str] = Field(
        default=None,
        description="Optional associated sample ID for linking in job history.",
    )


class UploadEncryptedResponse(BaseModel):
    """Response after uploading a pre-existing .csde encrypted file."""

    encrypted_filename: str = Field(
        description="Safe server basename assigned to the uploaded encrypted file."
    )
    original_filename: str = Field(
        description="Original name of the uploaded encrypted file."
    )
    file_size_bytes: int = Field(
        description="Size of the uploaded encrypted file in bytes."
    )
    message: str = Field(
        default="Encrypted file uploaded and verified as CyberShield Demo Encrypted format."
    )


class DemoDecryptResponse(BaseModel):
    """Immediate response when a demo decryption job is accepted."""

    job_id: str
    status: str
    message: str


# ---------------------------------------------------------------
# Job status
# ---------------------------------------------------------------


class JobStatusResponse(BaseModel):
    """
    Recovery job status.  Key material is never included here.
    """

    job_id: str
    job_type: str = Field(description="'DEMO' or 'REAL'")
    status: str = Field(
        description=(
            "One of: READY_FOR_RECOVERY, RECOVERY_IN_PROGRESS, "
            "RECOVERY_SUCCEEDED, RECOVERY_PARTIAL, RECOVERY_FAILED, "
            "OUTPUT_VERIFICATION_FAILED."
        )
    )
    input_file: Optional[str] = None
    output_path: Optional[str] = None
    plaintext_sha256: Optional[str] = Field(
        default=None,
        description="Expected SHA-256 (hex) of the recovered plaintext.",
    )
    output_sha256: Optional[str] = Field(
        default=None,
        description="Actual SHA-256 (hex) of the recovered output file.",
    )
    verified: bool = Field(
        description=(
            "True only when the output exists, its hash was calculated, "
            "and it matches the expected plaintext SHA-256."
        )
    )
    error_message: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None


# ---------------------------------------------------------------
# Eligibility check
# ---------------------------------------------------------------


class EligibilityResponse(BaseModel):
    """
    Result of checking whether a real ransomware sample is eligible
    for supported recovery.
    """

    sample_id: str
    filename: str
    recovery_status: str = Field(
        description=(
            "One of: ANALYSIS_REQUIRED, FAMILY_UNKNOWN, VARIANT_UNCONFIRMED, "
            "DECRYPTOR_UNAVAILABLE, UNSUPPORTED_VARIANT, KEY_REQUIRED, "
            "READY_FOR_RECOVERY."
        )
    )
    ransomware_family: Optional[str] = None
    identification_confidence: Optional[float] = None
    compatible_adapters: list[str] = Field(
        default_factory=list,
        description="IDs of adapters that may support this sample.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Analysis indicators that informed this result.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Reasons why recovery may not be possible.",
    )
    explanation: str = Field(
        description="Human-readable explanation of the eligibility result."
    )


# ---------------------------------------------------------------
# Decryptor registry
# ---------------------------------------------------------------


class DecryptorInfo(BaseModel):
    """Metadata about a registered decryptor adapter."""

    adapter_id: str
    display_name: str
    source: str = Field(description="e.g., 'No More Ransom', 'Emsisoft'")
    supported_families: list[str]
    supported_variants: list[str]
    status: str = Field(
        description="'AVAILABLE', 'UNAVAILABLE', or 'REQUIRES_PREREQUISITES'"
    )
    prerequisites: list[str] = Field(
        description="What must be in place before this adapter can run."
    )
    limitations: list[str]
    can_run_automatically: bool = Field(
        description=(
            "False for adapters that require a manually downloaded external tool "
            "or separate key material that CyberShield cannot obtain automatically."
        )
    )
    requires_explicit_approval: bool


class RegistryResponse(BaseModel):
    """Full list of registered decryptors."""

    adapters: list[DecryptorInfo]
    total: int
    available_count: int
    note: str = Field(
        default=(
            "Adapter availability reflects the current server environment. "
            "Some adapters require external tools or key material that must "
            "be provided separately and approved before use."
        )
    )


# ---------------------------------------------------------------
# Demo file listing
# ---------------------------------------------------------------


class DemoFileInfo(BaseModel):
    filename: str
    size_bytes: int
    description: str


class DemoFilesResponse(BaseModel):
    files: list[DemoFileInfo]
    demo_directory_note: str = Field(
        default=(
            "These are controlled demonstration files. "
            "They do not contain real sensitive data. "
            "Encrypting them with the demo endpoint produces CyberShield Demo Encrypted "
            "(.csde) blobs that can be decrypted with the provided key."
        )
    )
