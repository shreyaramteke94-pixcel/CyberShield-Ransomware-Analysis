"""
No More Ransom — GandCrab Decryptor Adapter (Documented Stub)

Source
------
No More Ransom Project
https://www.nomoreransom.org/en/decryption-tools.html

Official tool page
------------------
"GandCrab" decryptor by Bitdefender / No More Ransom
https://www.nomoreransom.org/en/decryption-tools.html#gandcrab

Verified facts about this decryptor
------------------------------------
- Supports GandCrab v1, v4, and v5 up to v5.2.
- Released after law enforcement seized GandCrab C2 infrastructure in 2019.
- Distributed as a standalone Windows executable (GandCrabDecryptor.exe).
- Requires the victim's decryption key (obtained from seized C2 data via
  the tool's built-in key lookup or a manually supplied key file).
- Does NOT support GandCrab v2, v3, or any post-v5.2 variant.
- Not an open-source library; cannot be used as a Python import.
- Official download must be verified by SHA-256 before execution.

Why this adapter is UNAVAILABLE by default
------------------------------------------
1. The external GandCrabDecryptor.exe is not bundled with CyberShield.
   Automatic download from an arbitrary URL would violate the requirement
   to never automatically download or execute unknown binaries.
2. The decryptor requires victim-specific key material (resolved from the
   C2 database seized in 2019).  CyberShield cannot obtain this automatically.
3. The current CyberShield identification service does not confirm GandCrab
   family identification with sufficient certainty; it returns "Unknown" for
   most samples.  This adapter will not engage without a confirmed family match.

How to enable this adapter (manual operator steps)
---------------------------------------------------
1. Download GandCrabDecryptor.exe from the official No More Ransom site.
2. Verify its SHA-256 against the value published on the official page.
3. Place the verified executable in a path configured via
   GANDCRAB_DECRYPTOR_PATH environment variable.
4. Obtain victim-specific key material if available.
5. Restart the CyberShield backend; the adapter will detect the binary
   and transition to REQUIRES_PREREQUISITES status.
6. An operator with admin privilege must provide explicit approval before
   this adapter executes any file.

This adapter NEVER executes automatically.
"""

import logging
import os
from pathlib import Path

from app.decryption.adapters.base import DecryptorAdapter, AdapterCapabilities

logger = logging.getLogger(__name__)

# Environment variable that would point to the verified GandCrab executable.
_ENV_DECRYPTOR_PATH = "GANDCRAB_DECRYPTOR_PATH"


class NoMoreRansomGandCrabAdapter(DecryptorAdapter):
    """
    Adapter stub for the No More Ransom GandCrab decryptor.

    Status is always UNAVAILABLE unless the operator has manually installed
    the verified executable and configured its path via environment variable.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def adapter_id(self) -> str:
        return "nmr_gandcrab"

    @property
    def display_name(self) -> str:
        return "No More Ransom — GandCrab Decryptor (Bitdefender)"

    @property
    def source(self) -> str:
        return "No More Ransom"

    @property
    def source_url(self) -> str:
        return "https://www.nomoreransom.org/en/decryption-tools.html#gandcrab"

    @property
    def supported_families(self) -> list[str]:
        return ["GandCrab"]

    @property
    def supported_variants(self) -> list[str]:
        return ["v1", "v4", "v5", "v5.1", "v5.2"]

    @property
    def status(self) -> str:
        """
        UNAVAILABLE unless the operator has configured the decryptor path
        AND a verified binary exists at that path.
        """
        decryptor_path = os.environ.get(_ENV_DECRYPTOR_PATH)
        if decryptor_path and Path(decryptor_path).is_file():
            return "REQUIRES_PREREQUISITES"
        return "UNAVAILABLE"

    @property
    def prerequisites(self) -> list[str]:
        return [
            (
                "GandCrabDecryptor.exe must be downloaded from the official "
                "No More Ransom website, its SHA-256 verified against the "
                "published value, and its path set via the "
                f"{_ENV_DECRYPTOR_PATH} environment variable."
            ),
            (
                "Victim-specific decryption key material (from seized C2 "
                "infrastructure or the built-in key lookup) must be available."
            ),
            "Explicit operator approval is required before execution.",
            "The target sample must be confirmed GandCrab v1, v4, or v5–v5.2.",
        ]

    @property
    def limitations(self) -> list[str]:
        return [
            "Does NOT support GandCrab v2 or v3.",
            "Does NOT support any GandCrab variant released after v5.2.",
            (
                "Recovery is possible only for victims whose decryption keys "
                "were included in the 2019 C2 data seizure.  Keys for all "
                "infections may not be available."
            ),
            "Requires a Windows execution environment.",
            (
                "The CyberShield identification service currently returns "
                "'Unknown' for most samples.  This adapter will not engage "
                "without a confirmed GandCrab family identification."
            ),
        ]

    @property
    def can_run_automatically(self) -> bool:
        return False

    @property
    def requires_explicit_approval(self) -> bool:
        return True

    # ------------------------------------------------------------------
    # Compatibility
    # ------------------------------------------------------------------

    def is_compatible(
        self,
        ransomware_family: str | None,
        variant: str | None = None,
        file_extension: str | None = None,
        extra_metadata: dict | None = None,
    ) -> tuple[bool, str]:
        """
        Only compatible when the family is positively identified as GandCrab
        and the variant is one of the supported versions.
        """
        if not ransomware_family:
            return (
                False,
                "Ransomware family is unknown. "
                "GandCrab identification is required before this adapter can engage.",
            )

        if "gandcrab" not in ransomware_family.lower():
            return (
                False,
                f"Family '{ransomware_family}' is not GandCrab. "
                "This adapter supports GandCrab only.",
            )

        if variant and variant.lower() in {"v2", "v3"}:
            return (
                False,
                f"GandCrab {variant} is not supported by this decryptor. "
                "Only v1, v4, and v5–v5.2 are covered.",
            )

        if self.status == "UNAVAILABLE":
            return (
                False,
                "GandCrab family identified, but the decryptor executable "
                "is not installed. See prerequisites for setup instructions.",
            )

        return (
            True,
            "GandCrab family identified and adapter prerequisites are met. "
            "Explicit operator approval is required before execution.",
        )

    # ------------------------------------------------------------------
    # Execution — not implemented; approval gate enforced by base class
    # ------------------------------------------------------------------

    def decrypt(self, sample_path: Path, output_dir: Path, extra_params: dict | None = None) -> dict:
        """
        Execute the GandCrab decryptor against *sample_path*.

        This method will raise NotImplementedError until the operator has:
          1. Installed the verified GandCrabDecryptor.exe.
          2. Configured GANDCRAB_DECRYPTOR_PATH.
          3. Provided explicit approval (enforced by the orchestrator layer).

        When implemented, this must:
          - Validate the executable's SHA-256 before running.
          - Run with a timeout (e.g., 120 seconds).
          - Capture stdout/stderr without executing any uploaded samples.
          - Write recovered files only to *output_dir*.
          - Verify output integrity before reporting success.
        """
        if self.status == "UNAVAILABLE":
            raise NotImplementedError(
                "GandCrabDecryptor.exe is not installed. "
                "Follow the prerequisites to enable this adapter."
            )
        raise NotImplementedError(
            "GandCrab decryptor execution is not yet implemented. "
            "Operator approval and subprocess sandboxing must be "
            "configured before this method can run."
        )
