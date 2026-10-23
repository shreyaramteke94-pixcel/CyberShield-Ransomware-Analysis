"""
Abstract base class for CyberShield decryptor adapters.

Every concrete adapter must implement this interface.  The registry
discovers adapters by instantiating each class and calling its
public properties.

Adapter status values
---------------------
  AVAILABLE               – All prerequisites are met; adapter can run.
  UNAVAILABLE             – Prerequisites not satisfied in this environment.
  REQUIRES_PREREQUISITES  – Adapter is registered and documented, but needs
                            manual setup (external tool download, key material)
                            before it can execute.

IMPORTANT RULE
--------------
An adapter MUST NOT claim status=AVAILABLE unless it has verified that:
  - Any required external executable is present and its hash has been validated.
  - Any required key material or configuration is available.
  - The execution environment meets the documented prerequisites.

Do not invent APIs, keys, compatibility claims, or successful recovery results.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AdapterCapabilities:
    """
    Static capabilities and requirements of a decryptor adapter.
    Returned by the registry to the UI layer.
    """

    adapter_id: str
    display_name: str
    source: str
    source_url: str
    supported_families: list[str] = field(default_factory=list)
    supported_variants: list[str] = field(default_factory=list)
    status: str = "UNAVAILABLE"          # AVAILABLE | UNAVAILABLE | REQUIRES_PREREQUISITES
    prerequisites: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    can_run_automatically: bool = False
    requires_explicit_approval: bool = True


class DecryptorAdapter(ABC):
    """
    Abstract base class for a decryptor adapter.

    Subclasses represent a specific external decryptor tool or service.
    They are responsible for:
      1. Documenting supported families, variants, and prerequisites accurately.
      2. Checking compatibility with a specific sample.
      3. Executing the decryptor (only when all prerequisites are met and
         explicit user approval has been recorded).
    """

    # ------------------------------------------------------------------
    # Identity — override in subclasses
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def adapter_id(self) -> str:
        """Stable machine-readable identifier, e.g. 'nmr_gandcrab'."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name, e.g. 'No More Ransom — GandCrab Decryptor'."""

    @property
    @abstractmethod
    def source(self) -> str:
        """Source organisation, e.g. 'No More Ransom'."""

    @property
    @abstractmethod
    def source_url(self) -> str:
        """Official URL for the tool or documentation."""

    @property
    @abstractmethod
    def supported_families(self) -> list[str]:
        """Ransomware family names this adapter may support."""

    @property
    @abstractmethod
    def supported_variants(self) -> list[str]:
        """
        Specific variant strings this adapter was verified to handle.
        An empty list means all variants of the listed families
        (only use this when the tool's documentation confirms broad support).
        """

    @property
    @abstractmethod
    def status(self) -> str:
        """
        Current availability in this environment.
        One of: AVAILABLE | UNAVAILABLE | REQUIRES_PREREQUISITES
        """

    @property
    @abstractmethod
    def prerequisites(self) -> list[str]:
        """Human-readable list of things that must be in place before this adapter can run."""

    @property
    @abstractmethod
    def limitations(self) -> list[str]:
        """Known limitations — families, versions, or conditions it cannot handle."""

    @property
    def can_run_automatically(self) -> bool:
        """
        False for adapters that require a manually downloaded external tool
        or separate key material that CyberShield cannot obtain automatically.
        Override to True only if the adapter is a pure-Python implementation
        with all key material resolvable programmatically.
        """
        return False

    @property
    def requires_explicit_approval(self) -> bool:
        """
        True if executing this adapter requires explicit user confirmation
        before any external process is launched.
        """
        return True

    # ------------------------------------------------------------------
    # Compatibility check
    # ------------------------------------------------------------------

    @abstractmethod
    def is_compatible(
        self,
        ransomware_family: str | None,
        variant: str | None = None,
        file_extension: str | None = None,
        extra_metadata: dict | None = None,
    ) -> tuple[bool, str]:
        """
        Check whether this adapter is compatible with the described sample.

        Returns
        -------
        (bool, str)
            (True, reason)   – compatible
            (False, reason)  – not compatible, with explanation

        This check must be conservative.  If there is insufficient information
        to confirm compatibility, return (False, ...).  Never return True
        based only on a family name match without verifying variant/prerequisites.
        """

    # ------------------------------------------------------------------
    # Capabilities summary
    # ------------------------------------------------------------------

    def capabilities(self) -> AdapterCapabilities:
        """Return a capabilities summary for the registry."""
        return AdapterCapabilities(
            adapter_id=self.adapter_id,
            display_name=self.display_name,
            source=self.source,
            source_url=self.source_url,
            supported_families=self.supported_families,
            supported_variants=self.supported_variants,
            status=self.status,
            prerequisites=self.prerequisites,
            limitations=self.limitations,
            can_run_automatically=self.can_run_automatically,
            requires_explicit_approval=self.requires_explicit_approval,
        )

    # ------------------------------------------------------------------
    # Execution — intentionally raises by default
    # ------------------------------------------------------------------

    def decrypt(
        self,
        sample_path: "Path",  # noqa: F821  (type hint only)
        output_dir: "Path",   # noqa: F821
        extra_params: dict | None = None,
    ) -> dict:
        """
        Execute the decryptor against *sample_path* and write recovered
        files to *output_dir*.

        Default implementation raises NotImplementedError.  Subclasses
        that have AVAILABLE status must override this method.

        IMPORTANT: This method MUST NOT be called unless:
          1. is_compatible() returned True.
          2. status == 'AVAILABLE'.
          3. Explicit user approval has been recorded.
          4. The execution is sandboxed with a timeout.

        Returns
        -------
        dict with keys: status, output_files, message, verified
        """
        raise NotImplementedError(
            f"Adapter '{self.adapter_id}' has not implemented decrypt(). "
            f"Status: {self.status}. "
            "Only AVAILABLE adapters with explicit user approval may be executed."
        )
