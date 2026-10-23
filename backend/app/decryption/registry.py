"""
Decryptor adapter registry for the CyberShield Decryption & Recovery Engine.

The registry is a singleton that holds all registered DecryptorAdapter
instances.  It is the single source of truth for:
  - Which adapters exist.
  - Their current availability status.
  - Their supported families and variants.

Registry design
---------------
  - Adapters are registered at import time via _build_registry().
  - The registry never claims an adapter is AVAILABLE unless the adapter
    itself reports AVAILABLE status (the adapter checks its own prerequisites).
  - Adapters can be looked up by adapter_id.
  - No adapter is added to the registry without a documented source, real
    supported-family list, and accurate status.

Adding a new adapter
--------------------
1. Create a new file in adapters/ that subclasses DecryptorAdapter.
2. Add an instance to the _ADAPTERS list in _build_registry() below.
3. Restart the application — the registry is rebuilt on each import.
"""

import logging
from typing import Optional

from app.decryption.adapters.base import DecryptorAdapter, AdapterCapabilities
from app.decryption.adapters.nomoreransom_gandcrab import NoMoreRansomGandCrabAdapter
from app.decryption.adapters.emsisoft_stub import EmsioftGenericStubAdapter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Registry singleton
# ---------------------------------------------------------------------------


class _DecryptorRegistry:
    """
    Internal registry.  Access via the module-level functions below.
    """

    def __init__(self, adapters: list[DecryptorAdapter]) -> None:
        self._adapters: dict[str, DecryptorAdapter] = {
            a.adapter_id: a for a in adapters
        }
        logger.info(
            "Decryptor registry initialised with %d adapter(s): %s",
            len(self._adapters),
            list(self._adapters.keys()),
        )

    def get(self, adapter_id: str) -> Optional[DecryptorAdapter]:
        """Return the adapter with *adapter_id*, or None."""
        return self._adapters.get(adapter_id)

    def all_adapters(self) -> list[DecryptorAdapter]:
        """Return all registered adapters (insertion order)."""
        return list(self._adapters.values())

    def available_adapters(self) -> list[DecryptorAdapter]:
        """Return only adapters with status == 'AVAILABLE'."""
        return [a for a in self._adapters.values() if a.status == "AVAILABLE"]

    def capabilities_list(self) -> list[AdapterCapabilities]:
        """Return capabilities for all adapters (for the registry API endpoint)."""
        return [a.capabilities() for a in self._adapters.values()]


def _build_registry() -> _DecryptorRegistry:
    """
    Instantiate and register all adapters.

    Add new adapters here.  The order determines the display order in the
    registry API response.
    """
    adapters: list[DecryptorAdapter] = [
        NoMoreRansomGandCrabAdapter(),
        EmsioftGenericStubAdapter(),
    ]
    return _DecryptorRegistry(adapters)


# Module-level singleton — built once when this module is imported.
_registry: _DecryptorRegistry = _build_registry()


# ---------------------------------------------------------------------------
# Public interface (functions preferred over direct class access)
# ---------------------------------------------------------------------------


def list_adapters() -> list[AdapterCapabilities]:
    """Return capability summaries for all registered adapters."""
    return _registry.capabilities_list()


def get_adapter(adapter_id: str) -> Optional[DecryptorAdapter]:
    """Return the adapter with *adapter_id*, or None if not found."""
    return _registry.get(adapter_id)


def find_compatible_adapters(
    ransomware_family: str | None,
    variant: str | None = None,
    file_extension: str | None = None,
    extra_metadata: dict | None = None,
) -> list[tuple[DecryptorAdapter, str]]:
    """
    Return a list of (adapter, reason) tuples for adapters that report
    compatibility with the given sample characteristics.

    Only adapters where is_compatible() returns True are included.

    Parameters
    ----------
    ransomware_family : str | None
        Identified ransomware family string, or None if unknown.
    variant : str | None
        Specific variant, or None.
    file_extension : str | None
        File extension of the encrypted sample.
    extra_metadata : dict | None
        Additional analysis metadata.

    Returns
    -------
    list of (DecryptorAdapter, compatibility_reason_str)
        Empty list if no adapter is compatible.
    """
    results = []
    for adapter in _registry.all_adapters():
        compatible, reason = adapter.is_compatible(
            ransomware_family=ransomware_family,
            variant=variant,
            file_extension=file_extension,
            extra_metadata=extra_metadata,
        )
        if compatible:
            results.append((adapter, reason))
    return results


def available_count() -> int:
    """Return the number of currently AVAILABLE adapters."""
    return len(_registry.available_adapters())
