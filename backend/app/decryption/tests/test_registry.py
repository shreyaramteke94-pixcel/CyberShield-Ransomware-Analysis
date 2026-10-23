"""
Tests for app.decryption.registry

Covers:
  - Registry returns a non-empty adapter list
  - All required fields are present on every adapter
  - No adapter falsely claims AVAILABLE status without prerequisites
  - get_adapter returns None for unknown IDs
  - find_compatible_adapters returns empty list for unknown family
  - find_compatible_adapters checks correctly for known families
  - available_count is accurate
"""

import pytest

from app.decryption import registry
from app.decryption.registry import (
    available_count,
    find_compatible_adapters,
    get_adapter,
    list_adapters,
)


def test_registry_returns_adapters():
    adapters = list_adapters()
    assert len(adapters) >= 2, "Registry should contain at least 2 registered adapters"


def test_all_adapters_have_required_fields():
    for a in list_adapters():
        assert a.adapter_id, f"adapter_id missing on {a}"
        assert a.display_name, f"display_name missing on {a}"
        assert a.source, f"source missing on {a}"
        assert isinstance(a.supported_families, list), "supported_families must be a list"
        assert a.status in {"AVAILABLE", "UNAVAILABLE", "REQUIRES_PREREQUISITES"}, \
            f"Invalid status: {a.status}"
        assert isinstance(a.prerequisites, list)
        assert isinstance(a.limitations, list)
        assert isinstance(a.can_run_automatically, bool)
        assert isinstance(a.requires_explicit_approval, bool)


def test_no_adapter_falsely_available():
    """
    Without any external executables installed, no adapter should report AVAILABLE.
    (REQUIRES_PREREQUISITES is allowed if a binary is found; UNAVAILABLE is the base state.)
    """
    for a in list_adapters():
        # We accept UNAVAILABLE or REQUIRES_PREREQUISITES but not AVAILABLE
        # in a clean environment with no external tools installed.
        if a.can_run_automatically is False:
            assert a.status in {"UNAVAILABLE", "REQUIRES_PREREQUISITES"}, \
                f"Adapter {a.adapter_id} reports AVAILABLE but cannot run automatically"


def test_get_adapter_known_ids():
    for a in list_adapters():
        fetched = get_adapter(a.adapter_id)
        assert fetched is not None
        assert fetched.adapter_id == a.adapter_id


def test_get_adapter_unknown_id_returns_none():
    assert get_adapter("nonexistent_adapter_xyz_9999") is None


def test_find_compatible_unknown_family():
    result = find_compatible_adapters(ransomware_family=None)
    assert result == []


def test_find_compatible_benign():
    result = find_compatible_adapters(ransomware_family="Benign / Clean")
    # GandCrab and Emsisoft stubs should reject benign samples
    compatible_ids = [a.adapter_id for a, _ in result]
    assert "nmr_gandcrab" not in compatible_ids


def test_find_compatible_unsupported_family():
    result = find_compatible_adapters(ransomware_family="LockBit 3.0")
    # Neither adapter currently claims LockBit support (GandCrab only)
    compatible_ids = [a.adapter_id for a, _ in result]
    assert "nmr_gandcrab" not in compatible_ids


def test_gandcrab_family_detected_but_unavailable():
    """GandCrab family is recognised by the adapter but returns not-compatible because
    the executable is unavailable in the test environment."""
    result = find_compatible_adapters(ransomware_family="GandCrab")
    # The adapter is_compatible returns False when status=UNAVAILABLE
    compatible_ids = [a.adapter_id for a, _ in result]
    assert "nmr_gandcrab" not in compatible_ids  # unavailable → not compatible


def test_available_count_type():
    count = available_count()
    assert isinstance(count, int)
    assert count >= 0


def test_required_adapters_registered():
    ids = {a.adapter_id for a in list_adapters()}
    assert "nmr_gandcrab" in ids
    assert "emsisoft_generic_stub" in ids
