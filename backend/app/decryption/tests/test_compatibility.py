"""
Tests for app.decryption.compatibility

Covers:
  - No analysis → ANALYSIS_REQUIRED
  - Benign family → DECRYPTOR_UNAVAILABLE
  - Unknown family → FAMILY_UNKNOWN
  - Known unsupported family → DECRYPTOR_UNAVAILABLE
  - Return structure always has required fields
  - Uncertainty is propagated explicitly
"""

import pytest

from app.decryption.compatibility import check_eligibility


SAMPLE_ID = "test-sample-uuid-0001"
FILENAME = "test_sample.exe"


def _result(identification=None, analysis=None):
    return check_eligibility(
        sample_id=SAMPLE_ID,
        filename=FILENAME,
        identification_result=identification,
        analysis_result=analysis,
    )


# ---------------------------------------------------------------------------
# Required fields in every response
# ---------------------------------------------------------------------------


def _assert_has_required_fields(result: dict):
    for field in ("sample_id", "filename", "recovery_status",
                  "compatible_adapters", "evidence", "limitations", "explanation"):
        assert field in result, f"Missing field: {field}"
    assert isinstance(result["compatible_adapters"], list)
    assert isinstance(result["evidence"], list)
    assert isinstance(result["limitations"], list)
    assert isinstance(result["explanation"], str)


def test_no_analysis_returns_analysis_required():
    result = _result(identification=None, analysis=None)
    assert result["recovery_status"] == "ANALYSIS_REQUIRED"
    _assert_has_required_fields(result)


def test_empty_dicts_treated_as_unknown():
    result = _result(identification={}, analysis={})
    assert result["recovery_status"] == "FAMILY_UNKNOWN"
    _assert_has_required_fields(result)


# ---------------------------------------------------------------------------
# Benign
# ---------------------------------------------------------------------------


def test_benign_family_returns_unavailable():
    identification = {
        "ransomware_family": "Benign / Clean",
        "identification_status": "BENIGN",
        "confidence": 0.99,
        "cipher_algorithm": None,
    }
    result = _result(identification=identification, analysis={})
    assert result["recovery_status"] == "DECRYPTOR_UNAVAILABLE"
    _assert_has_required_fields(result)


def test_benign_status_flag_returns_unavailable():
    identification = {
        "ransomware_family": "Unknown",
        "identification_status": "BENIGN",
        "confidence": 0.95,
        "cipher_algorithm": None,
    }
    result = _result(identification=identification, analysis={})
    assert result["recovery_status"] == "DECRYPTOR_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Unknown family
# ---------------------------------------------------------------------------


def test_unknown_family_string_returns_family_unknown():
    identification = {
        "ransomware_family": "Unknown",
        "identification_status": "IDENTIFIED",
        "confidence": 0.3,
        "cipher_algorithm": "AES-256",
    }
    result = _result(identification=identification, analysis={})
    assert result["recovery_status"] == "FAMILY_UNKNOWN"
    _assert_has_required_fields(result)


def test_none_family_returns_family_unknown():
    identification = {
        "ransomware_family": None,
        "identification_status": "",
        "confidence": None,
        "cipher_algorithm": None,
    }
    result = _result(identification=identification, analysis={})
    assert result["recovery_status"] == "FAMILY_UNKNOWN"


# ---------------------------------------------------------------------------
# Unsupported (but known) family
# ---------------------------------------------------------------------------


def test_lockbit_returns_decryptor_unavailable():
    """LockBit 3.0 has no registered adapter → DECRYPTOR_UNAVAILABLE."""
    identification = {
        "ransomware_family": "LockBit 3.0",
        "identification_status": "IDENTIFIED",
        "confidence": 0.85,
        "cipher_algorithm": "AES-256-CTR",
    }
    analysis = {
        "risk_score": 95,
        "severity": "CRITICAL",
        "yara_matches": ["LockBit_3_Ransom_Note"],
        "suspicious_strings": ["Your files have been encrypted"],
    }
    result = _result(identification=identification, analysis=analysis)
    assert result["recovery_status"] == "DECRYPTOR_UNAVAILABLE"
    assert result["compatible_adapters"] == []
    _assert_has_required_fields(result)


def test_wannacry_returns_decryptor_unavailable():
    """WannaCry has no registered adapter in the current registry."""
    identification = {
        "ransomware_family": "WannaCry",
        "identification_status": "IDENTIFIED",
        "confidence": 0.9,
        "cipher_algorithm": "AES-128-CBC",
    }
    result = _result(identification=identification, analysis={})
    assert result["recovery_status"] == "DECRYPTOR_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Evidence propagation
# ---------------------------------------------------------------------------


def test_evidence_includes_yara_matches():
    identification = {
        "ransomware_family": "Unknown",
        "identification_status": "",
        "confidence": 0.2,
        "cipher_algorithm": None,
    }
    analysis = {
        "risk_score": 70,
        "severity": "HIGH",
        "yara_matches": ["Generic_Ransomware_Note"],
        "suspicious_strings": [],
    }
    result = _result(identification=identification, analysis=analysis)
    assert any("YARA" in e for e in result["evidence"])


def test_limitations_non_empty_for_unavailable():
    identification = {
        "ransomware_family": "LockBit 3.0",
        "identification_status": "IDENTIFIED",
        "confidence": 0.9,
        "cipher_algorithm": "AES-256",
    }
    result = _result(identification=identification, analysis={})
    assert len(result["limitations"]) > 0
