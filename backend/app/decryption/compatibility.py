"""
Compatibility checker for the CyberShield Decryption & Recovery Engine.

This module evaluates whether a real ransomware sample is eligible for
supported recovery, based on the analysis results already stored in the
CyberShield database.

It answers the question:
  "Given what we know about this sample, can we attempt recovery?"

It does NOT perform decryption.  It does NOT modify files.

Recovery status values (subset used here)
------------------------------------------
  ANALYSIS_REQUIRED     – No analysis results found for the sample.
  FAMILY_UNKNOWN        – Analysis ran but could not identify a family.
  VARIANT_UNCONFIRMED   – Family identified but variant/cipher is uncertain.
  DECRYPTOR_UNAVAILABLE – Family known but no adapter supports it.
  UNSUPPORTED_VARIANT   – Family known, adapter exists, but variant mismatch.
  KEY_REQUIRED          – Compatible adapter found but requires key material.
  READY_FOR_RECOVERY    – Compatible adapter found and all conditions met.

Honesty rule
------------
The checker MUST return uncertainty explicitly.  Returning
DECRYPTOR_UNAVAILABLE when recovery is genuinely unsupported is correct
and honest.  Do not use READY_FOR_RECOVERY unless at least one adapter's
is_compatible() call returned True AND its status == 'AVAILABLE'.
"""

import logging
from typing import Any

from app.decryption import registry as reg

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def check_eligibility(
    sample_id: str,
    filename: str,
    identification_result: dict[str, Any] | None,
    analysis_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Evaluate recovery eligibility for a sample.

    Parameters
    ----------
    sample_id : str
        The sample's UUID from the CyberShield database.
    filename : str
        Original filename (for display purposes).
    identification_result : dict | None
        The dict returned by RansomwareIdentificationService.identify().
        Expected keys: ransomware_family, cipher_algorithm, confidence,
        identification_status.
    analysis_result : dict | None
        The dict returned by AnalysisServices.analyze().
        Used to collect evidence indicators.

    Returns
    -------
    dict with EligibilityResponse-compatible structure.
    """
    evidence: list[str] = []
    limitations: list[str] = []

    # --- No analysis available ---
    if identification_result is None and analysis_result is None:
        return _build_result(
            sample_id=sample_id,
            filename=filename,
            status="ANALYSIS_REQUIRED",
            family=None,
            confidence=None,
            compatible_adapters=[],
            evidence=evidence,
            limitations=["No analysis results found for this sample."],
            explanation=(
                "This sample has not been analysed yet. "
                "Run the CyberShield static analysis before checking eligibility."
            ),
        )

    identification_result = identification_result or {}
    analysis_result = analysis_result or {}

    ransomware_family = identification_result.get("ransomware_family")
    cipher_algorithm = identification_result.get("cipher_algorithm")
    confidence = identification_result.get("confidence")
    id_status = identification_result.get("identification_status", "")

    # --- Collect evidence indicators ---
    yara_matches = analysis_result.get("yara_matches") or []
    suspicious_strings = analysis_result.get("suspicious_strings") or []
    risk_score = analysis_result.get("risk_score", 0)
    severity = analysis_result.get("severity", "LOW")

    if yara_matches:
        evidence.append(f"YARA matches: {', '.join(str(y) for y in yara_matches[:5])}")
    if risk_score:
        evidence.append(f"Risk score: {risk_score}/100 ({severity})")
    if suspicious_strings:
        evidence.append(
            f"{len(suspicious_strings)} suspicious string(s) detected"
        )
    if ransomware_family:
        evidence.append(f"Identified family: {ransomware_family}")
    if cipher_algorithm and cipher_algorithm not in {"None", "Unknown", "N/A"}:
        evidence.append(f"Cipher algorithm: {cipher_algorithm}")
    if confidence is not None:
        evidence.append(f"Identification confidence: {confidence:.0%}")

    # --- Benign / clean sample ---
    if id_status == "BENIGN" or (
        ransomware_family and ransomware_family.lower() in {
            "benign / clean", "benign", "clean"
        }
    ):
        limitations.append("This sample was identified as benign or clean.")
        return _build_result(
            sample_id=sample_id,
            filename=filename,
            status="DECRYPTOR_UNAVAILABLE",
            family=ransomware_family,
            confidence=confidence,
            compatible_adapters=[],
            evidence=evidence,
            limitations=limitations,
            explanation=(
                "This sample has been identified as benign or clean. "
                "No ransomware decryptor is applicable."
            ),
        )

    # --- Unknown family ---
    if not ransomware_family or ransomware_family.lower() in {
        "unknown", "n/a", ""
    }:
        limitations.append(
            "The ransomware family could not be identified from static analysis."
        )
        limitations.append(
            "Without a confirmed family identification, no decryptor can be selected."
        )
        return _build_result(
            sample_id=sample_id,
            filename=filename,
            status="FAMILY_UNKNOWN",
            family=None,
            confidence=confidence,
            compatible_adapters=[],
            evidence=evidence,
            limitations=limitations,
            explanation=(
                "Static analysis detected suspicious indicators, but could not "
                "identify a specific ransomware family. "
                "No compatible decryptor can be selected without a confirmed family. "
                "Consider submitting to a threat intelligence platform or "
                "No More Ransom's ID Ransomware service."
            ),
        )

    # --- Family identified — check adapter compatibility ---
    compatible = reg.find_compatible_adapters(
        ransomware_family=ransomware_family,
        variant=None,  # variant identification not yet implemented
        file_extension=analysis_result.get("extension"),
    )

    compatible_ids = [a.adapter_id for a, _ in compatible]

    if not compatible:
        limitations.append(
            f"No registered adapter supports the '{ransomware_family}' family "
            "at this time."
        )
        limitations.append(
            "Modern ransomware using strong key management (LockBit 3.0, "
            "BlackCat/ALPHV, etc.) typically cannot be decrypted without the "
            "threat actor's private key or a flaw in their implementation."
        )
        return _build_result(
            sample_id=sample_id,
            filename=filename,
            status="DECRYPTOR_UNAVAILABLE",
            family=ransomware_family,
            confidence=confidence,
            compatible_adapters=[],
            evidence=evidence,
            limitations=limitations,
            explanation=(
                f"The family '{ransomware_family}' was identified, but no "
                "verified decryptor adapter is available for it. "
                "Check the No More Ransom (nomoreransom.org) and Emsisoft "
                "(emsisoft.com/en/ransomware-decryption/) tools pages for "
                "the latest coverage."
            ),
        )

    # Compatible adapter(s) found — check if any are AVAILABLE.
    available_adapters = [
        a for a, _ in compatible if a.status == "AVAILABLE"
    ]

    if not available_adapters:
        limitations.append(
            "Compatible adapter(s) found but prerequisites are not satisfied."
        )
        for adapter, reason in compatible:
            limitations.append(f"{adapter.display_name}: {reason}")
        return _build_result(
            sample_id=sample_id,
            filename=filename,
            status="KEY_REQUIRED",
            family=ransomware_family,
            confidence=confidence,
            compatible_adapters=compatible_ids,
            evidence=evidence,
            limitations=limitations,
            explanation=(
                f"The family '{ransomware_family}' has a registered decryptor, "
                "but the adapter prerequisites are not yet satisfied. "
                "See the limitations for what is required before recovery can proceed."
            ),
        )

    # READY_FOR_RECOVERY — at least one AVAILABLE adapter is compatible.
    return _build_result(
        sample_id=sample_id,
        filename=filename,
        status="READY_FOR_RECOVERY",
        family=ransomware_family,
        confidence=confidence,
        compatible_adapters=compatible_ids,
        evidence=evidence,
        limitations=limitations,
        explanation=(
            f"The family '{ransomware_family}' has a compatible and available "
            "decryptor. Explicit operator approval is required before proceeding."
        ),
    )


# ---------------------------------------------------------------------------
# Internal builder
# ---------------------------------------------------------------------------


def _build_result(
    sample_id: str,
    filename: str,
    status: str,
    family: str | None,
    confidence: float | None,
    compatible_adapters: list[str],
    evidence: list[str],
    limitations: list[str],
    explanation: str,
) -> dict:
    return {
        "sample_id": sample_id,
        "filename": filename,
        "recovery_status": status,
        "ransomware_family": family,
        "identification_confidence": confidence,
        "compatible_adapters": compatible_adapters,
        "evidence": evidence,
        "limitations": limitations,
        "explanation": explanation,
    }
