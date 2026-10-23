
import os

os.environ.setdefault(
    "SECRET_KEY",
    "pytest-only-secret-key-not-for-production",
)
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite:///./pytest_test.db",
)

from app.services.file_service import FileService


def make_analysis(
    risk_score=0,
    severity="LOW",
    yara_matches=None,
):
    return {
        "risk_score": risk_score,
        "severity": severity,
        "yara_matches": yara_matches or [],
    }


def make_ml_result(risk_level="LOW"):
    return {"risk_level": risk_level}


def test_clean_file_returns_low_risk():
    assert FileService._determine_overall_verdict(
        make_analysis(),
        make_ml_result(),
    ) == "LOW_RISK"


def test_yara_match_returns_suspicious():
    assert FileService._determine_overall_verdict(
        make_analysis(
            risk_score=28,
            severity="MEDIUM",
            yara_matches=["Generic_Ransomware"],
        ),
        make_ml_result(),
    ) == "SUSPICIOUS"


def test_medium_static_severity_returns_suspicious():
    assert FileService._determine_overall_verdict(
        make_analysis(risk_score=28, severity="MEDIUM"),
        make_ml_result(),
    ) == "SUSPICIOUS"


def test_static_score_50_returns_high_risk():
    assert FileService._determine_overall_verdict(
        make_analysis(risk_score=50),
        make_ml_result(),
    ) == "HIGH_RISK"


def test_critical_severity_returns_high_risk():
    assert FileService._determine_overall_verdict(
        make_analysis(risk_score=30, severity="CRITICAL"),
        make_ml_result(),
    ) == "HIGH_RISK"


def test_ml_medium_risk_returns_suspicious():
    assert FileService._determine_overall_verdict(
        make_analysis(),
        make_ml_result("MEDIUM"),
    ) == "SUSPICIOUS"


def test_static_high_risk_overrides_benign_ml():
    assert FileService._determine_overall_verdict(
        make_analysis(risk_score=60, severity="HIGH"),
        {
            "ml_prediction": "benign",
            "risk_level": "LOW",
        },
    ) == "HIGH_RISK"
