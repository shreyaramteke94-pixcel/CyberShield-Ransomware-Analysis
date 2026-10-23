"""
Unit tests for ransomware_detection package components:
- Analyzer
- Entropy calculation
- Features extraction
- RansomwarePredictor
- RiskEngine
- ThreatIntelligence
"""

import os
from pathlib import Path
import pytest

from src.entropy import calculate_entropy, entropy_level
from src.features import extract_features, add_threat_intelligence_features
from src.file_features import extract_features as extract_file_features
from src.predict import RansomwarePredictor
from src.risk_engine import RiskEngine
from src.analyzer import Analyzer
from src.threat_intelligence import ThreatIntelligence


@pytest.fixture
def sample_text_file(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("This is clean plain text without any ransomware activity.", encoding="utf-8")
    return f


@pytest.fixture
def high_entropy_file(tmp_path):
    f = tmp_path / "encrypted_sample.bin"
    f.write_bytes(os.urandom(2048))
    return f


def test_calculate_entropy_plain(sample_text_file):
    entropy = calculate_entropy(str(sample_text_file))
    assert 0.0 <= entropy <= 5.0
    level = entropy_level(entropy)
    assert level in ["LOW", "MEDIUM", "HIGH"]


def test_calculate_entropy_random(high_entropy_file):
    entropy = calculate_entropy(str(high_entropy_file))
    assert entropy > 7.0
    level = entropy_level(entropy)
    assert level in ["HIGH", "VERY HIGH"]


def test_extract_features(sample_text_file):
    features = extract_features(
        file_path=str(sample_text_file),
        yara_matches=[],
        entropy=3.5,
    )
    assert "file_size" in features
    assert "entropy" in features
    assert "suspicious_extension" in features
    assert "yara_match_count" in features
    assert features["entropy"] == 3.5


def test_extract_features_with_threat_intelligence(sample_text_file):
    features = extract_features(str(sample_text_file), [], 2.0)
    features = add_threat_intelligence_features(features, 85)
    assert features["threat_intelligence_score"] == 85


def test_extract_file_features(sample_text_file):
    data = sample_text_file.read_bytes()
    features = extract_file_features(
        filename=sample_text_file.name,
        data=data,
        yara_match_count=0,
        threat_intelligence_score=0.0,
    )
    assert features["file_size"] > 0
    assert 0.0 <= features["entropy"] <= 8.0
    assert "threat_intelligence_score" in features
    assert "suspicious_extension" in features


def test_ransomware_predictor_prediction(sample_text_file):
    predictor = RansomwarePredictor()
    data = sample_text_file.read_bytes()
    features = extract_file_features(
        filename=sample_text_file.name,
        data=data,
        yara_match_count=0,
        threat_intelligence_score=0.0,
    )
    result = predictor.predict(features)
    assert "prediction" in result
    assert "risk_probability" in result
    assert result["prediction"] in ["benign", "ransomware"]
    assert 0.0 <= result["risk_probability"] <= 1.0


def test_risk_engine():
    engine = RiskEngine()
    result = engine.calculate(
        ml_probability=0.95,
        entropy=7.8,
        yara_match_count=2,
        suspicious_extension=1,
        threat_intelligence_score=80.0,
    )
    assert hasattr(result, "score")
    assert hasattr(result, "level")
    assert hasattr(result, "reasons")
    assert result.level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert result.score > 50


def test_analyzer_end_to_end(sample_text_file):
    analyzer = Analyzer()
    data = sample_text_file.read_bytes()
    features = extract_file_features(
        filename=sample_text_file.name,
        data=data,
        yara_match_count=0,
        threat_intelligence_score=0.0,
    )
    analysis = analyzer.analyze(features)
    assert "risk_score" in analysis
    assert "risk_level" in analysis
    assert "reasons" in analysis
    assert "ml_prediction" in analysis
    assert "ml_probability" in analysis


def test_threat_intelligence_lookup():
    ti_path = Path(__file__).resolve().parents[1] / "threat_intelligence.csv"
    if not ti_path.exists():
        pytest.skip("threat_intelligence.csv not found")
    ti = ThreatIntelligence(str(ti_path))
    assert len(ti.indicators) > 0
    # Lookup non-existent
    assert ti.lookup("NON_EXISTENT_INDICATOR") == []
    # Test is_known_indicator
    assert ti.is_known_indicator("NON_EXISTENT_INDICATOR") is False
