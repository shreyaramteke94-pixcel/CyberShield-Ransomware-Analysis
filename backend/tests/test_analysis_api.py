
from datetime import datetime
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.analysis import router
from app.database.database import get_db
from app.repositories.sample_repository import SampleRepository
from app.repositories.analysis_repository import AnalysisRepository


app = FastAPI()
app.include_router(router)


def override_get_db():
    yield object()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


def test_analysis_returns_saved_results(monkeypatch):
    sample = SimpleNamespace(
        id="sample-123",
        original_filename="example.txt",
        sha256="abc123",
    )
    analysis = SimpleNamespace(
        mime_type="text/plain",
        entropy=4.2,
        pe_analysis=None,
        yara_matches=["Generic_Ransomware"],
        suspicious_strings=["SEND PAYMENT"],
        risk_score=28,
        severity="MEDIUM",
        analyzed_at=datetime(2026, 1, 1),
    )

    monkeypatch.setattr(
        SampleRepository, "get_by_id",
        staticmethod(lambda db, sample_id: sample),
    )
    monkeypatch.setattr(
        AnalysisRepository, "get_by_sample_id",
        staticmethod(lambda db, sample_id: analysis),
    )

    response = client.get("/api/v1/analysis/sample-123")

    assert response.status_code == 200
    body = response.json()
    assert body["sample_id"] == "sample-123"
    assert body["analysis"]["risk_score"] == 28
    assert body["analysis"]["severity"] == "MEDIUM"
    assert body["analysis"]["yara_matches"] == ["Generic_Ransomware"]


def test_analysis_returns_404_for_missing_sample(monkeypatch):
    monkeypatch.setattr(
        SampleRepository, "get_by_id",
        staticmethod(lambda db, sample_id: None),
    )

    response = client.get("/api/v1/analysis/missing-sample")

    assert response.status_code == 404
    assert response.json()["detail"] == "Sample not found."


def test_analysis_returns_404_when_results_are_missing(monkeypatch):
    sample = SimpleNamespace(
        id="sample-456",
        original_filename="example.txt",
        sha256="abc123",
    )

    monkeypatch.setattr(
        SampleRepository, "get_by_id",
        staticmethod(lambda db, sample_id: sample),
    )
    monkeypatch.setattr(
        AnalysisRepository, "get_by_sample_id",
        staticmethod(lambda db, sample_id: None),
    )

    response = client.get("/api/v1/analysis/sample-456")

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "No saved analysis results found for this sample."
    )
