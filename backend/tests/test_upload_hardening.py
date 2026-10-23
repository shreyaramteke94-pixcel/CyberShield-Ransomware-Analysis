"""
Targeted tests for Stage 2: Real Upload Hardening, Safe Static Analysis, and Reporting.

Covers:
  - Streaming file size enforcement against MAX_FILE_SIZE (HTTP 413)
  - Mid-stream limit exceeding and disk cleanup (no partial file remains)
  - Rejection of empty (0-byte) files (HTTP 400)
  - Path traversal attempts in filenames (HTTP 400)
  - Null bytes and control characters in filenames (HTTP 400)
  - Missing and unsupported file extensions (HTTP 400)
  - Duplicate filenames get distinct storage UUIDs without collision
  - Failed analysis triggers cleanup of both storage file and DB sample record
  - SHA-256 calculation correctness
  - GET /api/v1/samples/ listing endpoint and authorization note
  - GET /api/v1/samples/{sample_id} metadata and validation
  - GET /api/v1/samples/{sample_id}/report standardized forensic report and attachment download
"""

import hashlib
import io
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database.database import Base, get_db
from app.main import app
from app.models.sample import Sample
from app.models.analysis import Analysis
from app.repositories.sample_repository import SampleRepository
from app.repositories.analysis_repository import AnalysisRepository


# ---------------------------------------------------------------------------
# Test Database & Client Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def test_db_session():
    """Create an isolated in-memory SQLite database for upload tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db_session, tmp_path):
    """Provide a TestClient with temporary upload directory and isolated DB."""
    test_upload_dir = tmp_path / "test_uploads"
    test_upload_dir.mkdir(parents=True, exist_ok=True)

    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    with patch.object(settings, "UPLOAD_DIR", str(test_upload_dir)):
        yield TestClient(app), test_upload_dir

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. Size Limit & Streaming Enforcement
# ---------------------------------------------------------------------------


def test_upload_streaming_exceeds_max_size_returns_413(client):
    tc, upload_dir = client
    # Set a small MAX_FILE_SIZE (e.g., 50 KB)
    small_limit = 50 * 1024
    with patch.object(settings, "MAX_FILE_SIZE", small_limit):
        oversized_data = b"A" * (small_limit + 1024)  # 51 KB
        resp = tc.post(
            "/api/v1/upload/",
            files={"file": ("large_sample.txt", io.BytesIO(oversized_data), "text/plain")},
        )
        assert resp.status_code == 413
        assert "exceeds maximum allowed size" in resp.json()["detail"]

        # Ensure no partial file was left in the upload directory
        files_left = list(upload_dir.glob("*"))
        assert len(files_left) == 0, f"Expected 0 files in upload dir, found: {files_left}"


def test_upload_within_size_limit_succeeds(client):
    tc, upload_dir = client
    payload = b"Safe benign content for static analysis test."
    resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("benign.txt", io.BytesIO(payload), "text/plain")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "benign.txt"
    assert data["file_size"] == len(payload)
    assert data["sha256"] == hashlib.sha256(payload).hexdigest()

    # Stored file must exist on disk
    stored = upload_dir / data["stored_filename"]
    assert stored.is_file()
    assert stored.read_bytes() == payload


# ---------------------------------------------------------------------------
# 2. Empty Files and Filename Validation
# ---------------------------------------------------------------------------


def test_upload_empty_file_rejected(client):
    tc, upload_dir = client
    resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("empty.txt", io.BytesIO(b""), "text/plain")},
    )
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()
    assert len(list(upload_dir.glob("*"))) == 0


def test_upload_path_traversal_filename_rejected(client):
    tc, upload_dir = client
    malicious_names = [
        "../../etc_passwd.txt",
        "..\\windows_system32.txt",
        "sub/folder/sample.txt",
        "..\\..\\boot.ini.txt",
    ]
    for bad_name in malicious_names:
        resp = tc.post(
            "/api/v1/upload/",
            files={"file": (bad_name, io.BytesIO(b"test data"), "text/plain")},
        )
        assert resp.status_code == 400
        assert "path" in resp.json()["detail"].lower() or "traversal" in resp.json()["detail"].lower()
        assert len(list(upload_dir.glob("*"))) == 0


def test_upload_null_byte_filename_rejected(client):
    tc, upload_dir = client
    resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("bad\x00file.txt", io.BytesIO(b"test data"), "text/plain")},
    )
    assert resp.status_code == 400
    assert len(list(upload_dir.glob("*"))) == 0


def test_upload_missing_extension_rejected(client):
    tc, upload_dir = client
    resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("unknown_format", io.BytesIO(b"binary data"), "application/octet-stream")},
    )
    assert resp.status_code == 400
    assert "extension" in resp.json()["detail"].lower()


def test_upload_unsupported_extension_rejected(client):
    tc, upload_dir = client
    resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("script.sh", io.BytesIO(b"#!/bin/bash\necho hello"), "text/x-sh")},
    )
    assert resp.status_code == 400
    assert "unsupported file type" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 3. Duplicate Filenames & Unique Storage
# ---------------------------------------------------------------------------


def test_upload_duplicate_filenames_stored_safely(client):
    tc, upload_dir = client
    payload1 = b"Version 1 of confidential report"
    payload2 = b"Version 2 of confidential report with new numbers"

    resp1 = tc.post(
        "/api/v1/upload/",
        files={"file": ("report.txt", io.BytesIO(payload1), "text/plain")},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()

    resp2 = tc.post(
        "/api/v1/upload/",
        files={"file": ("report.txt", io.BytesIO(payload2), "text/plain")},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()

    # Must have distinct sample IDs and distinct stored filenames
    assert data1["sample_id"] != data2["sample_id"]
    assert data1["stored_filename"] != data2["stored_filename"]

    # Both files must coexist on disk without overwriting
    f1 = upload_dir / data1["stored_filename"]
    f2 = upload_dir / data2["stored_filename"]
    assert f1.read_bytes() == payload1
    assert f2.read_bytes() == payload2


# ---------------------------------------------------------------------------
# 4. Failure Cleanup (No orphaned files or partial DB records)
# ---------------------------------------------------------------------------


def test_upload_cleans_up_on_analysis_failure(client, monkeypatch):
    tc, upload_dir = client

    def fail_analysis(*args, **kwargs):
        raise RuntimeError("Simulated static analyzer crash")

    from app.services.analysis_services import AnalysisServices
    monkeypatch.setattr(AnalysisServices, "analyze", fail_analysis)

    resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("sample.txt", io.BytesIO(b"payload content"), "text/plain")},
    )
    assert resp.status_code == 500

    # Verify no file remains on disk
    files = list(upload_dir.glob("*"))
    assert len(files) == 0


# ---------------------------------------------------------------------------
# 5. Sample Listing & Forensic Reporting Endpoints
# ---------------------------------------------------------------------------


def test_list_samples_returns_items(client):
    tc, _ = client
    # Upload one sample first
    tc.post(
        "/api/v1/upload/",
        files={"file": ("document.txt", io.BytesIO(b"sample document text"), "text/plain")},
    )

    resp = tc.get("/api/v1/samples/")
    assert resp.status_code == 200
    data = resp.json()
    assert "samples" in data
    assert "total" in data
    assert data["total"] >= 1
    assert "auth_model_note" in data
    assert data["samples"][0]["original_filename"] == "document.txt"


def test_get_sample_by_id(client):
    tc, _ = client
    upload_resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("document.txt", io.BytesIO(b"sample document text"), "text/plain")},
    )
    sample_id = upload_resp.json()["sample_id"]

    resp = tc.get(f"/api/v1/samples/{sample_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == sample_id
    assert resp.json()["original_filename"] == "document.txt"


def test_get_sample_invalid_id_format_rejected(client):
    tc, _ = client
    # Attempt directory traversal or malformed characters in ID
    resp = tc.get("/api/v1/samples/..%2F..%2Fsecret")
    assert resp.status_code in {400, 404}


def test_get_sample_not_found(client):
    tc, _ = client
    resp = tc.get("/api/v1/samples/nonexistent-uuid-9999")
    assert resp.status_code == 404


def test_get_sample_report_success(client):
    tc, _ = client
    upload_resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("analysis_target.txt", io.BytesIO(b"Sample analysis target body"), "text/plain")},
    )
    sample_id = upload_resp.json()["sample_id"]

    resp = tc.get(f"/api/v1/samples/{sample_id}/report")
    assert resp.status_code == 200
    report = resp.json()

    assert report["report_id"] == f"CSR-{sample_id}"
    assert "platform" in report
    assert "static_analysis" in report
    assert "recovery_assessment" in report
    assert report["sample"]["original_filename"] == "analysis_target.txt"
    assert report["static_analysis"]["entropy"] is not None


def test_get_sample_report_download_header(client):
    tc, _ = client
    upload_resp = tc.post(
        "/api/v1/upload/",
        files={"file": ("export_target.txt", io.BytesIO(b"Export target data"), "text/plain")},
    )
    sample_id = upload_resp.json()["sample_id"]

    resp = tc.get(f"/api/v1/samples/{sample_id}/report?download=true")
    assert resp.status_code == 200
    assert "Content-Disposition" in resp.headers
    assert "attachment" in resp.headers["Content-Disposition"]
    assert f"CyberShield_Report_{sample_id[:8]}.json" in resp.headers["Content-Disposition"]
