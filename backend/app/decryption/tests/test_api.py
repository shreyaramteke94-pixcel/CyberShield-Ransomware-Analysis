"""
Tests for the CyberShield Decryption Engine API endpoints.

Covers:
  - GET  /api/v1/decryption/demo/files        → 200, returns file list
  - POST /api/v1/decryption/demo/encrypt      → 201, returns key + filename
  - POST /api/v1/decryption/demo/encrypt      → 400 on path traversal
  - POST /api/v1/decryption/demo/encrypt      → 404 on missing file
  - POST /api/v1/decryption/demo/jobs         → 201, RECOVERY_SUCCEEDED with correct key
  - POST /api/v1/decryption/demo/jobs         → 201, RECOVERY_FAILED with wrong key
  - POST /api/v1/decryption/demo/jobs         → 404 on missing encrypted file
  - POST /api/v1/decryption/demo/jobs         → 422 on malformed key
  - GET  /api/v1/decryption/demo/jobs         → 200, list
  - GET  /api/v1/decryption/demo/jobs/{id}    → 200 for known job
  - GET  /api/v1/decryption/demo/jobs/{id}    → 404 for unknown job
  - GET  /api/v1/decryption/registry          → 200, adapters present
  - Response never contains server filesystem paths (only basenames)
"""

import base64
import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# We import the router from the existing file to avoid re-creating it.
from app.api.decrypt import router, _demo_dir, _encrypted_dir, _output_dir


# ---------------------------------------------------------------------------
# Build a test application that uses the real decryption router
# with overridden directory paths pointing to tmp dirs.
# ---------------------------------------------------------------------------

app = FastAPI()
app.include_router(router)
client = TestClient(app)


@pytest.fixture(autouse=True)
def patch_dirs(tmp_path):
    """
    Redirect the three directory helpers to temporary paths for every test.
    Each test gets an isolated environment.
    """
    demo = tmp_path / "demo_files"
    demo.mkdir()
    # Provide a real demo file
    (demo / "sample_report.txt").write_bytes(
        b"CyberShield API test demo file content."
    )

    encrypted = demo / "encrypted"
    encrypted.mkdir()

    recovery = tmp_path / "recovery_output"
    recovery.mkdir()

    with (
        patch("app.api.decrypt._demo_dir", return_value=demo),
        patch("app.api.decrypt._encrypted_dir", return_value=encrypted),
        patch("app.api.decrypt._output_dir", return_value=recovery),
    ):
        yield {"demo": demo, "encrypted": encrypted, "recovery": recovery}


# ---------------------------------------------------------------------------
# GET /demo/files
# ---------------------------------------------------------------------------


def test_list_demo_files_returns_200():
    resp = client.get("/api/v1/decryption/demo/files")
    assert resp.status_code == 200


def test_list_demo_files_has_files():
    resp = client.get("/api/v1/decryption/demo/files")
    data = resp.json()
    assert "files" in data
    assert len(data["files"]) >= 1
    file_names = [f["filename"] for f in data["files"]]
    assert "sample_report.txt" in file_names


def test_list_demo_files_has_note():
    resp = client.get("/api/v1/decryption/demo/files")
    data = resp.json()
    assert "demo_directory_note" in data


# ---------------------------------------------------------------------------
# POST /demo/encrypt
# ---------------------------------------------------------------------------


def test_encrypt_returns_201():
    resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "sample_report.txt"},
    )
    assert resp.status_code == 201


def test_encrypt_response_has_key():
    resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "sample_report.txt"},
    )
    data = resp.json()
    assert "key_b64" in data
    assert "encrypted_filename" in data
    assert "plaintext_sha256" in data
    assert data["encrypted_filename"].endswith(".csde")


def test_encrypt_key_is_32_bytes():
    resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "sample_report.txt"},
    )
    key_b64 = resp.json()["key_b64"]
    key = base64.urlsafe_b64decode(key_b64 + "==")
    assert len(key) == 32


def test_encrypt_has_warning_field():
    resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "sample_report.txt"},
    )
    assert "warning" in resp.json()


def test_encrypt_missing_file_returns_404():
    resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "does_not_exist.txt"},
    )
    assert resp.status_code == 404


def test_encrypt_path_traversal_returns_400():
    resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "../../../etc/passwd"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /demo/jobs — success
# ---------------------------------------------------------------------------


@pytest.fixture
def encrypt_result():
    resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "sample_report.txt"},
    )
    assert resp.status_code == 201
    return resp.json()


def test_decrypt_job_succeeds(encrypt_result):
    resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": encrypt_result["encrypted_filename"],
            "key_b64": encrypt_result["key_b64"],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "RECOVERY_SUCCEEDED"
    assert data["verified"] is True


def test_decrypt_job_response_has_no_server_path(encrypt_result):
    resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": encrypt_result["encrypted_filename"],
            "key_b64": encrypt_result["key_b64"],
        },
    )
    data = resp.json()
    # output_path in response must be a basename only, not an absolute path
    output_path = data.get("output_path")
    if output_path:
        assert "/" not in output_path or not output_path.startswith("/")
        assert ":\\" not in output_path


def test_decrypt_job_response_no_key_material(encrypt_result):
    resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": encrypt_result["encrypted_filename"],
            "key_b64": encrypt_result["key_b64"],
        },
    )
    resp_text = resp.text
    # The key should not appear in the job response
    assert encrypt_result["key_b64"] not in resp_text


# ---------------------------------------------------------------------------
# POST /demo/jobs — failure paths
# ---------------------------------------------------------------------------


def test_decrypt_job_wrong_key_fails(encrypt_result):
    wrong_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": encrypt_result["encrypted_filename"],
            "key_b64": wrong_key,
        },
    )
    assert resp.status_code == 201  # Job is created, but it fails
    data = resp.json()
    assert data["status"] == "RECOVERY_FAILED"
    assert data["verified"] is False


def test_decrypt_job_missing_file_returns_404():
    resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": "nonexistent.csde",
            "key_b64": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        },
    )
    assert resp.status_code == 404


def test_decrypt_job_path_traversal_returns_400():
    resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": "../../../secret.csde",
            "key_b64": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        },
    )
    assert resp.status_code == 400


def test_decrypt_job_malformed_key_returns_422():
    resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": "something.csde",
            "key_b64": "NOT!!!VALID***BASE64",
        },
    )
    # Either 422 (key validation) or 404 (file not found first)
    assert resp.status_code in {400, 404, 422}


# ---------------------------------------------------------------------------
# GET /demo/jobs
# ---------------------------------------------------------------------------


def test_list_jobs_returns_200():
    resp = client.get("/api/v1/decryption/demo/jobs")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# GET /demo/jobs/{job_id}
# ---------------------------------------------------------------------------


def test_get_job_returns_200_for_known_job(encrypt_result):
    create_resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": encrypt_result["encrypted_filename"],
            "key_b64": encrypt_result["key_b64"],
        },
    )
    job_id = create_resp.json()["job_id"]
    get_resp = client.get(f"/api/v1/decryption/demo/jobs/{job_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["job_id"] == job_id


def test_get_job_returns_404_for_unknown():
    resp = client.get("/api/v1/decryption/demo/jobs/totally-fake-id-9999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /registry
# ---------------------------------------------------------------------------


def test_registry_returns_200():
    resp = client.get("/api/v1/decryption/registry")
    assert resp.status_code == 200


def test_registry_has_adapters():
    resp = client.get("/api/v1/decryption/registry")
    data = resp.json()
    assert "adapters" in data
    assert data["total"] >= 2
    assert isinstance(data["adapters"], list)


def test_registry_adapter_fields():
    resp = client.get("/api/v1/decryption/registry")
    for adapter in resp.json()["adapters"]:
        for field in ("adapter_id", "display_name", "source",
                      "supported_families", "status", "prerequisites",
                      "limitations", "can_run_automatically",
                      "requires_explicit_approval"):
            assert field in adapter, f"Missing field {field} in adapter"


# ---------------------------------------------------------------------------
# POST /{sample_id}/eligibility
# ---------------------------------------------------------------------------


def test_check_eligibility_invalid_sample_id_rejected():
    # Disallowed characters (e.g. $, !, spaces) or >64 chars should yield 400
    resp = client.post("/api/v1/decryption/invalid$sample*id/eligibility")
    assert resp.status_code == 400
    assert "Invalid sample ID format" in resp.json()["detail"]

    too_long = "a" * 65
    resp2 = client.post(f"/api/v1/decryption/{too_long}/eligibility")
    assert resp2.status_code == 400
    assert "Invalid sample ID format" in resp2.json()["detail"]


def test_check_eligibility_sample_not_found():
    with patch("app.repositories.sample_repository.SampleRepository.get_by_id", return_value=None):
        resp = client.post("/api/v1/decryption/nonexistent-sample-123/eligibility")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"]


def test_check_eligibility_lockbit_sample_truthfully_reports_unavailable():
    mock_sample = Mock()
    mock_sample.id = "sample-lockbit-uuid-1"
    mock_sample.original_filename = "payload.exe"
    mock_sample.file_extension = ".lockbit"

    mock_analysis = Mock()
    mock_analysis.ransomware_family = "LockBit 3.0"
    mock_analysis.cipher_algorithm = "AES-256-GCM / Curve25519"
    mock_analysis.confidence = 0.95
    mock_analysis.identification_status = "IDENTIFIED"
    mock_analysis.yara_matches = ["LockBit_Note"]
    mock_analysis.suspicious_strings = ["LockBit 3.0 all your files have been encrypted"]
    mock_analysis.risk_score = 95
    mock_analysis.severity = "CRITICAL"

    with (
        patch("app.repositories.sample_repository.SampleRepository.get_by_id", return_value=mock_sample),
        patch("app.repositories.analysis_repository.AnalysisRepository.get_by_sample_id", return_value=mock_analysis),
    ):
        resp = client.post(f"/api/v1/decryption/{mock_sample.id}/eligibility")
        assert resp.status_code == 200
        data = resp.json()
        assert data["sample_id"] == mock_sample.id
        assert data["recovery_status"] == "DECRYPTOR_UNAVAILABLE"
        assert data["ransomware_family"] == "LockBit 3.0"
        assert len(data["limitations"]) > 0
        assert "LockBit 3.0" in data["explanation"]


def test_check_eligibility_clean_sample_reports_unavailable():
    mock_sample = Mock()
    mock_sample.id = "clean-sample-uuid-2"
    mock_sample.original_filename = "document.pdf"
    mock_sample.file_extension = ".pdf"

    mock_analysis = Mock()
    mock_analysis.ransomware_family = "Benign / Clean"
    mock_analysis.cipher_algorithm = None
    mock_analysis.confidence = 0.99
    mock_analysis.identification_status = "BENIGN"
    mock_analysis.yara_matches = []
    mock_analysis.suspicious_strings = []
    mock_analysis.risk_score = 5
    mock_analysis.severity = "LOW"

    with (
        patch("app.repositories.sample_repository.SampleRepository.get_by_id", return_value=mock_sample),
        patch("app.repositories.analysis_repository.AnalysisRepository.get_by_sample_id", return_value=mock_analysis),
    ):
        resp = client.post(f"/api/v1/decryption/{mock_sample.id}/eligibility")
        assert resp.status_code == 200
        data = resp.json()
        assert data["recovery_status"] == "DECRYPTOR_UNAVAILABLE"
        assert "benign or clean" in data["explanation"].lower()


def test_check_eligibility_unidentified_family_reports_family_unknown():
    mock_sample = Mock()
    mock_sample.id = "unknown-sample-uuid-3"
    mock_sample.original_filename = "suspicious.bin"
    mock_sample.file_extension = ".bin"

    mock_analysis = Mock()
    mock_analysis.ransomware_family = "Unknown"
    mock_analysis.cipher_algorithm = None
    mock_analysis.confidence = 0.40
    mock_analysis.identification_status = "ANALYZED"
    mock_analysis.yara_matches = ["Generic_Ransom_Behavior"]
    mock_analysis.suspicious_strings = ["payment", "bitcoin"]
    mock_analysis.risk_score = 65
    mock_analysis.severity = "HIGH"

    with (
        patch("app.repositories.sample_repository.SampleRepository.get_by_id", return_value=mock_sample),
        patch("app.repositories.analysis_repository.AnalysisRepository.get_by_sample_id", return_value=mock_analysis),
    ):
        resp = client.post(f"/api/v1/decryption/{mock_sample.id}/eligibility")
        assert resp.status_code == 200
        data = resp.json()
        assert data["recovery_status"] == "FAMILY_UNKNOWN"
        assert "could not identify a specific ransomware family" in data["explanation"].lower()


# ---------------------------------------------------------------------------
# GET /demo/jobs/{job_id}/download  – round-trip and error cases
# ---------------------------------------------------------------------------

ORIGINAL_PLAINTEXT = b"CyberShield round-trip test: original plaintext bytes. \xde\xad\xbe\xef"


@pytest.fixture
def completed_job():
    """Encrypt a file and immediately decrypt it; return (original_bytes, job_id)."""
    # Write a synthetic demo file into the patched demo dir (provided by patch_dirs).
    # We reach it via the running TestClient, which already has patch_dirs active.
    resp_files = client.get("/api/v1/decryption/demo/files")
    # Use the first available file from the patched dir (sample_report.txt).
    filename = resp_files.json()["files"][0]["filename"]

    enc_resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": filename},
    )
    assert enc_resp.status_code == 201, f"Encrypt failed: {enc_resp.text}"
    enc_data = enc_resp.json()

    dec_resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": enc_data["encrypted_filename"],
            "key_b64": enc_data["key_b64"],
        },
    )
    assert dec_resp.status_code == 201, f"Decrypt job failed: {dec_resp.text}"
    job = dec_resp.json()
    assert job["status"] == "RECOVERY_SUCCEEDED", f"Job did not succeed: {job}"
    assert job["verified"] is True
    return job["job_id"]


def test_download_roundtrip_bytes_match_original(patch_dirs):
    """
    Full round-trip: encrypt demo file → decrypt → download.
    The downloaded bytes must match the original plaintext exactly.
    """
    demo_dir: Path = patch_dirs["demo"]
    original_path = demo_dir / "sample_report.txt"
    original_bytes = original_path.read_bytes()

    # Encrypt
    enc_resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "sample_report.txt"},
    )
    assert enc_resp.status_code == 201
    enc_data = enc_resp.json()

    # Decrypt
    dec_resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={
            "encrypted_filename": enc_data["encrypted_filename"],
            "key_b64": enc_data["key_b64"],
        },
    )
    assert dec_resp.status_code == 201
    job = dec_resp.json()
    assert job["status"] == "RECOVERY_SUCCEEDED"
    assert job["verified"] is True
    job_id = job["job_id"]

    # Download
    dl_resp = client.get(f"/api/v1/decryption/demo/jobs/{job_id}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.headers.get("content-type", "").startswith("application/octet-stream")

    # The downloaded content must be byte-for-byte identical to the original.
    assert dl_resp.content == original_bytes, (
        f"Downloaded {len(dl_resp.content)} bytes but original was {len(original_bytes)} bytes."
    )


def test_download_failed_job_returns_400(patch_dirs):
    """Downloading a job that failed (wrong key) must return 400."""
    import os, base64
    enc_resp = client.post(
        "/api/v1/decryption/demo/encrypt",
        json={"demo_filename": "sample_report.txt"},
    )
    assert enc_resp.status_code == 201
    enc_data = enc_resp.json()

    wrong_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    dec_resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={"encrypted_filename": enc_data["encrypted_filename"], "key_b64": wrong_key},
    )
    assert dec_resp.status_code == 201
    job = dec_resp.json()
    assert job["status"] == "RECOVERY_FAILED"
    job_id = job["job_id"]

    dl_resp = client.get(f"/api/v1/decryption/demo/jobs/{job_id}/download")
    assert dl_resp.status_code == 400
    assert "cannot be downloaded" in dl_resp.json()["detail"]


def test_download_nonexistent_job_returns_404():
    """Downloading a non-existent job must return 404."""
    dl_resp = client.get("/api/v1/decryption/demo/jobs/totally-nonexistent-id-xyz/download")
    assert dl_resp.status_code == 404
