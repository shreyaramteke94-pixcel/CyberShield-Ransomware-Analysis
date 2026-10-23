"""
Tests for the custom-file encrypt / upload / decrypt / download workflow.

Endpoints under test
--------------------
POST /api/v1/decryption/custom/encrypt
POST /api/v1/decryption/custom/upload-encrypted
GET  /api/v1/decryption/custom/encrypted/{filename}/download
POST /api/v1/decryption/demo/jobs  (used with custom encrypted file)
GET  /api/v1/decryption/demo/jobs/{job_id}/download

Round-trip invariant
--------------------
decrypt(encrypt(plaintext, key), key) == plaintext  (byte-for-byte)

Key-safety invariant
--------------------
The decryption API response must NOT contain the key.

Path-traversal invariant
------------------------
Filenames with path separators or leading dots must be rejected with HTTP 400.
"""
from __future__ import annotations

import base64
import io
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.decrypt import router, _demo_dir, _encrypted_dir, _output_dir

# -------------------------------------------------------------------------
# Build a test application using the real decryption router
# with temporary directory overrides (same pattern as test_api.py)
# -------------------------------------------------------------------------

_test_app = FastAPI()
_test_app.include_router(router)

_PLAINTEXT = b"Hello, CyberShield! Round-trip test \xf0\x9f\x94\x90"
_PLAINTEXT_BIG = b"A" * 1024  # 1 KB — non-trivial size


@pytest.fixture(scope="module")
def dirs(tmp_path_factory):
    """Isolated temporary directories shared across the module."""
    base = tmp_path_factory.mktemp("custom_decrypt")
    demo = base / "demo_files"
    demo.mkdir()
    # Provide a demo file for regression tests
    (demo / "sample_report.txt").write_bytes(b"CyberShield regression demo file.")
    encrypted = demo / "encrypted"
    encrypted.mkdir()
    recovery = base / "recovery_output"
    recovery.mkdir()
    return {"demo": demo, "encrypted": encrypted, "recovery": recovery}


@pytest.fixture(scope="module")
def client(dirs):
    """TestClient with directories patched to the temp dirs."""
    with patch("app.api.decrypt._demo_dir", return_value=dirs["demo"]), \
         patch("app.api.decrypt._encrypted_dir", return_value=dirs["encrypted"]), \
         patch("app.api.decrypt._output_dir", return_value=dirs["recovery"]):
        with TestClient(_test_app) as c:
            yield c


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _upload_file(client: TestClient, content: bytes, filename: str = "test.txt"):
    """POST /custom/encrypt — returns response."""
    return client.post(
        "/api/v1/decryption/custom/encrypt",
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
    )


def _decrypt_job(client: TestClient, encrypted_filename: str, key_b64: str):
    """POST /demo/jobs — returns response."""
    return client.post(
        "/api/v1/decryption/demo/jobs",
        json={"encrypted_filename": encrypted_filename, "key_b64": key_b64},
    )


def _download_recovered(client: TestClient, job_id: str):
    """GET /demo/jobs/{job_id}/download — returns response."""
    return client.get(f"/api/v1/decryption/demo/jobs/{job_id}/download")


def _download_encrypted(client: TestClient, filename: str):
    """GET /custom/encrypted/{filename}/download — returns response."""
    return client.get(f"/api/v1/decryption/custom/encrypted/{filename}/download")


def _wrong_key(key_b64: str) -> str:
    """Flip the first byte of the decoded key and re-encode. Length stays identical."""
    raw = base64.urlsafe_b64decode(key_b64 + "==")
    bad_raw = bytes([raw[0] ^ 0xFF]) + raw[1:]
    return base64.urlsafe_b64encode(bad_raw).decode().rstrip("=")


# -------------------------------------------------------------------------
# 1. Full round-trip: encrypt → decrypt → download bytes == original
# -------------------------------------------------------------------------

class TestRoundTrip:
    def test_encrypt_returns_201_with_key(self, client):
        resp = _upload_file(client, _PLAINTEXT, "hello.txt")
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert "key_b64" in data
        assert "encrypted_filename" in data
        assert data["key_b64"]  # non-empty

    def test_round_trip_bytes_match(self, client):
        """decrypt(encrypt(P)) == P byte-for-byte."""
        resp = _upload_file(client, _PLAINTEXT, "roundtrip.txt")
        assert resp.status_code == 201, resp.text
        enc_data = resp.json()

        dec_resp = _decrypt_job(client, enc_data["encrypted_filename"], enc_data["key_b64"])
        assert dec_resp.status_code == 201, dec_resp.text
        job = dec_resp.json()
        assert job["status"] == "RECOVERY_SUCCEEDED"
        assert job["verified"] is True

        dl = _download_recovered(client, job["job_id"])
        assert dl.status_code == 200, dl.text
        assert dl.content == _PLAINTEXT

    def test_round_trip_large_payload(self, client):
        resp = _upload_file(client, _PLAINTEXT_BIG, "big.bin")
        assert resp.status_code == 201, resp.text
        enc_data = resp.json()

        dec_resp = _decrypt_job(client, enc_data["encrypted_filename"], enc_data["key_b64"])
        assert dec_resp.status_code == 201, dec_resp.text
        job = dec_resp.json()
        assert job["status"] == "RECOVERY_SUCCEEDED"

        dl = _download_recovered(client, job["job_id"])
        assert dl.status_code == 200
        assert dl.content == _PLAINTEXT_BIG

    def test_sha256_matches_plaintext(self, client):
        import hashlib
        resp = _upload_file(client, _PLAINTEXT, "sha_check.txt")
        assert resp.status_code == 201, resp.text
        enc_data = resp.json()
        expected_sha = hashlib.sha256(_PLAINTEXT).hexdigest()
        assert enc_data["plaintext_sha256"] == expected_sha

    def test_download_filename_is_basename_only(self, client):
        """Content-Disposition header must not contain server filesystem paths."""
        resp = _upload_file(client, _PLAINTEXT, "myfile.txt")
        enc_data = resp.json()
        job = _decrypt_job(client, enc_data["encrypted_filename"], enc_data["key_b64"]).json()
        dl = _download_recovered(client, job["job_id"])
        assert dl.status_code == 200
        cd = dl.headers.get("content-disposition", "")
        # Must not contain a directory separator
        assert "/" not in cd or "filename" in cd.split("/")[-1]
        assert "\\" not in cd


# -------------------------------------------------------------------------
# 2. Wrong-key rejection
# -------------------------------------------------------------------------

class TestWrongKey:
    def test_wrong_key_returns_recovery_failed(self, client):
        resp = _upload_file(client, _PLAINTEXT, "wk.txt")
        assert resp.status_code == 201, resp.text
        enc_data = resp.json()
        bad_key = _wrong_key(enc_data["key_b64"])

        dec_resp = _decrypt_job(client, enc_data["encrypted_filename"], bad_key)
        assert dec_resp.status_code == 201, dec_resp.text
        job = dec_resp.json()
        assert job["status"] in ("RECOVERY_FAILED", "OUTPUT_VERIFICATION_FAILED")

    def test_wrong_key_download_blocked(self, client):
        """After wrong-key failure, download must be blocked (HTTP 400)."""
        resp = _upload_file(client, _PLAINTEXT, "wk2.txt")
        enc_data = resp.json()
        bad_key = _wrong_key(enc_data["key_b64"])

        job = _decrypt_job(client, enc_data["encrypted_filename"], bad_key).json()
        assert "job_id" in job, f"Expected job dict, got: {job}"
        dl = _download_recovered(client, job["job_id"])
        assert dl.status_code == 400


# -------------------------------------------------------------------------
# 3. Tampered ciphertext
# -------------------------------------------------------------------------

class TestTamperedCiphertext:
    def test_tampered_ciphertext_fails(self, client, dirs):
        from app.decryption import demo_crypto
        # Build a genuine blob, flip a byte in the ciphertext area.
        plaintext = b"tamper test data"
        key = demo_crypto.generate_key()
        blob = bytearray(demo_crypto.encrypt(plaintext, key))
        # Flip a byte in the authenticated payload (after 49-byte header).
        blob[50] ^= 0xFF
        tampered = bytes(blob)
        key_b64 = base64.urlsafe_b64encode(key).decode().rstrip("=")

        # Save tampered blob as a fake .csde via upload endpoint
        resp = client.post(
            "/api/v1/decryption/custom/upload-encrypted",
            files={"file": ("tampered.csde", io.BytesIO(tampered), "application/octet-stream")},
        )
        # May succeed at save (magic bytes intact), or be rejected if validation catches it
        if resp.status_code == 201:
            enc_filename = resp.json()["encrypted_filename"]
            dec_resp = _decrypt_job(client, enc_filename, key_b64)
            job = dec_resp.json()
            # Must not succeed — GCM tag will reject tampered ciphertext
            assert job["status"] in ("RECOVERY_FAILED", "OUTPUT_VERIFICATION_FAILED"), \
                f"Expected failure, got {job['status']}: {job}"
        else:
            # Rejected at upload validation — also acceptable
            assert resp.status_code in (422, 400), resp.text


# -------------------------------------------------------------------------
# 4. Upload-encrypted endpoint validation
# -------------------------------------------------------------------------

class TestUploadEncrypted:
    def test_non_csde_extension_rejected(self, client):
        resp = client.post(
            "/api/v1/decryption/custom/upload-encrypted",
            files={"file": ("evil.exe", io.BytesIO(b"data"), "application/octet-stream")},
        )
        assert resp.status_code == 422

    def test_wrong_magic_rejected(self, client):
        bad_blob = b"BAAD" + b"\x01" + b"\x00" * 60
        resp = client.post(
            "/api/v1/decryption/custom/upload-encrypted",
            files={"file": ("bad.csde", io.BytesIO(bad_blob), "application/octet-stream")},
        )
        assert resp.status_code == 422

    def test_valid_csde_accepted(self, client):
        from app.decryption import demo_crypto
        key = demo_crypto.generate_key()
        blob = demo_crypto.encrypt(b"valid payload", key)
        resp = client.post(
            "/api/v1/decryption/custom/upload-encrypted",
            files={"file": ("valid.csde", io.BytesIO(blob), "application/octet-stream")},
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert "encrypted_filename" in data

    def test_too_short_blob_rejected(self, client):
        resp = client.post(
            "/api/v1/decryption/custom/upload-encrypted",
            files={"file": ("tiny.csde", io.BytesIO(b"CS"), "application/octet-stream")},
        )
        assert resp.status_code == 422

    def test_wrong_version_rejected(self, client):
        from app.decryption.demo_crypto import MAGIC
        bad_blob = MAGIC + b"\x99" + b"\x00" * 60
        resp = client.post(
            "/api/v1/decryption/custom/upload-encrypted",
            files={"file": ("badver.csde", io.BytesIO(bad_blob), "application/octet-stream")},
        )
        assert resp.status_code == 422


# -------------------------------------------------------------------------
# 5. Download encrypted file
# -------------------------------------------------------------------------

class TestDownloadEncrypted:
    def test_download_encrypted_file_ok(self, client):
        resp = _upload_file(client, _PLAINTEXT, "dl_enc.txt")
        assert resp.status_code == 201
        enc_filename = resp.json()["encrypted_filename"]
        dl = _download_encrypted(client, enc_filename)
        assert dl.status_code == 200
        assert len(dl.content) > 0

    def test_download_encrypted_content_type(self, client):
        resp = _upload_file(client, _PLAINTEXT, "dl_ct.txt")
        enc_filename = resp.json()["encrypted_filename"]
        dl = _download_encrypted(client, enc_filename)
        assert dl.status_code == 200
        assert "octet-stream" in dl.headers.get("content-type", "")

    def test_download_encrypted_nonexistent_404(self, client):
        dl = _download_encrypted(client, "nonexistent_abc123.csde")
        assert dl.status_code == 404

    def test_download_encrypted_path_traversal_blocked(self, client):
        dl = client.get("/api/v1/decryption/custom/encrypted/../encrypted/anything.csde/download")
        assert dl.status_code in (400, 404, 422)

    def test_download_non_csde_blocked(self, client):
        dl = _download_encrypted(client, "file.exe")
        assert dl.status_code == 400


# -------------------------------------------------------------------------
# 6. Recovered file download guards
# -------------------------------------------------------------------------

class TestDownloadRecoveredGuards:
    def test_missing_job_returns_404(self, client):
        dl = _download_recovered(client, "00000000-0000-0000-0000-000000000000")
        assert dl.status_code == 404

    def test_failed_job_download_blocked(self, client):
        resp = _upload_file(client, _PLAINTEXT, "fail_dl.txt")
        enc_data = resp.json()
        bad_key = _wrong_key(enc_data["key_b64"])

        job = _decrypt_job(client, enc_data["encrypted_filename"], bad_key).json()
        assert "job_id" in job, f"Expected job dict, got: {job}"
        dl = _download_recovered(client, job["job_id"])
        assert dl.status_code == 400


# -------------------------------------------------------------------------
# 7. Empty file rejection
# -------------------------------------------------------------------------

class TestEmptyFile:
    def test_empty_file_upload_rejected(self, client):
        resp = _upload_file(client, b"", "empty.txt")
        assert resp.status_code == 422


# -------------------------------------------------------------------------
# 8. Key NOT in API response
# -------------------------------------------------------------------------

class TestKeySafety:
    def test_key_not_in_decrypt_job_response(self, client):
        """The decryption job API response must never include the key."""
        resp = _upload_file(client, b"key safety check", "ks.txt")
        assert resp.status_code == 201, resp.text
        enc_data = resp.json()
        key_b64 = enc_data["key_b64"]

        dec_resp = _decrypt_job(client, enc_data["encrypted_filename"], key_b64)
        assert dec_resp.status_code == 201, dec_resp.text
        # Key must not appear in the job status response body
        assert key_b64 not in dec_resp.text, \
            f"key_b64 found in job response: {dec_resp.text}"

    def test_key_not_in_job_list_response(self, client):
        """GET /demo/jobs must never return key material."""
        resp = _upload_file(client, b"list key check", "lkc.txt")
        enc_data = resp.json()
        key_b64 = enc_data["key_b64"]
        _decrypt_job(client, enc_data["encrypted_filename"], key_b64)

        list_resp = client.get("/api/v1/decryption/demo/jobs")
        assert list_resp.status_code == 200
        assert key_b64 not in list_resp.text, \
            f"key_b64 found in job list: {list_resp.text}"


# -------------------------------------------------------------------------
# 9. Regression: existing demo file workflow still works
# -------------------------------------------------------------------------

class TestDemoFileRegression:
    def test_demo_files_list(self, client):
        resp = client.get("/api/v1/decryption/demo/files")
        assert resp.status_code == 200
        data = resp.json()
        assert "files" in data
        assert len(data["files"]) >= 1

    def test_demo_encrypt_and_decrypt(self, client):
        files_resp = client.get("/api/v1/decryption/demo/files")
        demo_files = files_resp.json()["files"]
        if not demo_files:
            pytest.skip("No demo files available")

        first = demo_files[0]["filename"]
        enc_resp = client.post(
            "/api/v1/decryption/demo/encrypt",
            json={"demo_filename": first},
        )
        assert enc_resp.status_code == 201, enc_resp.text
        enc_data = enc_resp.json()

        dec_resp = _decrypt_job(client, enc_data["encrypted_filename"], enc_data["key_b64"])
        assert dec_resp.status_code == 201, dec_resp.text
        job = dec_resp.json()
        assert job["status"] == "RECOVERY_SUCCEEDED"
        assert job["verified"] is True

    def test_demo_registry_reachable(self, client):
        resp = client.get("/api/v1/decryption/registry")
        assert resp.status_code == 200

    def test_demo_encrypt_wrong_key_fails(self, client):
        files_resp = client.get("/api/v1/decryption/demo/files")
        demo_files = files_resp.json()["files"]
        if not demo_files:
            pytest.skip("No demo files available")
        enc_resp = client.post(
            "/api/v1/decryption/demo/encrypt",
            json={"demo_filename": demo_files[0]["filename"]},
        )
        enc_data = enc_resp.json()
        bad_key = _wrong_key(enc_data["key_b64"])
        job = _decrypt_job(client, enc_data["encrypted_filename"], bad_key).json()
        assert job["status"] in ("RECOVERY_FAILED", "OUTPUT_VERIFICATION_FAILED")
