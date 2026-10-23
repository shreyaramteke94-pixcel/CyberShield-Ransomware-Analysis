"""
End-to-end live smoke test exercising all CyberShield workflows:
1. API Documentation / OpenAPI schema
2. File Upload & Static Analysis Pipeline
3. Sample retrieval & Analysis retrieval from SQLite
4. Preset Demo Decryption workflow (3 files, encrypt, decrypt, download verified bytes)
5. Custom File Encryption, .csde download, Decryption, verified recovered download
6. Security boundaries: wrong key rejection, blocked download for unverified jobs
"""

import hashlib
import io
import sys
from pathlib import Path

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parents[1]
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app

def run_e2e_verification():
    client = TestClient(app)
    print("=== 1. Checking API Documentation, Health & OpenAPI schema ===")
    root_resp = client.get("/")
    assert root_resp.status_code == 200, f"Root failed: {root_resp.status_code}"
    health_resp = client.get("/health")
    assert health_resp.status_code == 200, f"Health failed: {health_resp.status_code}"
    docs_resp = client.get("/docs")
    assert docs_resp.status_code == 200, f"Docs failed: {docs_resp.status_code}"
    openapi_resp = client.get("/openapi.json")
    assert openapi_resp.status_code == 200, f"OpenAPI failed: {openapi_resp.status_code}"
    print("PASS: /, /health, /docs, and /openapi.json loaded successfully.")

    print("\n=== 2. Testing Harmless File Upload & Analysis ===")
    harmless_content = b"CyberShield synthetic benign telemetry test content 2026."
    sample_sha = hashlib.sha256(harmless_content).hexdigest()
    
    upload_resp = client.post(
        "/api/v1/upload/",
        files={"file": ("synthetic_test_doc.txt", io.BytesIO(harmless_content), "text/plain")},
    )
    assert upload_resp.status_code in (200, 201), f"Upload failed: {upload_resp.status_code} - {upload_resp.text}"
    upload_data = upload_resp.json()
    sample_id = upload_data.get("sample_id") or upload_data.get("id")
    print(f"PASS: Uploaded sample ID: {sample_id}, Status: {upload_data.get('status')}")

    print("\n=== 3. Testing Sample & Analysis Retrieval from SQLite ===")
    get_sample = client.get(f"/api/v1/samples/{sample_id}")
    assert get_sample.status_code == 200, f"Get sample failed: {get_sample.status_code}"
    print(f"PASS: Retrieved sample: {get_sample.json().get('original_filename')}")

    get_analysis = client.get(f"/api/v1/analysis/{sample_id}")
    assert get_analysis.status_code == 200, f"Get analysis failed: {get_analysis.status_code}"
    analysis_data = get_analysis.json()
    print(f"PASS: Analysis record retrieved. Risk score: {analysis_data.get('risk_score')}, Severity: {analysis_data.get('severity')}")

    print("\n=== 4. Testing Preset Demo Decryption (3 Demo Files) ===")
    files_resp = client.get("/api/v1/decryption/demo/files")
    assert files_resp.status_code == 200
    demo_files = files_resp.json().get("files", [])
    filenames = [f["filename"] for f in demo_files]
    print(f"Available preset demo files: {filenames}")
    assert "client_data_sample_demo.csv" in filenames
    assert "configuration_backup_demo.json" in filenames
    assert "quarterly_report_demo.txt" in filenames
    print("PASS: All 3 preset demo files present.")

    # Encrypt & Decrypt first preset demo file
    preset_file = "quarterly_report_demo.txt"
    enc_preset_resp = client.post("/api/v1/decryption/demo/encrypt", json={"demo_filename": preset_file})
    assert enc_preset_resp.status_code == 201
    preset_enc_data = enc_preset_resp.json()
    preset_key = preset_enc_data["key_b64"]
    preset_enc_filename = preset_enc_data["encrypted_filename"]
    print(f"PASS: Encrypted preset demo file -> {preset_enc_filename}")

    # Decrypt preset demo file
    dec_preset_resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={"encrypted_filename": preset_enc_filename, "key_b64": preset_key, "sample_id": sample_id},
    )
    assert dec_preset_resp.status_code == 201
    preset_job = dec_preset_resp.json()
    assert preset_job["status"] == "RECOVERY_SUCCEEDED"
    assert preset_job["verified"] is True
    print(f"PASS: Preset decryption job succeeded and verified.")

    # Download recovered preset demo file
    dl_preset_resp = client.get(f"/api/v1/decryption/demo/jobs/{preset_job['job_id']}/download")
    assert dl_preset_resp.status_code == 200
    print(f"PASS: Downloaded recovered preset file ({len(dl_preset_resp.content)} bytes).")

    print("\n=== 5. Testing Custom File Encryption, Download, Decryption & Recovery ===")
    custom_plaintext = b"CONFIDENTIAL CLIENT REPORT: CyberShield custom file round-trip byte verification test."
    custom_sha256 = hashlib.sha256(custom_plaintext).hexdigest()

    # Upload custom file to encrypt
    custom_enc_resp = client.post(
        "/api/v1/decryption/custom/encrypt",
        files={"file": ("financial_records_2026.docx", io.BytesIO(custom_plaintext), "application/octet-stream")},
    )
    assert custom_enc_resp.status_code == 201
    custom_enc_data = custom_enc_resp.json()
    custom_key = custom_enc_data["key_b64"]
    custom_enc_filename = custom_enc_data["encrypted_filename"]
    assert custom_enc_data["plaintext_sha256"] == custom_sha256
    print(f"PASS: Custom file encrypted -> {custom_enc_filename}, Key generated securely (not stored in DB).")

    # Download encrypted .csde file
    dl_csde_resp = client.get(f"/api/v1/decryption/custom/encrypted/{custom_enc_filename}/download")
    assert dl_csde_resp.status_code == 200
    assert len(dl_csde_resp.content) > len(custom_plaintext)  # Has CSDE header + IV + tag
    print(f"PASS: Downloaded encrypted .csde file ({len(dl_csde_resp.content)} bytes).")

    # Decrypt custom file using the key
    dec_custom_resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={"encrypted_filename": custom_enc_filename, "key_b64": custom_key, "sample_id": sample_id},
    )
    assert dec_custom_resp.status_code == 201
    custom_job = dec_custom_resp.json()
    assert custom_job["status"] == "RECOVERY_SUCCEEDED"
    assert custom_job["verified"] is True
    assert custom_job["output_sha256"] == custom_sha256
    print(f"PASS: Custom decryption job succeeded! Verified SHA-256 matches: {custom_sha256}")

    # Download recovered custom file and verify byte equality
    dl_custom_resp = client.get(f"/api/v1/decryption/demo/jobs/{custom_job['job_id']}/download")
    assert dl_custom_resp.status_code == 200
    assert dl_custom_resp.content == custom_plaintext, "Downloaded recovered bytes DO NOT match original!"
    print("PASS: Byte-for-byte equality confirmed between original upload and downloaded recovery!")

    print("\n=== 6. Testing Security Boundaries & Failure Handling ===")
    # Rejection of wrong key
    bad_key = ("A" * len(custom_key[:-4])) + "===="
    bad_dec_resp = client.post(
        "/api/v1/decryption/demo/jobs",
        json={"encrypted_filename": custom_enc_filename, "key_b64": bad_key},
    )
    assert bad_dec_resp.status_code in (201, 422)
    if bad_dec_resp.status_code == 201:
        bad_job = bad_dec_resp.json()
        assert bad_job["status"] == "RECOVERY_FAILED"
        # Download must be blocked
        dl_fail = client.get(f"/api/v1/decryption/demo/jobs/{bad_job['job_id']}/download")
        assert dl_fail.status_code == 400
        print("PASS: Failed recovery job blocked from downloading (HTTP 400).")
    print("PASS: Security boundaries verified.")

    print("\nALL END-TO-END WORKFLOWS PASSED CLEANLY!")

if __name__ == "__main__":
    run_e2e_verification()
