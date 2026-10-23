"""
Tests for app.decryption.orchestrator

Covers:
  - list_demo_input_files returns files from real demo dir
  - encrypt_demo_file produces an encrypted file and returns key
  - encrypt_demo_file rejects path traversal in filename
  - encrypt_demo_file raises DemoFileNotFoundError for missing files
  - create_demo_decrypt_job succeeds with correct key → RECOVERY_SUCCEEDED
  - create_demo_decrypt_job fails with wrong key → RECOVERY_FAILED
  - create_demo_decrypt_job raises EncryptedFileNotFoundError for missing file
  - create_demo_decrypt_job raises PathTraversalError for traversal attempt
  - create_demo_decrypt_job raises InvalidKeyError for malformed key
  - get_job returns None for unknown ID
  - get_job returns a copy (not live reference)
  - list_jobs returns only DEMO jobs when filtered
  - Verified field is only True when recovery truly succeeded
  - Output file actually exists after RECOVERY_SUCCEEDED
  - Original demo file is preserved after round-trip
"""

import base64
import os
from pathlib import Path

import pytest

from app.decryption import orchestrator
from app.decryption.orchestrator import RecoveryStatus
from app.decryption.exceptions import (
    DemoFileNotFoundError,
    EncryptedFileNotFoundError,
    InvalidKeyError,
    PathTraversalError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def demo_dir(tmp_path) -> Path:
    """A temporary demo directory with one plaintext file."""
    d = tmp_path / "demo_files"
    d.mkdir()
    (d / "test_doc.txt").write_bytes(b"Hello from test_doc.txt content.")
    return d


@pytest.fixture
def encrypted_dir(tmp_path) -> Path:
    d = tmp_path / "encrypted"
    d.mkdir()
    return d


@pytest.fixture
def output_dir(tmp_path) -> Path:
    d = tmp_path / "recovery_output"
    d.mkdir()
    return d


@pytest.fixture
def encrypt_result(demo_dir, encrypted_dir):
    """Run encrypt once and return the result dict."""
    return orchestrator.encrypt_demo_file(
        demo_dir=demo_dir,
        filename="test_doc.txt",
        encrypted_dir=encrypted_dir,
    )


# ---------------------------------------------------------------------------
# list_demo_input_files
# ---------------------------------------------------------------------------


def test_list_demo_input_files_returns_files(demo_dir):
    files = orchestrator.list_demo_input_files(demo_dir)
    assert len(files) == 1
    assert files[0]["filename"] == "test_doc.txt"
    assert files[0]["size_bytes"] > 0


def test_list_demo_input_files_missing_dir(tmp_path):
    missing = tmp_path / "nonexistent"
    assert orchestrator.list_demo_input_files(missing) == []


def test_list_demo_input_files_excludes_gitkeep(demo_dir):
    (demo_dir / ".gitkeep").write_bytes(b"")
    files = orchestrator.list_demo_input_files(demo_dir)
    names = [f["filename"] for f in files]
    assert ".gitkeep" not in names


# ---------------------------------------------------------------------------
# encrypt_demo_file
# ---------------------------------------------------------------------------


def test_encrypt_returns_key_and_filename(demo_dir, encrypted_dir):
    result = orchestrator.encrypt_demo_file(demo_dir, "test_doc.txt", encrypted_dir)
    assert "key_b64" in result
    assert "encrypted_filename" in result
    assert result["encrypted_filename"].endswith(".csde")
    assert result["original_filename"] == "test_doc.txt"
    assert result["file_size_bytes"] > 0
    assert result["plaintext_sha256"]


def test_encrypt_writes_file(demo_dir, encrypted_dir):
    result = orchestrator.encrypt_demo_file(demo_dir, "test_doc.txt", encrypted_dir)
    output = encrypted_dir / result["encrypted_filename"]
    assert output.is_file()
    assert output.stat().st_size > 0


def test_encrypt_key_is_valid_base64(demo_dir, encrypted_dir):
    result = orchestrator.encrypt_demo_file(demo_dir, "test_doc.txt", encrypted_dir)
    key_bytes = base64.urlsafe_b64decode(result["key_b64"] + "==")
    assert len(key_bytes) == 32


def test_encrypt_preserves_original(demo_dir, encrypted_dir):
    original_content = (demo_dir / "test_doc.txt").read_bytes()
    orchestrator.encrypt_demo_file(demo_dir, "test_doc.txt", encrypted_dir)
    assert (demo_dir / "test_doc.txt").read_bytes() == original_content


def test_encrypt_missing_file_raises(demo_dir, encrypted_dir):
    with pytest.raises(DemoFileNotFoundError):
        orchestrator.encrypt_demo_file(demo_dir, "nonexistent.txt", encrypted_dir)


def test_encrypt_path_traversal_raises(demo_dir, encrypted_dir):
    with pytest.raises(PathTraversalError):
        orchestrator.encrypt_demo_file(demo_dir, "../../../etc/passwd", encrypted_dir)


def test_encrypt_path_traversal_backslash_raises(demo_dir, encrypted_dir):
    with pytest.raises(PathTraversalError):
        orchestrator.encrypt_demo_file(demo_dir, "..\\..\\secret.txt", encrypted_dir)


def test_encrypt_leading_dot_raises(demo_dir, encrypted_dir):
    with pytest.raises(PathTraversalError):
        orchestrator.encrypt_demo_file(demo_dir, ".hidden_file", encrypted_dir)


def test_encrypt_two_calls_produce_different_filenames(demo_dir, encrypted_dir):
    r1 = orchestrator.encrypt_demo_file(demo_dir, "test_doc.txt", encrypted_dir)
    r2 = orchestrator.encrypt_demo_file(demo_dir, "test_doc.txt", encrypted_dir)
    assert r1["encrypted_filename"] != r2["encrypted_filename"]


# ---------------------------------------------------------------------------
# create_demo_decrypt_job — success path
# ---------------------------------------------------------------------------


def test_decrypt_job_succeeds_with_correct_key(encrypted_dir, output_dir, encrypt_result):
    job = orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=encrypt_result["key_b64"],
        output_dir=output_dir,
    )
    assert job["status"] == RecoveryStatus.RECOVERY_SUCCEEDED
    assert job["verified"] is True
    assert job["output_path"] is not None
    assert Path(job["output_path"]).is_file()


def test_decrypt_job_verified_only_on_success(encrypted_dir, output_dir, encrypt_result):
    job = orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=encrypt_result["key_b64"],
        output_dir=output_dir,
    )
    # verified must not be True unless status is RECOVERY_SUCCEEDED
    if job["status"] != RecoveryStatus.RECOVERY_SUCCEEDED:
        assert job["verified"] is False


def test_decrypt_output_matches_original(demo_dir, encrypted_dir, output_dir, encrypt_result):
    original = (demo_dir / "test_doc.txt").read_bytes()
    job = orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=encrypt_result["key_b64"],
        output_dir=output_dir,
    )
    assert job["status"] == RecoveryStatus.RECOVERY_SUCCEEDED
    recovered = Path(job["output_path"]).read_bytes()
    assert recovered == original


def test_decrypt_job_has_sha256_fields(encrypted_dir, output_dir, encrypt_result):
    job = orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=encrypt_result["key_b64"],
        output_dir=output_dir,
    )
    assert job["plaintext_sha256"]
    assert job["output_sha256"]
    assert job["plaintext_sha256"] == job["output_sha256"]


# ---------------------------------------------------------------------------
# create_demo_decrypt_job — failure paths
# ---------------------------------------------------------------------------


def test_decrypt_job_wrong_key_fails(encrypted_dir, output_dir, encrypt_result):
    wrong_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    job = orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=wrong_key,
        output_dir=output_dir,
    )
    assert job["status"] == RecoveryStatus.RECOVERY_FAILED
    assert job["verified"] is False
    assert job["error_message"] is not None


def test_decrypt_job_missing_file_raises(encrypted_dir, output_dir):
    with pytest.raises(EncryptedFileNotFoundError):
        orchestrator.create_demo_decrypt_job(
            encrypted_dir=encrypted_dir,
            encrypted_filename="does_not_exist.csde",
            key_b64=base64.urlsafe_b64encode(os.urandom(32)).decode(),
            output_dir=output_dir,
        )


def test_decrypt_job_path_traversal_raises(encrypted_dir, output_dir):
    with pytest.raises(PathTraversalError):
        orchestrator.create_demo_decrypt_job(
            encrypted_dir=encrypted_dir,
            encrypted_filename="../../../etc/shadow.csde",
            key_b64=base64.urlsafe_b64encode(os.urandom(32)).decode(),
            output_dir=output_dir,
        )


def test_decrypt_job_invalid_key_base64_raises(encrypted_dir, output_dir, encrypt_result):
    with pytest.raises(InvalidKeyError):
        orchestrator.create_demo_decrypt_job(
            encrypted_dir=encrypted_dir,
            encrypted_filename=encrypt_result["encrypted_filename"],
            key_b64="NOT!!!VALID***BASE64!!!",
            output_dir=output_dir,
        )


def test_decrypt_job_wrong_key_length_raises(encrypted_dir, output_dir, encrypt_result):
    short_key = base64.urlsafe_b64encode(b"tooshort").decode()
    with pytest.raises(InvalidKeyError):
        orchestrator.create_demo_decrypt_job(
            encrypted_dir=encrypted_dir,
            encrypted_filename=encrypt_result["encrypted_filename"],
            key_b64=short_key,
            output_dir=output_dir,
        )


# ---------------------------------------------------------------------------
# Job store
# ---------------------------------------------------------------------------


def test_get_job_returns_none_for_unknown():
    assert orchestrator.get_job("totally-fake-uuid-9999") is None


def test_get_job_returns_copy(encrypted_dir, output_dir, encrypt_result):
    job = orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=encrypt_result["key_b64"],
        output_dir=output_dir,
    )
    retrieved = orchestrator.get_job(job["job_id"])
    assert retrieved is not None
    # Modifying the copy must not affect the store
    retrieved["status"] = "MUTATED"
    fresh = orchestrator.get_job(job["job_id"])
    assert fresh is not None
    assert fresh["status"] != "MUTATED"


def test_list_jobs_demo_filter(encrypted_dir, output_dir, encrypt_result):
    orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=encrypt_result["key_b64"],
        output_dir=output_dir,
    )
    demo_jobs = orchestrator.list_jobs(job_type="DEMO")
    assert all(j["job_type"] == "DEMO" for j in demo_jobs)
    real_jobs = orchestrator.list_jobs(job_type="REAL")
    assert all(j["job_type"] == "REAL" for j in real_jobs)


def test_job_record_contains_no_key_material(encrypted_dir, output_dir, encrypt_result):
    """Keys must never appear in job records."""
    job = orchestrator.create_demo_decrypt_job(
        encrypted_dir=encrypted_dir,
        encrypted_filename=encrypt_result["encrypted_filename"],
        key_b64=encrypt_result["key_b64"],
        output_dir=output_dir,
    )
    job_str = str(job)
    # The key is 32 random bytes; its b64 representation should not be in the job
    assert encrypt_result["key_b64"] not in job_str
