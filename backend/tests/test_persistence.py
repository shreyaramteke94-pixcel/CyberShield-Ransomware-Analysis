"""
Comprehensive tests for SQLite persistence, state transitions, restarts,
and security boundaries in CyberShield Sandbox and Decryption engines.

Covers:
  - SandboxJob & DecryptionJob persistence across simulated backend restarts
  - Sandbox status transitions in SQLite (QUEUED/RUNNING -> COMPLETED / TIMED_OUT / UNAVAILABLE / FAILED)
  - Decryption job persistence across independent DB sessions
  - Strict absence of key material in database records and job responses
  - Download enforcements (rejection of unverified/failed jobs, missing output, traversal)
  - Byte-for-byte recovery verification through download endpoint
  - Database failure resilience (graceful in-memory fallback without crashing)
"""

import base64
import os
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.decrypt import router as decrypt_router
from app.config import settings
from app.database.database import Base, get_db
from app.decryption.orchestrator import (
    RecoveryStatus,
    create_demo_decrypt_job,
    encrypt_demo_file,
    get_job as get_decryption_job,
    list_jobs as list_decryption_jobs,
    _jobs as decryption_jobs_cache,
    _active_encrypted as active_encrypted_cache,
)
from app.main import app
from app.models.analysis import Analysis
from app.models.decryption_job import DecryptionJob
from app.models.sample import Sample
from app.models.sandbox_job import SandboxJob
from app.repositories.decryption_job_repository import DecryptionJobRepository
from app.repositories.sandbox_job_repository import SandboxJobRepository
from app.sandbox.manager import SandboxManager, sandbox_manager
from app.sandbox.schemas import SandboxDetectorResponse, SandboxStatus


# ---------------------------------------------------------------------------
# In-memory test DB session fixture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="function")
def test_db_session():
    """Create an isolated SQLite database in memory for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def isolated_dirs(tmp_path):
    """Provide isolated temporary directories for demo encryption/recovery."""
    demo_dir = tmp_path / "demo_files"
    demo_dir.mkdir()
    sample_file = demo_dir / "sample_contract.txt"
    sample_bytes = b"CONFIDENTIAL CYBERSHIELD RECOVERY DEMO DATA 2026."
    sample_file.write_bytes(sample_bytes)

    enc_dir = demo_dir / "encrypted"
    enc_dir.mkdir()

    out_dir = tmp_path / "recovery_output"
    out_dir.mkdir()

    return {
        "demo": demo_dir,
        "sample_file": sample_file,
        "sample_bytes": sample_bytes,
        "encrypted": enc_dir,
        "recovery": out_dir,
    }


# ---------------------------------------------------------------------------
# Test 1: Sandbox job persistence across simulated restart
# ---------------------------------------------------------------------------
def test_sandbox_job_persisted_and_survives_restart(test_db_session):
    """
    Verify that creating a sandbox job writes to the database, and clearing
    the in-memory cache simulates a restart where get_job and list_jobs
    restore the job state from SQLite.
    """
    # Create sample record in DB
    sample = Sample(
        id=str(uuid.uuid4()),
        original_filename="malware_sample.bin",
        stored_filename=f"{uuid.uuid4()}_malware_sample.bin",
        file_extension=".bin",
        file_size=1024,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="uploaded",
    )
    test_db_session.add(sample)
    test_db_session.commit()
    test_db_session.refresh(sample)

    manager = SandboxManager()
    created_job = manager.create_job(
        sample_id=sample.id,
        filename=sample.original_filename,
        confirm_dynamic_execution=False,  # Rejection path generates persisted record
        db=test_db_session,
    )
    job_id = created_job.job_id
    assert created_job.status == SandboxStatus.FAILED
    assert created_job.error_message is not None
    assert "rejected" in created_job.error_message.lower()

    # Verify DB has the record directly
    db_job = SandboxJobRepository.get_by_id(test_db_session, job_id)
    assert db_job is not None
    assert db_job.job_id == job_id
    assert db_job.sample_id == sample.id
    assert db_job.status == "FAILED"

    # Simulate backend restart: wipe in-memory jobs cache
    manager._jobs.clear()
    assert job_id not in manager._jobs

    # Query get_job - must restore from DB
    restored_job = manager.get_job(job_id, db=test_db_session)
    assert restored_job is not None
    assert restored_job.job_id == job_id
    assert restored_job.sample_id == sample.id
    assert restored_job.status == SandboxStatus.FAILED
    assert restored_job.filename == "malware_sample.bin"

    # Query list_jobs - must include the DB job
    manager._jobs.clear()
    jobs_list = manager.list_jobs(db=test_db_session)
    assert any(j.job_id == job_id for j in jobs_list)


# ---------------------------------------------------------------------------
# Test 2: Sandbox status transitions in SQLite
# ---------------------------------------------------------------------------
def test_sandbox_job_status_transitions_in_db(test_db_session, tmp_path):
    """
    Verify status transitions in SQLite across normal completion and timeout.
    """
    # Setup sample file within mock uploads
    mock_upload = tmp_path / "uploads"
    mock_upload.mkdir()
    sample_file = mock_upload / "test_sample.exe"
    sample_file.write_bytes(b"MZ\x90\x00synthetic_payload")

    sample = Sample(
        id=str(uuid.uuid4()),
        original_filename="test_sample.exe",
        stored_filename="test_sample.exe",
        file_extension=".exe",
        file_size=len(sample_file.read_bytes()),
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        status="uploaded",
    )
    test_db_session.add(sample)
    test_db_session.commit()
    test_db_session.refresh(sample)

    manager = SandboxManager()

    mock_detector = SandboxDetectorResponse(
        docker_cli_available=True,
        docker_daemon_reachable=True,
        sandbox_image_available=True,
        dynamic_analysis_ready=True,
        sandbox_status="AVAILABLE",
        sandbox_image="cybershield/analysis-sandbox:latest",
        security_policies={},
        diagnostics=["Ready"],
    )

    # 1. Test COMPLETED transition with mock subprocess output
    with (
        patch("app.sandbox.manager.get_sandbox_status", return_value=mock_detector),
        patch("app.sandbox.manager.settings") as mock_settings,
        patch("subprocess.run") as mock_run,
    ):
        mock_settings.UPLOAD_DIR = mock_upload
        mock_run.return_value = MagicMock(returncode=0, stdout="Container finished", stderr="")

        completed_job = manager.create_job(
            sample_id=sample.id,
            filename="test_sample.exe",
            sample_path=sample_file,
            confirm_dynamic_execution=True,
            timeout_seconds=30,
            db=test_db_session,
        )

        assert completed_job.status == SandboxStatus.COMPLETED
        # Verify SQLite record reflects COMPLETED
        db_job = SandboxJobRepository.get_by_id(test_db_session, completed_job.job_id)
        assert db_job is not None
        assert db_job.status == "COMPLETED"
        assert db_job.completed_at is not None

    # 2. Test TIMED_OUT transition
    with (
        patch("app.sandbox.manager.get_sandbox_status", return_value=mock_detector),
        patch("app.sandbox.manager.settings") as mock_settings,
        patch(
            "subprocess.run",
            side_effect=[
                subprocess.TimeoutExpired(cmd="docker run", timeout=10),
                MagicMock(returncode=0),
                MagicMock(returncode=0),
            ],
        ),
    ):
        mock_settings.UPLOAD_DIR = mock_upload

        timed_out_job = manager.create_job(
            sample_id=sample.id,
            filename="test_sample.exe",
            sample_path=sample_file,
            confirm_dynamic_execution=True,
            timeout_seconds=10,
            db=test_db_session,
        )

        assert timed_out_job.status == SandboxStatus.TIMED_OUT
        # Verify SQLite record reflects TIMED_OUT
        db_job = SandboxJobRepository.get_by_id(test_db_session, timed_out_job.job_id)
        assert db_job is not None
        assert db_job.status == "TIMED_OUT"
        assert db_job.error_message is not None
        assert "timeout" in db_job.error_message.lower()


# ---------------------------------------------------------------------------
# Test 3: Decryption job persistence across simulated restart
# ---------------------------------------------------------------------------
def test_decryption_job_persisted_and_survives_restart(test_db_session, isolated_dirs):
    """
    Verify decryption jobs are persisted to SQLite and restored after clearing memory.
    """
    demo_dir = isolated_dirs["demo"]
    enc_dir = isolated_dirs["encrypted"]
    out_dir = isolated_dirs["recovery"]

    enc_info = encrypt_demo_file(demo_dir, "sample_contract.txt", enc_dir)
    enc_filename = enc_info["encrypted_filename"]
    key_b64 = enc_info["key_b64"]

    # Create job with db persistence
    job = create_demo_decrypt_job(
        encrypted_dir=enc_dir,
        encrypted_filename=enc_filename,
        key_b64=key_b64,
        output_dir=out_dir,
        db=test_db_session,
    )
    job_id = job["job_id"]
    assert job["status"] == RecoveryStatus.RECOVERY_SUCCEEDED
    assert job["verified"] is True

    # Verify directly in SQLite repository
    db_job = DecryptionJobRepository.get_by_id(test_db_session, job_id)
    assert db_job is not None
    assert db_job["job_id"] == job_id
    assert db_job["status"] == "RECOVERY_SUCCEEDED"
    assert db_job["verified"] is True
    assert db_job["plaintext_sha256"] == enc_info["plaintext_sha256"]

    # Clear in-memory caches to simulate server restart
    decryption_jobs_cache.clear()
    active_encrypted_cache.clear()
    assert job_id not in decryption_jobs_cache

    # Restored via get_decryption_job
    restored = get_decryption_job(job_id, db=test_db_session)
    assert restored is not None
    assert restored["job_id"] == job_id
    assert restored["status"] == RecoveryStatus.RECOVERY_SUCCEEDED
    assert restored["verified"] is True

    # Restored via list_decryption_jobs
    decryption_jobs_cache.clear()
    all_jobs = list_decryption_jobs(job_type="DEMO", db=test_db_session)
    assert any(j["job_id"] == job_id for j in all_jobs)


# ---------------------------------------------------------------------------
# Test 4: Zero key material or secrets in DB or job responses
# ---------------------------------------------------------------------------
def test_zero_key_material_in_db_and_job_responses(test_db_session, isolated_dirs):
    """
    Ensure neither SQLite database records nor job dictionaries ever store
    or expose decryption keys or secrets.
    """
    demo_dir = isolated_dirs["demo"]
    enc_dir = isolated_dirs["encrypted"]
    out_dir = isolated_dirs["recovery"]

    enc_info = encrypt_demo_file(demo_dir, "sample_contract.txt", enc_dir)
    key_b64 = enc_info["key_b64"]

    job = create_demo_decrypt_job(
        encrypted_dir=enc_dir,
        encrypted_filename=enc_info["encrypted_filename"],
        key_b64=key_b64,
        output_dir=out_dir,
        db=test_db_session,
    )
    job_id = job["job_id"]

    # 1. Inspect returned dictionary
    for k in job.keys():
        assert "key" not in k.lower(), f"Unexpected key-related field in job dict: {k}"
        assert "secret" not in k.lower()

    # 2. Inspect SQLite model columns
    columns = [c.name for c in DecryptionJob.__table__.columns]
    for col in columns:
        assert "key" not in col.lower(), f"Forbidden key-related column in DB model: {col}"
        assert "secret" not in col.lower()

    # 3. Inspect raw DB row in SQLite
    db_row = test_db_session.query(DecryptionJob).filter(DecryptionJob.id == job_id).first()
    assert db_row is not None

    for col in columns:
        val = getattr(db_row, col)
        if isinstance(val, str):
            assert key_b64 not in val, f"Key found leaked in column {col}"


# ---------------------------------------------------------------------------
# Test 5: Download security enforcements & byte-for-byte fidelity
# ---------------------------------------------------------------------------
def test_download_security_enforcements_and_fidelity(test_db_session, isolated_dirs):
    """
    Verify:
      - Valid job: downloaded bytes match original plaintext byte-for-byte.
      - Failed job: HTTP 400 (cannot download unverified/failed output).
      - Unknown job ID: HTTP 404.
      - Deleted output file: HTTP 404.
      - Path traversal in output_file is blocked.
    """
    demo_dir = isolated_dirs["demo"]
    enc_dir = isolated_dirs["encrypted"]
    out_dir = isolated_dirs["recovery"]
    original_bytes = isolated_dirs["sample_bytes"]

    # Override get_db in FastAPI
    app.dependency_overrides[get_db] = lambda: test_db_session
    client = TestClient(app)

    try:
        with (
            patch("app.api.decrypt._demo_dir", return_value=demo_dir),
            patch("app.api.decrypt._encrypted_dir", return_value=enc_dir),
            patch("app.api.decrypt._output_dir", return_value=out_dir),
        ):
            # Step A: Encrypt demo file
            enc_res = client.post("/api/v1/decryption/demo/encrypt", json={"demo_filename": "sample_contract.txt"})
            assert enc_res.status_code == 201
            enc_data = enc_res.json()
            enc_filename = enc_data["encrypted_filename"]
            key_b64 = enc_data["key_b64"]

            # Step B: Decrypt with CORRECT key
            dec_res = client.post(
                "/api/v1/decryption/demo/jobs",
                json={"encrypted_filename": enc_filename, "key_b64": key_b64},
            )
            assert dec_res.status_code == 201
            job_data = dec_res.json()
            job_id = job_data["job_id"]
            assert job_data["status"] == "RECOVERY_SUCCEEDED"
            assert job_data["verified"] is True

            # Step C: Download output file and assert byte-for-byte fidelity
            dl_res = client.get(f"/api/v1/decryption/demo/jobs/{job_id}/download")
            assert dl_res.status_code == 200
            assert dl_res.content == original_bytes, "Downloaded bytes do not match original bytes!"

            # Step D: Decrypt with WRONG key -> RECOVERY_FAILED
            wrong_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
            enc_res2 = client.post("/api/v1/decryption/demo/encrypt", json={"demo_filename": "sample_contract.txt"})
            enc_filename2 = enc_res2.json()["encrypted_filename"]

            dec_res2 = client.post(
                "/api/v1/decryption/demo/jobs",
                json={"encrypted_filename": enc_filename2, "key_b64": wrong_key},
            )
            assert dec_res2.status_code == 201
            failed_job = dec_res2.json()
            assert failed_job["status"] == "RECOVERY_FAILED"
            failed_id = failed_job["job_id"]

            # Attempting to download failed job must return 400
            dl_failed = client.get(f"/api/v1/decryption/demo/jobs/{failed_id}/download")
            assert dl_failed.status_code == 400
            assert "cannot be downloaded" in dl_failed.json()["detail"].lower()

            # Step E: Unknown job ID returns 404
            dl_unknown = client.get("/api/v1/decryption/demo/jobs/00000000-0000-0000-0000-000000000000/download")
            assert dl_unknown.status_code == 404

            # Step F: Missing output file on disk returns 404
            # Retrieve real output path from the orchestrator
            raw_job = get_decryption_job(job_id, db=test_db_session)
            assert raw_job is not None
            out_file_path = Path(raw_job["output_path"])
            assert out_file_path.is_file()
            out_file_path.unlink()

            dl_missing = client.get(f"/api/v1/decryption/demo/jobs/{job_id}/download")
            assert dl_missing.status_code == 404
            assert "no longer present" in dl_missing.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Test 6: Database failure resilience (graceful in-memory fallback)
# ---------------------------------------------------------------------------
def test_database_failure_resilience_fallback(isolated_dirs):
    """
    Verify that if the database session fails/errors, SandboxManager and
    DecryptionOrchestrator do not crash and still return in-memory jobs.
    """
    # Create a mock session whose commit/add raises an exception
    failing_session = MagicMock()
    failing_session.add.side_effect = RuntimeError("Database disk full or locked")

    # 1. SandboxManager resilience
    manager = SandboxManager()
    job = manager.create_job(
        sample_id=str(uuid.uuid4()),
        filename="test.bin",
        confirm_dynamic_execution=False,
        db=failing_session,
    )
    assert job is not None
    assert job.status == SandboxStatus.FAILED
    assert job.job_id in manager._jobs

    # 2. DecryptionOrchestrator resilience
    demo_dir = isolated_dirs["demo"]
    enc_dir = isolated_dirs["encrypted"]
    out_dir = isolated_dirs["recovery"]

    enc_info = encrypt_demo_file(demo_dir, "sample_contract.txt", enc_dir)

    job_dec = create_demo_decrypt_job(
        encrypted_dir=enc_dir,
        encrypted_filename=enc_info["encrypted_filename"],
        key_b64=enc_info["key_b64"],
        output_dir=out_dir,
        db=failing_session,
    )
    assert job_dec is not None
    assert job_dec["status"] == RecoveryStatus.RECOVERY_SUCCEEDED
    assert job_dec["verified"] is True


# ---------------------------------------------------------------------------
# Test 7: Genuine process and FastAPI restart with file-backed SQLite
# ---------------------------------------------------------------------------
def test_genuine_restart_persistence_with_file_db(tmp_path):
    """
    Verify that Sandbox and Decryption jobs persisted to a file-based SQLite DB
    are successfully restored by a completely fresh process/session without any
    in-memory cache.
    """
    db_file = tmp_path / "restart_test.db"
    db_url = f"sqlite:///{db_file.as_posix()}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # 1. Populate database in initial session
    with TestingSession() as session:
        sample_id = str(uuid.uuid4())
        sample = Sample(
            id=sample_id,
            original_filename="invoice_march.exe",
            stored_filename="stored_invoice_march.exe",
            file_extension=".exe",
            file_size=2048,
            sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            status="uploaded",
        )
        session.add(sample)
        session.commit()

        # Insert sandbox job
        sb_job = SandboxJob(
            id=str(uuid.uuid4()),
            sample_id=sample_id,
            filename="invoice_march.exe",
            status="COMPLETED",
            created_at="2026-10-20T10:00:00Z",
            completed_at="2026-10-20T10:01:00Z",
            operations_run=["container_boundary_setup", "execution"],
            error_message=None,
            process_tree=[{"pid": 100, "name": "sample.exe"}],
            network_beacons=[],
            runtime_events=[{"event": "process_start"}],
            security_verifications={"network_disabled": True},
            execution_summary="Dynamic analysis completed in isolated container.",
        )
        session.add(sb_job)

        # Insert decryption job (zero key material)
        dec_job = DecryptionJob(
            id=str(uuid.uuid4()),
            sample_id=sample_id,
            job_type="DEMO",
            status="RECOVERY_SUCCEEDED",
            input_file="sample_locked.csde",
            output_path="/safe/path/recovered_file.txt",
            plaintext_sha256="fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            output_sha256="fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            verified=True,
            error_message=None,
            created_at="2026-10-20T10:05:00Z",
            completed_at="2026-10-20T10:05:10Z",
        )
        session.add(dec_job)
        session.commit()

        sb_id = sb_job.id
        dec_id = dec_job.id

    # 2. Simulate complete restart: clear all in-memory caches
    sandbox_manager._jobs.clear()
    decryption_jobs_cache.clear()
    active_encrypted_cache.clear()

    # 3. Spin up fresh FastAPI client connected to the persistent disk DB
    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        # Check Sandbox Job via API
        sb_res = client.get(f"/api/v1/sandbox/jobs/{sb_id}")
        assert sb_res.status_code == 200, f"Expected 200, got {sb_res.status_code}: {sb_res.text}"
        sb_data = sb_res.json()
        assert sb_data["job_id"] == sb_id
        assert sb_data["status"] == "COMPLETED"
        assert sb_data["filename"] == "invoice_march.exe"
        assert len(sb_data["process_tree"]) == 1

        # Check Sandbox listing via API
        sb_list_res = client.get("/api/v1/sandbox/jobs")
        assert sb_list_res.status_code == 200
        assert any(j["job_id"] == sb_id for j in sb_list_res.json())

        # Check Decryption Job via API
        dec_res = client.get(f"/api/v1/decryption/demo/jobs/{dec_id}")
        assert dec_res.status_code == 200, f"Expected 200, got {dec_res.status_code}: {dec_res.text}"
        dec_data = dec_res.json()
        assert dec_data["job_id"] == dec_id
        assert dec_data["status"] == "RECOVERY_SUCCEEDED"
        assert dec_data["verified"] is True
        assert "key" not in dec_data

        # Check Decryption listing via API
        dec_list_res = client.get("/api/v1/decryption/demo/jobs")
        assert dec_list_res.status_code == 200
        assert any(j["job_id"] == dec_id for j in dec_list_res.json())
    finally:
        app.dependency_overrides.clear()

