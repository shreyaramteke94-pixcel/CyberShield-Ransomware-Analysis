import os
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

os.environ.setdefault(
    "SECRET_KEY",
    "pytest-only-secret-key-not-for-production",
)
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite:///./pytest_test.db",
)

from app.services.recovery_service import RecoveryService


def test_missing_sample_returns_404(monkeypatch):
    monkeypatch.setattr(
        "app.services.recovery_service.SampleRepository.get_by_id",
        lambda **kwargs: None,
    )

    with pytest.raises(HTTPException) as exc:
        RecoveryService.check_recovery(
            db=Mock(),
            sample_id="missing-sample",
        )

    assert exc.value.status_code == 404


def test_missing_file_returns_404(monkeypatch, tmp_path):
    sample = Mock()
    sample.id = "sample-123"
    sample.original_filename = "encrypted.txt"
    sample.stored_filename = "sample-123.txt"

    monkeypatch.setattr(
        "app.services.recovery_service.SampleRepository.get_by_id",
        lambda **kwargs: sample,
    )
    monkeypatch.setattr(
        "app.services.recovery_service.settings.UPLOAD_DIR",
        str(tmp_path),
    )

    with pytest.raises(HTTPException) as exc:
        RecoveryService.check_recovery(
            db=Mock(),
            sample_id="sample-123",
        )

    assert exc.value.status_code == 404


def test_existing_file_reports_decryptor_unavailable(
    monkeypatch,
    tmp_path,
):
    sample = Mock()
    sample.id = "sample-123"
    sample.original_filename = "encrypted.txt"
    sample.stored_filename = "sample-123.txt"

    original = tmp_path / sample.stored_filename
    original.write_text("test fixture", encoding="utf-8")
    original_before = original.read_bytes()

    monkeypatch.setattr(
        "app.services.recovery_service.SampleRepository.get_by_id",
        lambda **kwargs: sample,
    )
    monkeypatch.setattr(
        "app.services.recovery_service.settings.UPLOAD_DIR",
        str(tmp_path),
    )

    result = RecoveryService.check_recovery(
        db=Mock(),
        sample_id="sample-123",
    )

    assert result["recovery_status"] == "DECRYPTOR_UNAVAILABLE"
    assert result["recovered"] is False
    assert original.read_bytes() == original_before

    
def test_path_traversal_is_rejected(monkeypatch, tmp_path):
    sample = Mock()
    sample.id = "sample-123"
    sample.original_filename = "encrypted.txt"
    sample.stored_filename = "..\\outside.txt"

    outside_file = tmp_path.parent / "outside.txt"
    outside_file.write_text("test fixture", encoding="utf-8")

    monkeypatch.setattr(
        "app.services.recovery_service.SampleRepository.get_by_id",
        lambda **kwargs: sample,
    )
    monkeypatch.setattr(
        "app.services.recovery_service.settings.UPLOAD_DIR",
        str(tmp_path),
    )

    with pytest.raises(HTTPException) as exc:
        RecoveryService.check_recovery(
            db=Mock(),
            sample_id="sample-123",
        )

    assert exc.value.status_code == 400
