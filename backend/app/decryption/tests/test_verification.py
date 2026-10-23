"""
Tests for app.decryption.verification

Covers:
  - verify_demo_output returns True when hash matches
  - verify_demo_output returns False when hash doesn't match
  - verify_demo_output returns False when file is missing
  - verify_demo_output returns False for empty expected hash
  - compute_file_sha256 returns correct hex hash
  - compute_file_sha256 returns None for missing file
"""

import hashlib
from pathlib import Path

import pytest

from app.decryption.verification import compute_file_sha256, verify_demo_output


@pytest.fixture
def tmp_file(tmp_path) -> tuple[Path, bytes]:
    content = b"CyberShield demo verification test content."
    f = tmp_path / "test_output.txt"
    f.write_bytes(content)
    return f, content


def test_verify_correct_hash(tmp_file):
    path, content = tmp_file
    expected_hex = hashlib.sha256(content).hexdigest()
    assert verify_demo_output(path, expected_hex) is True


def test_verify_wrong_hash(tmp_file):
    path, _ = tmp_file
    assert verify_demo_output(path, "a" * 64) is False


def test_verify_missing_file(tmp_path):
    missing = tmp_path / "nonexistent.txt"
    assert verify_demo_output(missing, "a" * 64) is False


def test_verify_empty_expected_hash(tmp_file):
    path, _ = tmp_file
    assert verify_demo_output(path, "") is False


def test_verify_case_insensitive(tmp_file):
    path, content = tmp_file
    expected_hex = hashlib.sha256(content).hexdigest().upper()
    assert verify_demo_output(path, expected_hex) is True


def test_compute_sha256_correct(tmp_file):
    path, content = tmp_file
    expected = hashlib.sha256(content).hexdigest()
    assert compute_file_sha256(path) == expected


def test_compute_sha256_missing_file(tmp_path):
    missing = tmp_path / "nope.bin"
    assert compute_file_sha256(missing) is None


def test_compute_sha256_empty_file(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert compute_file_sha256(f) == expected


def test_verify_large_file(tmp_path):
    content = b"X" * (2 * 1024 * 1024)  # 2 MB
    f = tmp_path / "large.bin"
    f.write_bytes(content)
    expected_hex = hashlib.sha256(content).hexdigest()
    assert verify_demo_output(f, expected_hex) is True
