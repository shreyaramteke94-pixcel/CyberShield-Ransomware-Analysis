"""
Tests for app.decryption.demo_crypto

Covers:
  - Successful encrypt → decrypt round-trip
  - Wrong key rejected (TamperedCiphertextError)
  - Modified ciphertext rejected (TamperedCiphertextError)
  - Modified header rejected (TamperedCiphertextError — AAD mismatch)
  - Truncated blob rejected (InvalidFormatError)
  - Wrong magic bytes rejected (InvalidFormatError)
  - Unsupported version rejected (UnsupportedVersionError)
  - Empty plaintext (edge case: 0-byte file)
  - Large plaintext (5 MB)
  - Key wrong length (InvalidKeyError)
  - verify_recovered_plaintext helper
  - extract_plaintext_sha256_hex helper
"""

import os
import struct

import pytest

from app.decryption import demo_crypto
from app.decryption.demo_crypto import (
    HEADER_SIZE,
    MAGIC,
    MIN_BLOB_SIZE,
    decrypt,
    encrypt,
    extract_plaintext_sha256_hex,
    generate_key,
    verify_recovered_plaintext,
)
from app.decryption.exceptions import (
    InvalidFormatError,
    InvalidKeyError,
    TamperedCiphertextError,
    UnsupportedVersionError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def key():
    return generate_key()


@pytest.fixture
def plaintext():
    return b"Hello, CyberShield demo world!"


@pytest.fixture
def blob(key, plaintext):
    return encrypt(plaintext, key)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_round_trip_basic(key, plaintext, blob):
    recovered = decrypt(blob, key)
    assert recovered == plaintext


def test_round_trip_empty_plaintext():
    key = generate_key()
    blob = encrypt(b"", key)
    assert decrypt(blob, key) == b""


def test_round_trip_large_plaintext():
    key = generate_key()
    large = os.urandom(5 * 1024 * 1024)  # 5 MB
    blob = encrypt(large, key)
    recovered = decrypt(blob, key)
    assert recovered == large


def test_round_trip_binary_data():
    key = generate_key()
    data = bytes(range(256)) * 100
    assert decrypt(encrypt(data, key), key) == data


# ---------------------------------------------------------------------------
# Wrong key
# ---------------------------------------------------------------------------


def test_wrong_key_raises(blob):
    wrong_key = generate_key()
    with pytest.raises(TamperedCiphertextError):
        decrypt(blob, wrong_key)


def test_all_zeros_key_rejected_as_wrong(blob):
    """A key of all zeros is valid in length but wrong cryptographically."""
    zero_key = b"\x00" * 32
    with pytest.raises(TamperedCiphertextError):
        decrypt(blob, zero_key)


# ---------------------------------------------------------------------------
# Tampered ciphertext
# ---------------------------------------------------------------------------


def test_flipped_ciphertext_bit_raises(key, blob):
    """Flip one bit in the ciphertext body (after header)."""
    tampered = bytearray(blob)
    tampered[HEADER_SIZE] ^= 0x01
    with pytest.raises(TamperedCiphertextError):
        decrypt(bytes(tampered), key)


def test_appended_byte_raises(key, blob):
    with pytest.raises(TamperedCiphertextError):
        decrypt(blob + b"\x00", key)


def test_truncated_body_raises(key, blob):
    """Remove last byte — the GCM tag is broken."""
    with pytest.raises((TamperedCiphertextError, InvalidFormatError)):
        decrypt(blob[:-1], key)


# ---------------------------------------------------------------------------
# Modified header (AAD tampered)
# ---------------------------------------------------------------------------


def test_modified_stored_hash_raises(key, blob):
    """Flip a byte in the stored SHA-256 field — AAD tampered → GCM fails."""
    tampered = bytearray(blob)
    tampered[HEADER_SIZE - 1] ^= 0xFF
    with pytest.raises(TamperedCiphertextError):
        decrypt(bytes(tampered), key)


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


def test_blob_too_short_raises(key):
    with pytest.raises(InvalidFormatError):
        decrypt(b"\x00" * (MIN_BLOB_SIZE - 1), key)


def test_empty_blob_raises(key):
    with pytest.raises(InvalidFormatError):
        decrypt(b"", key)


def test_wrong_magic_raises(key, blob):
    tampered = bytearray(blob)
    tampered[0:4] = b"XXXX"
    with pytest.raises(InvalidFormatError):
        decrypt(bytes(tampered), key)


def test_unsupported_version_raises(key, blob):
    tampered = bytearray(blob)
    tampered[4] = 0xFF  # version 255
    with pytest.raises(UnsupportedVersionError):
        decrypt(bytes(tampered), key)


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------


def test_short_key_raises_on_encrypt():
    with pytest.raises(InvalidKeyError):
        encrypt(b"test", b"tooshort")


def test_long_key_raises_on_encrypt():
    with pytest.raises(InvalidKeyError):
        encrypt(b"test", b"\x00" * 64)


def test_short_key_raises_on_decrypt(blob):
    with pytest.raises(InvalidKeyError):
        decrypt(blob, b"tooshort")


# ---------------------------------------------------------------------------
# generate_key
# ---------------------------------------------------------------------------


def test_generate_key_length():
    assert len(generate_key()) == 32


def test_generate_key_uniqueness():
    keys = {generate_key() for _ in range(20)}
    assert len(keys) == 20


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_verify_recovered_plaintext_correct(key, plaintext, blob):
    assert verify_recovered_plaintext(plaintext, blob) is True


def test_verify_recovered_plaintext_wrong_data(key, blob):
    assert verify_recovered_plaintext(b"wrong data", blob) is False


def test_verify_recovered_plaintext_short_blob():
    assert verify_recovered_plaintext(b"data", b"\x00" * 4) is False


def test_extract_sha256_hex(key, plaintext, blob):
    hex_hash = extract_plaintext_sha256_hex(blob)
    import hashlib
    assert hex_hash == hashlib.sha256(plaintext).hexdigest()


def test_extract_sha256_hex_short_blob():
    assert extract_plaintext_sha256_hex(b"\x00" * 4) is None


# ---------------------------------------------------------------------------
# Determinism and uniqueness
# ---------------------------------------------------------------------------


def test_two_encryptions_of_same_plaintext_differ():
    """Different nonces should produce different ciphertexts."""
    key = generate_key()
    plaintext = b"same data"
    blob1 = encrypt(plaintext, key)
    blob2 = encrypt(plaintext, key)
    # Nonces should differ; ciphertexts should differ
    assert blob1 != blob2
    # Both should decrypt to the same plaintext
    assert decrypt(blob1, key) == decrypt(blob2, key) == plaintext
