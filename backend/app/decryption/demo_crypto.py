"""
CyberShield Demo Crypto Engine
================================

Provides genuine AES-256-GCM encryption and decryption for the controlled
demonstration workflow.  This module:

  - Uses only the `cryptography` library (already in requirements.txt).
  - Does NOT implement any custom cryptographic algorithm.
  - Does NOT decrypt arbitrary third-party ransomware.
  - Is ONLY applied to files that are explicitly selected for the demo.

CyberShield Demo Encrypted Format (version 1)
----------------------------------------------

  Offset  Size  Field
  ------  ----  -----
       0     4  Magic = b'CSDE'  (0x43 0x53 0x44 0x45)
       4     1  Version = 0x01
       5    12  GCM nonce  (random, unique per encryption)
      17    32  SHA-256 of original plaintext  (authenticated, not encrypted)
      49     *  AES-256-GCM ciphertext + 16-byte GCM authentication tag

The entire 49-byte header is passed as Additional Authenticated Data (AAD) to
AESGCM.  Any modification to the header OR the ciphertext causes authentication
to fail before any plaintext is released.

Security properties
-------------------
  - Wrong key          → TamperedCiphertextError (GCM tag mismatch)
  - Modified ciphertext → TamperedCiphertextError (GCM tag mismatch)
  - Modified header    → TamperedCiphertextError (AAD mismatch invalidates tag)
  - Truncated blob     → InvalidFormatError (before any decryption attempt)
  - Wrong magic        → InvalidFormatError
  - Unknown version    → UnsupportedVersionError
"""

import hashlib
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.decryption.exceptions import (
    InvalidFormatError,
    InvalidKeyError,
    IntegrityError,
    TamperedCiphertextError,
    UnsupportedVersionError,
)

# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

MAGIC: bytes = b"CSDE"
CURRENT_VERSION: int = 0x01
KEY_SIZE: int = 32          # 256-bit AES key
NONCE_SIZE: int = 12        # NIST-recommended GCM nonce length
SHA256_SIZE: int = 32       # SHA-256 digest length
GCM_TAG_SIZE: int = 16      # AES-GCM authentication tag

#   Header layout:
#     [0:4]   MAGIC       (4 bytes)
#     [4:5]   VERSION     (1 byte)
#     [5:17]  nonce       (12 bytes)
#     [17:49] sha256      (32 bytes)
HEADER_SIZE: int = len(MAGIC) + 1 + NONCE_SIZE + SHA256_SIZE  # 49

# Minimum valid blob: header + GCM tag (0-byte plaintext edge case)
MIN_BLOB_SIZE: int = HEADER_SIZE + GCM_TAG_SIZE  # 65


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit (32-byte) AES key.

    Uses os.urandom which is backed by the OS CSPRNG (CryptGenRandom on
    Windows, getrandom(2) on Linux).
    """
    return os.urandom(KEY_SIZE)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM and return the complete
    CyberShield Demo Encrypted blob.

    Parameters
    ----------
    plaintext : bytes
        The data to encrypt.  May be empty (zero-length plaintext is valid).
    key : bytes
        A 32-byte (256-bit) AES key.  Use generate_key() to create one.

    Returns
    -------
    bytes
        The encrypted blob in CyberShield Demo Encrypted format.

    Raises
    ------
    InvalidKeyError
        If *key* is not exactly 32 bytes.
    """
    if len(key) != KEY_SIZE:
        raise InvalidKeyError(
            f"Key must be exactly {KEY_SIZE} bytes; got {len(key)} bytes."
        )

    nonce = os.urandom(NONCE_SIZE)
    plaintext_hash = _sha256_digest(plaintext)

    # Build the header — this becomes the AAD.
    header = MAGIC + struct.pack("B", CURRENT_VERSION) + nonce + plaintext_hash

    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + 16-byte tag concatenated.
    body = aesgcm.encrypt(nonce, plaintext, header)

    return header + body


def decrypt(blob: bytes, key: bytes) -> bytes:
    """
    Authenticate and decrypt a CyberShield Demo Encrypted blob.

    Authentication is performed by AESGCM before any plaintext is
    released.  If authentication succeeds, an independent SHA-256
    integrity check is performed on the recovered plaintext against
    the hash stored in the header.

    Parameters
    ----------
    blob : bytes
        The full encrypted blob produced by encrypt().
    key : bytes
        The 32-byte AES key used during encryption.

    Returns
    -------
    bytes
        The recovered plaintext.

    Raises
    ------
    InvalidKeyError
        If *key* is not exactly 32 bytes.
    InvalidFormatError
        If the blob is too short or has wrong magic bytes.
    UnsupportedVersionError
        If the blob's version byte is not supported.
    TamperedCiphertextError
        If GCM authentication fails (wrong key or tampered data).
    IntegrityError
        If authentication passes but the post-decryption hash check fails.
        This should not occur under normal conditions.
    """
    if len(key) != KEY_SIZE:
        raise InvalidKeyError(
            f"Key must be exactly {KEY_SIZE} bytes; got {len(key)} bytes."
        )

    # --- Structural validation (before any crypto) ---

    if len(blob) < MIN_BLOB_SIZE:
        raise InvalidFormatError(
            f"Blob is too short ({len(blob)} bytes). "
            f"Minimum valid CyberShield Demo Encrypted size is "
            f"{MIN_BLOB_SIZE} bytes."
        )

    magic = blob[0:4]
    if magic != MAGIC:
        raise InvalidFormatError(
            f"Invalid magic bytes {magic!r}. "
            f"Expected {MAGIC!r} (CyberShield Demo Encrypted file)."
        )

    version = struct.unpack("B", blob[4:5])[0]
    if version != CURRENT_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported format version {version}. "
            f"This engine supports version {CURRENT_VERSION} only."
        )

    # --- Extract header fields ---

    header = blob[:HEADER_SIZE]
    nonce = blob[5 : 5 + NONCE_SIZE]
    stored_hash = blob[5 + NONCE_SIZE : HEADER_SIZE]  # 32 bytes
    body = blob[HEADER_SIZE:]                          # ciphertext + GCM tag

    # --- AES-GCM authenticated decryption ---

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, body, header)
    except Exception as exc:
        # The cryptography library raises InvalidTag on authentication failure.
        raise TamperedCiphertextError(
            "AES-GCM authentication failed. "
            "The decryption key is incorrect, or the encrypted file has been "
            "tampered with since it was created. "
            "No plaintext was released."
        ) from exc

    # --- Independent post-decryption integrity check ---

    if not _constant_time_compare(_sha256_digest(plaintext), stored_hash):
        # This indicates an internal error — the GCM tag passed but the
        # stored hash doesn't match the recovered plaintext.
        raise IntegrityError(
            "Post-decryption integrity check failed: the SHA-256 of the "
            "recovered plaintext does not match the value stored in the "
            "encrypted file header. This should not occur under normal "
            "conditions and may indicate an internal format error."
        )

    return plaintext


def verify_recovered_plaintext(plaintext: bytes, blob: bytes) -> bool:
    """
    Return True if the SHA-256 of *plaintext* matches the hash
    embedded in the blob's header.

    This is a standalone check that can be called after writing the
    recovered bytes to disk, using the file's content read back
    from disk rather than the in-memory bytes, to confirm successful
    file write.

    Returns False (rather than raising) so callers can record a
    verification failure in a job record without raising an exception.
    """
    if len(blob) < HEADER_SIZE:
        return False
    stored_hash = blob[5 + NONCE_SIZE : HEADER_SIZE]
    return _constant_time_compare(_sha256_digest(plaintext), stored_hash)


def extract_plaintext_sha256_hex(blob: bytes) -> str | None:
    """
    Extract the hex-encoded expected plaintext SHA-256 from a blob's
    header without decrypting.

    Returns None if the blob is too short to contain the hash field.
    Used by the orchestrator to populate job metadata before decryption runs.
    """
    if len(blob) < HEADER_SIZE:
        return None
    stored_hash = blob[5 + NONCE_SIZE : HEADER_SIZE]
    return stored_hash.hex()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time to resist timing attacks.
    Returns True if they are equal.
    """
    import hmac
    return hmac.compare_digest(a, b)
