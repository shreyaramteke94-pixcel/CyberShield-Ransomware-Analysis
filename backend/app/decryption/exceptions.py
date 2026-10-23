"""
Typed exceptions for the CyberShield Decryption & Recovery Engine.

All exceptions inherit from DecryptionEngineError so callers can catch
the entire module's failures with a single base class while still
distinguishing specific failure modes.
"""


class DecryptionEngineError(Exception):
    """Base exception for all decryption engine errors."""


# ---------------------------------------------------------------
# Cryptographic failures
# ---------------------------------------------------------------


class InvalidKeyError(DecryptionEngineError):
    """
    The provided key has the wrong length or is otherwise malformed.

    This does NOT indicate that the key is cryptographically incorrect
    (i.e., it is not the right key for the given ciphertext) — that is
    reported as TamperedCiphertextError after a failed GCM tag verification.
    """


class TamperedCiphertextError(DecryptionEngineError):
    """
    AES-GCM authentication failed.

    Either the key is incorrect for this ciphertext, or the ciphertext
    (or its authenticated header) has been modified since encryption.
    No plaintext is released when this error is raised.
    """


class InvalidFormatError(DecryptionEngineError):
    """
    The encrypted blob does not conform to the CyberShield Demo Encrypted
    format (wrong magic bytes, truncated header, etc.).
    """


class UnsupportedVersionError(DecryptionEngineError):
    """
    The blob uses a format version that this engine does not support.
    """


class IntegrityError(DecryptionEngineError):
    """
    The recovered plaintext's SHA-256 hash does not match the value
    recorded in the encrypted file's header.

    The ciphertext authenticated successfully (correct key, no tampering),
    but the post-decryption integrity check failed, which should not
    happen under normal conditions and indicates a serious internal error.
    """


# ---------------------------------------------------------------
# File and path safety
# ---------------------------------------------------------------


class PathTraversalError(DecryptionEngineError):
    """
    A resolved file path escapes its approved base directory.
    This is a security violation and the operation is aborted.
    """


class FileSizeLimitError(DecryptionEngineError):
    """The input file exceeds the configured size limit."""


class DemoFileNotFoundError(DecryptionEngineError):
    """The requested demo file does not exist in the demo directory."""


class EncryptedFileNotFoundError(DecryptionEngineError):
    """The encrypted demo file referenced by the job does not exist."""


# ---------------------------------------------------------------
# Job management
# ---------------------------------------------------------------


class JobNotFoundError(DecryptionEngineError):
    """No recovery job exists with the given job ID."""


class JobAlreadyRunningError(DecryptionEngineError):
    """
    A recovery job for the same encrypted file is already in progress.
    Wait for it to complete or retrieve its result before starting another.
    """


# ---------------------------------------------------------------
# Adapter / compatibility
# ---------------------------------------------------------------


class AdapterUnavailableError(DecryptionEngineError):
    """
    The requested decryptor adapter is registered but not available
    in this environment (e.g., the external tool has not been installed
    or its prerequisites are not met).
    """


class UnsupportedFamilyError(DecryptionEngineError):
    """
    No registered adapter supports the identified ransomware family
    and variant combination.
    """
