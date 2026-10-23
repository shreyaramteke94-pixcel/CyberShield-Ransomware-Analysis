"""
CyberShield Decryption & Recovery Engine
=========================================

This package provides:

  A. Real ransomware recovery adapter infrastructure
     - Registry of verified decryptor adapters
     - Compatibility checker (family/variant/format/prerequisite validation)
     - Honest reporting when recovery is not possible

  B. Controlled cryptography demonstration
     - Genuine AES-256-GCM encrypt / decrypt using the `cryptography` library
     - Isolated demo files; never applied to live ransomware samples
     - Output integrity verification before reporting success

Modules
-------
demo_crypto    – AES-256-GCM encryption/decryption engine (CyberShield demo format)
verification   – Output integrity verifier
orchestrator   – In-memory recovery job orchestrator
registry       – Decryptor adapter registry
compatibility  – Eligibility checker for analyzed samples
schemas        – Pydantic request/response models
exceptions     – Typed exceptions for this package
adapters/      – Decryptor adapter implementations
"""
