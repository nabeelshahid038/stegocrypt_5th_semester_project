"""
crypto_utils.py
---------------
Compatibility bridge for StegoCrypt Version 1 / legacy API.
Internally delegates to core.crypto and core.payload.
"""

from core.crypto import (
    SALT_LEN,
    NONCE_LEN,
    KEY_LEN,
    MIN_PASSWORD_LEN,
    validate_password,
    derive_key as _derive_key,
    normalize_password as _normalize_password,
    encrypt_bytes,
    decrypt_bytes,
)
from core.payload import (
    MAGIC,
    HEADER_V1_LEN as HEADER_LEN,
    LENGTH_V1_FMT as LENGTH_FMT,
)
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

VERSION = b"\x01"
LENGTH_LEN = 4


def password_strength(password: str) -> str:
    """Legacy string-only strength helper: Weak / Fair / Strong / Very Strong."""
    from core.crypto import password_strength as ps
    return ps(password)["label"]


def encrypt_message(plaintext: str, password: str) -> bytes:
    """
    Encrypt plaintext string with password in Version 1 format.
    Preserves exact legacy format for backwards compatibility.
    """
    if not plaintext:
        raise ValueError("Secret message must not be empty.")
    validate_password(password)

    import os
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    length_bytes = struct.pack(LENGTH_FMT, len(ciphertext))

    return MAGIC + VERSION + salt + nonce + length_bytes + ciphertext


def decrypt_message(payload: bytes, password: str) -> str:
    """
    Decrypt legacy or modern message payload with password.
    """
    validate_password(password)

    if len(payload) < HEADER_LEN:
        raise ValueError("No valid StegoCrypt payload detected in this image.")

    if payload[:4] != MAGIC:
        raise ValueError("No StegoCrypt payload detected. (Magic header missing.)")

    version_byte = payload[4]
    if version_byte == 1:
        # Legacy version 1
        offset = 5
        salt = payload[offset : offset + SALT_LEN]
        offset += SALT_LEN
        nonce = payload[offset : offset + NONCE_LEN]
        offset += NONCE_LEN
        (ct_len,) = struct.unpack(LENGTH_FMT, payload[offset : offset + LENGTH_LEN])
        offset += LENGTH_LEN

        if ct_len <= 0 or ct_len > 100_000_000:
            raise ValueError("Payload length field is invalid or corrupted.")
        if len(payload) < offset + ct_len:
            raise ValueError("Payload is truncated or corrupted.")

        ciphertext = payload[offset : offset + ct_len]
        pt = decrypt_bytes(ciphertext, password, salt, nonce)
        return pt.decode("utf-8")
    elif version_byte == 2:
        # Version 2 payload containing vault
        from core.payload import parse_header
        from core.vault import extract_vault
        meta = parse_header(payload[:42])
        ciphertext = payload[meta.header_length : meta.total_length]
        pt = decrypt_bytes(ciphertext, password, meta.salt, meta.nonce)
        if meta.is_vault:
            vault = extract_vault(pt)
            return vault.message or ""
        return pt.decode("utf-8")
    else:
        raise ValueError(f"Unsupported payload version: {version_byte}.")
