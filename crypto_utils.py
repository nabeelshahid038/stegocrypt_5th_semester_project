"""
crypto_utils.py
---------------
AES-256-GCM encryption and decryption with scrypt key derivation.

Payload format (binary, no delimiters):
  [4 bytes]  Magic header  b'STGC'
  [1 byte]   Version       0x01
  [16 bytes] Salt
  [12 bytes] Nonce
  [4 bytes]  Ciphertext length (big-endian uint32)
  [N bytes]  Ciphertext (includes GCM auth tag)
"""

import os
import struct
import unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ── Constants ────────────────────────────────────────────────────────────────
MAGIC           = b'STGC'
VERSION         = b'\x01'
SALT_LEN        = 16   # bytes
NONCE_LEN       = 12   # bytes
KEY_LEN         = 32   # 256-bit AES key
LENGTH_FMT      = '>I'  # big-endian unsigned 32-bit int
LENGTH_LEN      = 4    # bytes

# Fixed header size (magic + version + salt + nonce + length field)
HEADER_LEN      = len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN + LENGTH_LEN

MIN_PASSWORD_LEN = 8

# ── Internal helpers ──────────────────────────────────────────────────────────

def _normalize_password(password: str) -> bytes:
    """NFKC-normalize and UTF-8 encode password."""
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password + salt using scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=2**14,   # CPU/memory cost — lower for usability, still secure
        r=8,
        p=1,
        backend=default_backend(),
    )
    return kdf.derive(_normalize_password(password))


# ── Public API ────────────────────────────────────────────────────────────────

def validate_password(password: str) -> None:
    """Raise ValueError if password does not meet requirements."""
    if not password:
        raise ValueError("Password must not be empty.")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LEN} characters long."
        )


def password_strength(password: str) -> str:
    """Return a simple strength label: Weak / Fair / Strong / Very Strong."""
    length = len(password)
    has_upper  = any(c.isupper() for c in password)
    has_lower  = any(c.islower() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    score = sum([has_upper, has_lower, has_digit, has_symbol])

    if length < 8:
        return "Weak"
    elif length < 12 or score <= 1:
        return "Fair"
    elif length < 16 or score <= 2:
        return "Strong"
    else:
        return "Very Strong"


def encrypt_message(plaintext: str, password: str) -> bytes:
    """
    Encrypt *plaintext* with *password* using AES-256-GCM + scrypt.

    Returns binary payload (STGC format).
    """
    if not plaintext:
        raise ValueError("Secret message must not be empty.")
    validate_password(password)

    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = _derive_key(password, salt)

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    length_bytes = struct.pack(LENGTH_FMT, len(ciphertext))

    payload = MAGIC + VERSION + salt + nonce + length_bytes + ciphertext
    return payload


def decrypt_message(payload: bytes, password: str) -> str:
    """
    Decrypt a STGC binary payload with *password*.

    Raises ValueError with a user-friendly message on any failure.
    """
    validate_password(password)

    # ── Validate magic header ─────────────────────────────────────────────
    if len(payload) < HEADER_LEN:
        raise ValueError("No valid StegoCrypt payload detected in this image.")

    if payload[:4] != MAGIC:
        raise ValueError("No StegoCrypt payload detected. (Magic header missing.)")

    version = payload[4:5]
    if version != VERSION:
        raise ValueError(
            f"Unsupported payload version: {version!r}. "
            "Please use the same version of StegoCrypt."
        )

    # ── Parse header fields ───────────────────────────────────────────────
    offset = 5
    salt   = payload[offset : offset + SALT_LEN];   offset += SALT_LEN
    nonce  = payload[offset : offset + NONCE_LEN];  offset += NONCE_LEN
    (ct_len,) = struct.unpack(LENGTH_FMT, payload[offset : offset + LENGTH_LEN])
    offset += LENGTH_LEN

    if ct_len <= 0 or ct_len > 100_000_000:
        raise ValueError("Payload length field is invalid or corrupted.")

    if len(payload) < offset + ct_len:
        raise ValueError("Payload is truncated or corrupted.")

    ciphertext = payload[offset : offset + ct_len]

    # ── Decrypt ───────────────────────────────────────────────────────────
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError(
            "Incorrect password or corrupted hidden data. "
            "Please check your password and try again."
        )

    return plaintext_bytes.decode("utf-8")
