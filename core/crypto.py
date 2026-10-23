"""
core/crypto.py
--------------
Cryptographic utilities for StegoCrypt Pro.
Implements AES-256-GCM authenticated encryption and scrypt key derivation.
"""

import os
import unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ── Constants ────────────────────────────────────────────────────────────────
SALT_LEN = 16          # 128-bit cryptographic salt
NONCE_LEN = 12         # 96-bit standard AES-GCM nonce
KEY_LEN = 32           # 256-bit AES key
SCRYPT_N = 2**14       # 16,384 CPU/memory cost
SCRYPT_R = 8           # Block size
SCRYPT_P = 1           # Parallelization parameter
MIN_PASSWORD_LEN = 8   # Minimum password length requirement


def normalize_password(password: str) -> bytes:
    """Normalize password with Unicode NFKC and return UTF-8 bytes."""
    if not isinstance(password, str):
        password = str(password)
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def validate_password(password: str) -> None:
    """
    Validate that the password satisfies security requirements.
    Raises ValueError with a user-friendly message if invalid.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LEN} characters long."
        )


def password_strength(password: str) -> dict:
    """
    Evaluate password strength and return label and recommendations.
    Strength levels: Weak, Fair, Strong, Very Strong.
    """
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    char_variety = sum([has_upper, has_lower, has_digit, has_symbol])

    if length < MIN_PASSWORD_LEN:
        label = "Weak"
        color = "#ef4444"
        score = 25
    elif length < 12 or char_variety <= 1:
        label = "Fair"
        color = "#f59e0b"
        score = 50
    elif length < 16 or char_variety <= 2:
        label = "Strong"
        color = "#3b82f6"
        score = 75
    else:
        label = "Very Strong"
        color = "#10b981"
        score = 100

    return {
        "label": label,
        "color": color,
        "score": score,
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
    }


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from password and salt using scrypt.
    """
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be exactly {SALT_LEN} bytes.")
    
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(normalize_password(password))


def encrypt_bytes(data: bytes, password: str, salt: bytes | None = None, nonce: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    Returns:
        tuple (salt: bytes, nonce: bytes, ciphertext: bytes)
    where ciphertext contains the 16-byte GCM authentication tag appended.
    """
    validate_password(password)
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data to encrypt must be bytes.")

    salt = salt if salt is not None else os.urandom(SALT_LEN)
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, bytes(data), None)

    return salt, nonce, ciphertext


def decrypt_bytes(ciphertext: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext using password, salt, and nonce.
    Raises ValueError on invalid password or corrupted data.
    """
    validate_password(password)

    if len(salt) != SALT_LEN:
        raise ValueError("Invalid salt length.")
    if len(nonce) != NONCE_LEN:
        raise ValueError("Invalid nonce length.")
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext is too short to contain a valid authentication tag.")

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except InvalidTag:
        raise ValueError(
            "Unable to unlock vault. Incorrect password or corrupted data."
        )
