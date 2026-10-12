"""
tests/test_crypto.py
--------------------
Automated tests for crypto_utils.py
"""

import pytest
from crypto_utils import encrypt_message, decrypt_message, validate_password, password_strength


# ── validate_password ─────────────────────────────────────────────────────────

def test_validate_password_empty():
    with pytest.raises(ValueError, match="empty"):
        validate_password("")


def test_validate_password_too_short():
    with pytest.raises(ValueError, match="at least"):
        validate_password("abc")


def test_validate_password_exactly_min():
    validate_password("12345678")   # should not raise


def test_password_strength_weak():
    assert password_strength("abc") == "Weak"


def test_password_strength_fair():
    assert password_strength("abcdefgh") in ("Weak", "Fair")


def test_password_strength_strong():
    assert password_strength("Abcdefgh1!xyz") in ("Strong", "Very Strong")


# ── encrypt / decrypt round-trip ──────────────────────────────────────────────

def test_basic_roundtrip():
    msg = "Hello, World!"
    pw  = "TestPass123!"
    payload = encrypt_message(msg, pw)
    assert decrypt_message(payload, pw) == msg


def test_unicode_roundtrip():
    msg = "السلام علیکم 🔐"
    pw  = "UnicodePass99!"
    payload = encrypt_message(msg, pw)
    assert decrypt_message(payload, pw) == msg


def test_emoji_roundtrip():
    msg = "🐍🔐🛡️💻🎉"
    pw  = "EmojiPass123!"
    payload = encrypt_message(msg, pw)
    assert decrypt_message(payload, pw) == msg


def test_long_text_roundtrip():
    msg = "Secret " * 500   # ~3500 chars
    pw  = "LongTextPass456!"
    payload = encrypt_message(msg, pw)
    assert decrypt_message(payload, pw) == msg


def test_wrong_password_fails():
    msg = "Top secret"
    pw  = "CorrectPass1!"
    payload = encrypt_message(msg, pw)
    with pytest.raises(ValueError, match="[Ii]ncorrect password|corrupted"):
        decrypt_message(payload, "WrongPassword1!")


def test_empty_message_raises():
    with pytest.raises(ValueError, match="[Ee]mpty|empty"):
        encrypt_message("", "SomePass1!")


def test_empty_password_raises():
    with pytest.raises(ValueError):
        encrypt_message("Hello", "")


def test_short_password_raises():
    with pytest.raises(ValueError, match="at least"):
        encrypt_message("Hello", "short")


def test_payload_has_magic_header():
    payload = encrypt_message("Test", "TestPass123!")
    assert payload[:4] == b'STGC'


def test_payload_version():
    payload = encrypt_message("Test", "TestPass123!")
    assert payload[4:5] == b'\x01'


def test_corrupted_payload():
    payload = bytearray(encrypt_message("Test", "TestPass123!"))
    payload[30] ^= 0xFF   # flip byte inside ciphertext
    with pytest.raises(ValueError):
        decrypt_message(bytes(payload), "TestPass123!")


def test_wrong_magic():
    with pytest.raises(ValueError, match="[Mm]agic|payload"):
        decrypt_message(b'XXXX\x01' + b'\x00' * 100, "TestPass123!")


def test_truncated_payload():
    with pytest.raises(ValueError):
        decrypt_message(b'STGC\x01' + b'\x00' * 10, "TestPass123!")


def test_nfkc_password_normalization():
    """Same logical password with different Unicode representations should work."""
    msg = "Normalize me"
    # é repeated to meet 8-char minimum, using NFC vs NFD form
    pw_nfc  = "\u00e9" * 8         # é as single codepoint (NFC)
    pw_nfd  = "e\u0301" * 8       # é as e + combining accent (NFD)
    payload = encrypt_message(msg, pw_nfc)
    # NFKC normalizes both forms to the same byte sequence → should decrypt
    assert decrypt_message(payload, pw_nfd) == msg
