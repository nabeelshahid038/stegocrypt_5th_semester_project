"""
tests/test_steganography.py
----------------------------
Automated tests for steganography.py
"""

import pytest
import numpy as np
from PIL import Image
from crypto_utils import encrypt_message, decrypt_message
from steganography import embed_payload, extract_payload, image_capacity_bytes


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_rgb_image(width=200, height=200) -> Image.Image:
    arr = np.random.randint(0, 255, (height, width, 3), dtype=np.uint8)
    return Image.fromarray(arr, mode="RGB")


def make_rgba_image(width=200, height=200) -> Image.Image:
    arr = np.random.randint(0, 255, (height, width, 4), dtype=np.uint8)
    return Image.fromarray(arr, mode="RGBA")


# ── Capacity ──────────────────────────────────────────────────────────────────

def test_capacity_rgb():
    img = make_rgb_image(100, 100)
    cap = image_capacity_bytes(img)
    assert cap == (100 * 100 * 3) // 8   # 3750 bytes


def test_capacity_rgba():
    img = make_rgba_image(100, 100)
    cap = image_capacity_bytes(img)
    # Only RGB channels used
    assert cap == (100 * 100 * 3) // 8


# ── Embed / Extract round-trip ────────────────────────────────────────────────

def test_embed_extract_rgb():
    img     = make_rgb_image(300, 300)
    payload = encrypt_message("Hello, StegoCrypt!", "TestPass123!")
    stego   = embed_payload(img, payload)
    out     = extract_payload(stego)
    assert decrypt_message(out, "TestPass123!") == "Hello, StegoCrypt!"


def test_embed_extract_rgba():
    img     = make_rgba_image(300, 300)
    payload = encrypt_message("RGBA test 🔐", "RgbaPass123!")
    stego   = embed_payload(img, payload)
    out     = extract_payload(stego)
    assert decrypt_message(out, "RgbaPass123!") == "RGBA test 🔐"


def test_alpha_channel_unchanged():
    img   = make_rgba_image(100, 100)
    alpha = np.array(img)[:, :, 3].copy()
    payload = encrypt_message("Alpha preserve", "AlphaPass123!")
    stego   = embed_payload(img, payload)
    stego_alpha = np.array(stego)[:, :, 3]
    assert np.array_equal(alpha, stego_alpha), "Alpha channel must remain unchanged"


def test_unicode_embed_extract():
    img     = make_rgb_image(300, 300)
    msg     = "السلام علیکم 🔐"
    payload = encrypt_message(msg, "UniPass123!")
    stego   = embed_payload(img, payload)
    out     = extract_payload(stego)
    assert decrypt_message(out, "UniPass123!") == msg


def test_long_message():
    img     = make_rgb_image(500, 500)
    msg     = "Long message " * 200
    payload = encrypt_message(msg, "LongPass123!")
    stego   = embed_payload(img, payload)
    out     = extract_payload(stego)
    assert decrypt_message(out, "LongPass123!") == msg


# ── Overflow ──────────────────────────────────────────────────────────────────

def test_payload_too_large_raises():
    img     = make_rgb_image(10, 10)   # tiny image — 37 bytes capacity
    payload = b'\x00' * 500           # much too large
    with pytest.raises(ValueError, match="[Tt]oo large|[Cc]apacity"):
        embed_payload(img, payload)


# ── Invalid / non-stego images ────────────────────────────────────────────────

def test_extract_non_stego_image_raises():
    img = make_rgb_image(200, 200)    # clean image with no payload
    with pytest.raises(ValueError, match="[Mm]agic|[Pp]ayload|not found"):
        extract_payload(img)


def test_embed_empty_payload_raises():
    img = make_rgb_image(100, 100)
    with pytest.raises(ValueError):
        embed_payload(img, b"")


# ── LSB integrity ─────────────────────────────────────────────────────────────

def test_lsb_pixel_values_within_1():
    """Embedded image should differ from original by at most 1 per pixel channel."""
    img     = make_rgb_image(200, 200)
    payload = encrypt_message("LSB delta test", "TestPass123!")
    stego   = embed_payload(img, payload)

    orig_arr  = np.array(img)[:, :, :3].astype(np.int16)
    stego_arr = np.array(stego)[:, :, :3].astype(np.int16)
    diff      = np.abs(orig_arr - stego_arr)
    assert diff.max() <= 1, "LSB embedding must change pixels by at most 1"


# ── End-to-end mandatory test ─────────────────────────────────────────────────

def test_mandatory_e2e():
    """
    Mandatory end-to-end test as specified in project requirements.
    """
    msg = "This is my secret message 🔐"
    pw  = "StrongPassword123!"

    img     = make_rgb_image(400, 400)
    payload = encrypt_message(msg, pw)
    stego   = embed_payload(img, payload)

    # ── Correct password ──────────────────────────────────────────────────
    out      = extract_payload(stego)
    recovered = decrypt_message(out, pw)
    assert recovered == msg, f"Expected '{msg}', got '{recovered}'"

    # ── Wrong password must fail ──────────────────────────────────────────
    with pytest.raises(ValueError, match="[Ii]ncorrect|corrupted"):
        decrypt_message(out, "WrongPassword123")
