"""
tests/test_detector.py
----------------------
Unit tests for Forensic Hidden-Data Detection & Statistical Steganalysis.
"""

import numpy as np
from PIL import Image
from core.detector import (
    analyze_image,
    compute_shannon_entropy,
    compute_lsb_entropy,
    compute_pairs_of_values_chisquare,
    extract_bit_plane,
)
from core.crypto import encrypt_bytes
from core.vault import create_vault
from core.payload import pack_payload_v2
from core.steganography import embed_payload


def test_clean_cover_image_detection():
    # Create a gradient/textured clean cover image (300x300)
    arr = np.zeros((300, 300, 3), dtype=np.uint8)
    for y in range(300):
        for x in range(300):
            arr[y, x, 0] = (x + y) % 256
            arr[y, x, 1] = (x * 2) % 256
            arr[y, x, 2] = (y * 3) % 256
    img = Image.fromarray(arr, mode="RGB")

    report = analyze_image(img)
    assert report.stgc_detected is False
    assert report.payload_metadata is None
    assert report.verdict_category in ("Category C", "Category B")
    assert report.suspicion_score < 100
    assert len(report.channels) == 3


def test_stegocrypt_vault_image_detection():
    # Create cover image
    arr = np.random.randint(50, 200, (200, 200, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")

    # Build and embed a real StegoCrypt vault
    zip_bytes, _ = create_vault(message="Forensic test message 🕵️", files=[("file.txt", b"secret")])
    salt, nonce, ciphertext = encrypt_bytes(zip_bytes, "StrongPassword123!")
    payload = pack_payload_v2(salt, nonce, ciphertext, is_compressed=True, is_vault=True, has_files=True, has_text=True)

    stego_img = embed_payload(img, payload)

    report = analyze_image(stego_img)
    assert report.stgc_detected is True
    assert report.payload_metadata is not None
    assert report.payload_metadata.version == 2
    assert report.payload_metadata.is_vault is True
    assert report.payload_metadata.has_files is True
    assert report.payload_metadata.has_text is True
    assert report.verdict_category == "Category A"
    assert report.suspicion_score == 100
    assert "CONFIRMED STEGOCRYPT PAYLOAD" in report.verdict_title


def test_bit_plane_extraction():
    img = Image.new("RGB", (50, 50), color=(128, 64, 32))
    # Test bit planes 0 to 7 for all 3 channels
    for ch in (0, 1, 2):
        for bit in range(8):
            plane = extract_bit_plane(img, channel_index=ch, bit_index=bit)
            assert isinstance(plane, Image.Image)
            assert plane.mode == "L"
            assert plane.size == (50, 50)


def test_shannon_entropy_calculation():
    # Pure constant array has 0 entropy
    const_arr = np.zeros(100, dtype=np.uint8)
    assert compute_shannon_entropy(const_arr) == 0.0

    # Uniform random array (all 256 values equal) has maximum entropy log2(256) = 8.0
    uniform_arr = np.tile(np.arange(256, dtype=np.uint8), 10)
    assert abs(compute_shannon_entropy(uniform_arr) - 8.0) < 0.001


def test_pairs_of_values_chisquare():
    # Image with equalized pairs: count of 2k equals 2k+1
    arr = np.repeat(np.arange(0, 256, 2, dtype=np.uint8), 10)
    arr_odds = np.repeat(np.arange(1, 256, 2, dtype=np.uint8), 10)
    equalized = np.concatenate([arr, arr_odds])
    chi2_stat, p_val, dof = compute_pairs_of_values_chisquare(equalized)
    assert chi2_stat == 0.0  # perfect pairing
    assert p_val == 1.0
