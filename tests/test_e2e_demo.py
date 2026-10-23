"""
tests/test_e2e_demo.py
----------------------
Master End-to-End Demo Verification matching Section 68 of the Master Prompt:
  1. Create vault with Cover PNG + Message 'Project Confidential 🔐' + 3 files (notes.txt, sample.pdf, sample.png)
  2. Encrypt with password 'StrongPassword123!' and embed into cover image.
  3. Reload stego PNG, decrypt with same password, verify exact text, exact files, exact SHA-256 hashes.
  4. Test wrong password -> fails cleanly without crash.
  5. Scan stego PNG in Detector -> Verified Confirmed StegoCrypt Payload (Category A).
  6. Scan ordinary PNG in Detector -> Verified No StegoCrypt signature, generic statistical assessment.
"""

import io
import hashlib
import numpy as np
from PIL import Image

from core.crypto import encrypt_bytes, decrypt_bytes
from core.vault import create_vault, extract_vault
from core.payload import pack_payload_v2
from core.steganography import embed_payload, extract_payload
from core.detector import analyze_image
from core.metrics import compute_metrics


def test_master_end_to_end_demo():
    # Step 1: Prepare Cover Image (400x400 PNG)
    cover_arr = np.zeros((400, 400, 3), dtype=np.uint8)
    for y in range(400):
        for x in range(400):
            cover_arr[y, x, 0] = (x * 3) % 256
            cover_arr[y, x, 1] = (y * 2) % 256
            cover_arr[y, x, 2] = (x + y) % 256
    cover_img = Image.fromarray(cover_arr, mode="RGB")

    # Step 2: Prepare Secret Vault contents
    secret_msg = "Project Confidential 🔐"
    file1_bytes = b"Classified military project briefing notes.\nDate: 2026-10-23."
    file2_bytes = b"%PDF-1.5 \x00\x01\x02 Test PDF Document stream..."
    file3_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02"

    files = [
        ("notes.txt", file1_bytes),
        ("sample.pdf", file2_bytes),
        ("sample.png", file3_bytes),
    ]

    password = "StrongPassword123!"

    # Step 3: Create compressed in-memory vault
    zip_bytes, vault_obj = create_vault(message=secret_msg, files=files)
    assert vault_obj.message == secret_msg
    assert len(vault_obj.files) == 3

    # Step 4: Encrypt with AES-256-GCM + scrypt
    salt, nonce, ciphertext = encrypt_bytes(zip_bytes, password)

    # Step 5: Pack structured Version 2 binary payload
    payload = pack_payload_v2(
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
        is_compressed=True,
        is_vault=True,
        has_files=True,
        has_text=True,
    )

    # Step 6: Embed into Cover Image
    stego_img = embed_payload(cover_img, payload)

    # Save to PNG buffer and reload (simulating download and upload)
    png_buf = io.BytesIO()
    stego_img.save(png_buf, format="PNG")
    png_buf.seek(0)
    reloaded_stego_img = Image.open(png_buf)
    reloaded_stego_img.load()

    # Step 7: Verify Metrics
    metrics = compute_metrics(cover_img, reloaded_stego_img)
    assert metrics["psnr"] > 45.0  # High fidelity
    assert metrics["ssim"] > 0.999
    assert metrics["changed_channels"] > 0

    # Step 8: Decrypt and Unlock Vault
    recovered_ct, meta = extract_payload(reloaded_stego_img)
    assert meta.version == 2
    assert meta.is_vault is True
    assert meta.has_files is True
    assert meta.has_text is True

    decrypted_zip = decrypt_bytes(recovered_ct, password, meta.salt, meta.nonce)
    recovered_vault = extract_vault(decrypted_zip)

    # Verify exact secret message
    assert recovered_vault.message == secret_msg

    # Verify exact files and SHA-256 hashes
    assert len(recovered_vault.files) == 3
    rec_files_map = {f.name: f for f in recovered_vault.files}

    for fname, orig_data in files:
        assert fname in rec_files_map
        rec_f = rec_files_map[fname]
        assert rec_f.data == orig_data
        assert rec_f.sha256 == hashlib.sha256(orig_data).hexdigest()

    # Step 9: Verify wrong password rejection
    try:
        decrypt_bytes(recovered_ct, "WrongPassword999!", meta.salt, meta.nonce)
        assert False, "Should have raised ValueError on wrong password"
    except ValueError as ve:
        assert "Incorrect password or corrupted data" in str(ve)

    # Step 10: Run Forensic Detector on Stego Image
    stego_report = analyze_image(reloaded_stego_img)
    assert stego_report.stgc_detected is True
    assert stego_report.verdict_category == "Category A"
    assert stego_report.suspicion_score == 100
    assert "CONFIRMED STEGOCRYPT PAYLOAD" in stego_report.verdict_title

    # Step 11: Run Forensic Detector on Clean Cover Image
    clean_report = analyze_image(cover_img)
    assert clean_report.stgc_detected is False
    assert clean_report.payload_metadata is None
    assert clean_report.verdict_category in ("Category B", "Category C")
    assert clean_report.suspicion_score < 100
