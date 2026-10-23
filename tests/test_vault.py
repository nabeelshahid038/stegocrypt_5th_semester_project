"""
tests/test_vault.py
-------------------
Unit tests for Secret Vault packaging, compression, and path traversal security.
"""

import hashlib
import pytest
from core.vault import (
    create_vault,
    extract_vault,
    sanitize_filename,
    compute_sha256,
    VaultContent,
)


def test_sanitize_filename():
    assert sanitize_filename("../../evil.exe") == "evil.exe"
    assert sanitize_filename("..\\..\\malicious.sh") == "malicious.sh"
    assert sanitize_filename("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("safe_report.pdf") == "safe_report.pdf"
    assert sanitize_filename("   ") == "unnamed_file.bin"
    assert sanitize_filename("folder/nested/doc.txt") == "doc.txt"


def test_create_and_extract_text_only_vault():
    msg = "This is a secret vault test 🔐"
    zip_bytes, content = create_vault(message=msg)

    assert content.message == msg
    assert len(content.files) == 0
    assert content.metadata["message_present"] is True
    assert content.metadata["file_count"] == 0

    extracted = extract_vault(zip_bytes)
    assert extracted.message == msg
    assert len(extracted.files) == 0
    assert extracted.metadata["message_present"] is True


def test_create_and_extract_file_vault():
    msg = "Project Confidential 🔐"
    file1_data = b"Meeting notes for 2026-10-23.\nHighly classified."
    file2_data = b"%PDF-1.4 sample pdf binary data \x00\x01\x02\xff"
    file3_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

    files = [
        ("notes.txt", file1_data),
        ("sample.pdf", file2_data),
        ("sample.png", file3_data),
    ]

    zip_bytes, content = create_vault(message=msg, files=files)
    assert content.message == msg
    assert len(content.files) == 3
    assert content.compressed_size > 0

    extracted = extract_vault(zip_bytes)
    assert extracted.message == msg
    assert len(extracted.files) == 3

    recovered_map = {f.name: f for f in extracted.files}
    assert "notes.txt" in recovered_map
    assert "sample.pdf" in recovered_map
    assert "sample.png" in recovered_map

    # Verify exact byte matches and SHA-256 hashes
    for fname, original_bytes in files:
        rec_file = recovered_map[fname]
        assert rec_file.data == original_bytes
        assert rec_file.sha256 == hashlib.sha256(original_bytes).hexdigest()
        assert rec_file.size == len(original_bytes)


def test_path_traversal_prevention_in_zip():
    # Attempt to inject path traversal filenames
    files = [
        ("../../../evil.exe", b"malicious binary payload"),
        ("..\\windows\\system32\\calc.exe", b"calc payload"),
    ]

    zip_bytes, content = create_vault(files=files)
    extracted = extract_vault(zip_bytes)

    # Filenames must be sanitized to pure basenames
    for f in extracted.files:
        assert "/" not in f.name
        assert "\\" not in f.name
        assert ".." not in f.name
    assert extracted.files[0].name == "evil.exe"
    assert extracted.files[1].name == "calc.exe"


def test_unicode_vault_content():
    urdu_msg = "یہ ایک خفیہ پیغام ہے 🔐"
    arabic_filename = "ملاحظات.txt"
    urdu_data = "خفیہ فائل مواد 🇵🇰".encode("utf-8")

    zip_bytes, _ = create_vault(message=urdu_msg, files=[(arabic_filename, urdu_data)])
    extracted = extract_vault(zip_bytes)

    assert extracted.message == urdu_msg
    assert len(extracted.files) == 1
    assert extracted.files[0].data == urdu_data


def test_empty_vault_raises_error():
    with pytest.raises(ValueError, match="either a secret message or at least one file"):
        create_vault(message="", files=[])


def test_corrupted_zip_raises_error():
    with pytest.raises(ValueError, match="not a valid ZIP archive"):
        extract_vault(b"corrupted not a zip archive data")
