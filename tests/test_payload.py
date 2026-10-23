"""
tests/test_payload.py
---------------------
Unit tests for structured binary payload packing, header parsing, and flags.
"""

import os
import pytest
from core.payload import (
    pack_payload_v2,
    parse_header,
    MAGIC,
    VERSION_1,
    VERSION_2,
    FLAG_COMPRESSED,
    FLAG_VAULT,
    FLAG_FILES_PRESENT,
    FLAG_TEXT_PRESENT,
    HEADER_V2_LEN,
    HEADER_V1_LEN,
)


def test_pack_and_parse_v2_header():
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ciphertext = b"encrypted_vault_data_bytes_12345"

    payload = pack_payload_v2(
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
        is_compressed=True,
        is_vault=True,
        has_files=True,
        has_text=True,
    )

    assert payload[:4] == MAGIC
    assert payload[4] == VERSION_2
    assert len(payload) == HEADER_V2_LEN + len(ciphertext)

    meta = parse_header(payload[:HEADER_V2_LEN])
    assert meta.version == VERSION_2
    assert meta.is_vault is True
    assert meta.is_compressed is True
    assert meta.has_files is True
    assert meta.has_text is True
    assert meta.salt == salt
    assert meta.nonce == nonce
    assert meta.ciphertext_length == len(ciphertext)
    assert meta.total_length == len(payload)


def test_parse_legacy_v1_header():
    # Construct a legacy v1 header
    salt = os.urandom(16)
    nonce = os.urandom(12)
    import struct
    ct_len = 1024
    v1_header = MAGIC + bytes([1]) + salt + nonce + struct.pack(">I", ct_len)
    assert len(v1_header) == HEADER_V1_LEN

    meta = parse_header(v1_header)
    assert meta.version == VERSION_1
    assert meta.is_vault is False
    assert meta.salt == salt
    assert meta.nonce == nonce
    assert meta.ciphertext_length == ct_len
    assert meta.total_length == HEADER_V1_LEN + ct_len


def test_invalid_magic_header():
    bad_header = b"BADM" + bytes([2]) + os.urandom(37)
    with pytest.raises(ValueError, match="Not a StegoCrypt image"):
        parse_header(bad_header)


def test_truncated_header():
    with pytest.raises(ValueError, match="Header bytes too short"):
        parse_header(b"ST")
