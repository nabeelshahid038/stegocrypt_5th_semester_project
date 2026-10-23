"""
core/payload.py
---------------
Structured binary payload packing, unpacking, and validation.
Supports StegoCrypt Pro (Version 2: Vault + Flags + 64-bit length)
with full backward compatibility for StegoCrypt (Version 1: Legacy 32-bit).
"""

import struct
from dataclasses import dataclass

MAGIC = b"STGC"

VERSION_1 = 1  # Legacy single-message payload
VERSION_2 = 2  # Vault payload with flags and 64-bit length

# Flag bits for Version 2
FLAG_COMPRESSED    = 1 << 0  # 0x01: Vault is ZIP-compressed
FLAG_VAULT         = 1 << 1  # 0x02: Vault package structure
FLAG_FILES_PRESENT = 1 << 2  # 0x04: Contains one or more files
FLAG_TEXT_PRESENT  = 1 << 3  # 0x08: Contains secret text message

# Header layout Version 2:
#   [0:4]   Magic (4 bytes)       'STGC'
#   [4:5]   Version (1 byte)      0x02
#   [5:6]   Flags (1 byte)        bitmask
#   [6:22]  Salt (16 bytes)       scrypt salt
#   [22:34] Nonce (12 bytes)      AES-GCM nonce
#   [34:42] Length (8 bytes)      uint64 big-endian ciphertext length
# Total fixed header = 42 bytes
HEADER_V2_LEN = 42
LENGTH_V2_FMT = ">Q"  # 64-bit unsigned integer

# Header layout Version 1 (legacy):
#   [0:4]   Magic (4 bytes)       'STGC'
#   [4:5]   Version (1 byte)      0x01
#   [5:21]  Salt (16 bytes)       scrypt salt
#   [21:33] Nonce (12 bytes)      AES-GCM nonce
#   [33:37] Length (4 bytes)      uint32 big-endian ciphertext length
# Total fixed header = 37 bytes
HEADER_V1_LEN = 37
LENGTH_V1_FMT = ">I"  # 32-bit unsigned integer


@dataclass
class PayloadMetadata:
    version: int
    flags: int
    salt: bytes
    nonce: bytes
    ciphertext_length: int
    header_length: int
    total_length: int
    is_vault: bool
    is_compressed: bool
    has_files: bool
    has_text: bool


def pack_payload_v2(
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    is_compressed: bool = True,
    is_vault: bool = True,
    has_files: bool = False,
    has_text: bool = True,
) -> bytes:
    """
    Construct a Version 2 StegoCrypt Pro binary payload.
    """
    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes.")
    if len(nonce) != 12:
        raise ValueError("Nonce must be exactly 12 bytes.")

    flags = 0
    if is_compressed:
        flags |= FLAG_COMPRESSED
    if is_vault:
        flags |= FLAG_VAULT
    if has_files:
        flags |= FLAG_FILES_PRESENT
    if has_text:
        flags |= FLAG_TEXT_PRESENT

    ct_len = len(ciphertext)
    len_bytes = struct.pack(LENGTH_V2_FMT, ct_len)

    header = (
        MAGIC +
        bytes([VERSION_2]) +
        bytes([flags]) +
        salt +
        nonce +
        len_bytes
    )
    return header + ciphertext


def parse_header(header_bytes: bytes) -> PayloadMetadata:
    """
    Inspect the binary header (at least 42 bytes recommended, minimum 37).
    Determines whether a valid StegoCrypt payload signature exists and
    parses metadata for either Version 1 or Version 2.
    
    Raises ValueError if header is invalid or corrupted.
    """
    if len(header_bytes) < 4:
        raise ValueError("Header bytes too short to verify signature.")

    if header_bytes[:4] != MAGIC:
        raise ValueError("Invalid magic header. Not a StegoCrypt image.")

    if len(header_bytes) < 5:
        raise ValueError("Header incomplete: missing version byte.")

    version = header_bytes[4]

    if version == VERSION_2:
        if len(header_bytes) < HEADER_V2_LEN:
            raise ValueError(f"Header too short for Version 2 (expected at least {HEADER_V2_LEN} bytes).")

        flags = header_bytes[5]
        salt = header_bytes[6:22]
        nonce = header_bytes[22:34]
        (ct_len,) = struct.unpack(LENGTH_V2_FMT, header_bytes[34:42])

        is_compressed = bool(flags & FLAG_COMPRESSED)
        is_vault = bool(flags & FLAG_VAULT)
        has_files = bool(flags & FLAG_FILES_PRESENT)
        has_text = bool(flags & FLAG_TEXT_PRESENT)

        return PayloadMetadata(
            version=VERSION_2,
            flags=flags,
            salt=salt,
            nonce=nonce,
            ciphertext_length=ct_len,
            header_length=HEADER_V2_LEN,
            total_length=HEADER_V2_LEN + ct_len,
            is_vault=is_vault,
            is_compressed=is_compressed,
            has_files=has_files,
            has_text=has_text,
        )

    elif version == VERSION_1:
        if len(header_bytes) < HEADER_V1_LEN:
            raise ValueError(f"Header too short for Version 1 (expected at least {HEADER_V1_LEN} bytes).")

        flags = 0
        salt = header_bytes[5:21]
        nonce = header_bytes[21:33]
        (ct_len,) = struct.unpack(LENGTH_V1_FMT, header_bytes[33:37])

        return PayloadMetadata(
            version=VERSION_1,
            flags=flags,
            salt=salt,
            nonce=nonce,
            ciphertext_length=ct_len,
            header_length=HEADER_V1_LEN,
            total_length=HEADER_V1_LEN + ct_len,
            is_vault=False,
            is_compressed=False,
            has_files=False,
            has_text=True,
        )

    else:
        raise ValueError(f"Unsupported StegoCrypt payload version: {version}.")
