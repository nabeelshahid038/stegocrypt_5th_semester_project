"""
steganography.py
----------------
Compatibility bridge for StegoCrypt Version 1 / legacy API.
"""

import numpy as np
from PIL import Image
import struct
from core.payload import MAGIC, HEADER_V1_LEN as HEADER_LEN, LENGTH_V1_FMT as LENGTH_FMT
from core.crypto import SALT_LEN, NONCE_LEN

LENGTH_LEN = 4


def _image_to_rgb_array(image: Image.Image) -> tuple[np.ndarray, str]:
    from core.steganography import image_to_rgb_array
    return image_to_rgb_array(image)


def _bits_from_bytes(data: bytes) -> np.ndarray:
    from core.steganography import bits_from_bytes
    return bits_from_bytes(data)


def _bytes_from_bits(bits: np.ndarray) -> bytes:
    from core.steganography import bytes_from_bits
    return bytes_from_bits(bits)


def image_capacity_bytes(image: Image.Image) -> int:
    from core.steganography import calculate_capacity
    return calculate_capacity(image)["capacity_bytes"]


def embed_payload(image: Image.Image, payload: bytes) -> Image.Image:
    from core.steganography import embed_payload as core_embed
    return core_embed(image, payload)


def extract_payload(image: Image.Image) -> bytes:
    """
    Legacy extraction function returning full raw payload bytes (header + ciphertext).
    """
    arr, _ = _image_to_rgb_array(image)
    if arr.ndim != 3 or arr.shape[2] < 3:
        raise ValueError("Image must have at least 3 colour channels.")

    flat_rgb = arr[:, :, :3].reshape(-1)

    # Read first 4 bytes for magic
    if len(flat_rgb) < 32:
        raise ValueError("Image is too small to contain a StegoCrypt payload.")

    magic = _bytes_from_bits((flat_rgb[:32] & 1).astype(np.uint8))
    if magic != MAGIC:
        raise ValueError(
            "No StegoCrypt payload detected in this image. "
            "(Magic header not found — this image was not produced by StegoCrypt.)"
        )

    # Read version byte
    version = _bytes_from_bits((flat_rgb[32:40] & 1).astype(np.uint8))[0]
    if version == 1:
        header_bits = HEADER_LEN * 8
        if len(flat_rgb) < header_bits:
            raise ValueError("Image is too small to contain a StegoCrypt payload.")
        header_bytes = _bytes_from_bits((flat_rgb[:header_bits] & 1).astype(np.uint8))
        offset = 4 + 1 + SALT_LEN + NONCE_LEN
        (ct_len,) = struct.unpack(LENGTH_FMT, header_bytes[offset : offset + LENGTH_LEN])
        if ct_len <= 0 or ct_len > 100_000_000:
            raise ValueError("Payload length field is invalid or corrupted.")
        total_bytes = HEADER_LEN + ct_len
        total_bits = total_bytes * 8
        if len(flat_rgb) < total_bits:
            raise ValueError("Payload claims more data than image can hold.")
        return _bytes_from_bits((flat_rgb[:total_bits] & 1).astype(np.uint8))
    elif version == 2:
        from core.payload import HEADER_V2_LEN, LENGTH_V2_FMT
        header_bits = HEADER_V2_LEN * 8
        if len(flat_rgb) < header_bits:
            raise ValueError("Image is too small.")
        header_bytes = _bytes_from_bits((flat_rgb[:header_bits] & 1).astype(np.uint8))
        (ct_len,) = struct.unpack(LENGTH_V2_FMT, header_bytes[34:42])
        total_bytes = HEADER_V2_LEN + ct_len
        total_bits = total_bytes * 8
        if len(flat_rgb) < total_bits:
            raise ValueError("Payload claims more data than image can hold.")
        return _bytes_from_bits((flat_rgb[:total_bits] & 1).astype(np.uint8))
    else:
        raise ValueError(f"Unsupported payload version: {version}.")
