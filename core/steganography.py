"""
core/steganography.py
---------------------
LSB (Least Significant Bit) steganography for StegoCrypt Pro.
Only modifies RGB channels; preserves alpha channel when present.
Extracts only the exact number of bits indicated by payload metadata.
"""

import numpy as np
from PIL import Image
from core.payload import (
    MAGIC,
    HEADER_V2_LEN,
    HEADER_V1_LEN,
    parse_header,
    PayloadMetadata,
)


def image_to_rgb_array(image: Image.Image) -> tuple[np.ndarray, str]:
    """
    Convert a PIL image to uint8 numpy array, preserving original mode.
    Converts paletted (P), grayscale (L), CMYK, etc., into RGB or RGBA.
    """
    original_mode = image.mode
    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGB")
    return np.array(image, dtype=np.uint8), original_mode


def bits_from_bytes(data: bytes) -> np.ndarray:
    """Convert bytes to a 1D numpy array of bits (MSB first)."""
    byte_array = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(byte_array)


def bytes_from_bits(bits: np.ndarray) -> bytes:
    """Convert a 1D numpy array of bits back to bytes."""
    valid_len = (len(bits) // 8) * 8
    return np.packbits(bits[:valid_len]).tobytes()


def calculate_capacity(image: Image.Image) -> dict:
    """
    Calculate maximum storage capacity of image's RGB channels.
    1 bit per RGB channel.
    """
    w, h = image.size
    total_pixels = w * h
    capacity_bits = total_pixels * 3
    capacity_bytes = capacity_bits // 8
    capacity_kb = capacity_bytes / 1024
    capacity_mb = capacity_kb / 1024

    return {
        "width": w,
        "height": h,
        "total_pixels": total_pixels,
        "capacity_bits": capacity_bits,
        "capacity_bytes": capacity_bytes,
        "capacity_kb": capacity_kb,
        "capacity_mb": capacity_mb,
    }


def embed_payload(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Embed binary payload bytes into image's RGB channels using LSB substitution.
    Does not modify alpha channel if present.
    Returns a new PIL Image (always lossless PNG ready).
    """
    if not payload:
        raise ValueError("Payload must not be empty.")

    arr, orig_mode = image_to_rgb_array(image)
    h, w = arr.shape[:2]

    total_rgb_channels = h * w * 3
    payload_bits = len(payload) * 8

    if payload_bits > total_rgb_channels:
        raise ValueError(
            f"Vault is too large for this image. "
            f"Payload requires {len(payload):,} bytes ({payload_bits:,} bits), "
            f"but image capacity is only {total_rgb_channels // 8:,} bytes. "
            "Please use a larger cover image or reduce vault contents."
        )

    # Separate RGB and Alpha
    has_alpha = arr.ndim == 3 and arr.shape[2] == 4
    rgb = arr[:, :, :3].copy()
    flat_rgb = rgb.reshape(-1)

    # Unpack payload bits
    bits = bits_from_bytes(payload)

    # Apply LSB embedding: clear LSB with 0xFE and OR in secret bit
    flat_rgb[:payload_bits] = (flat_rgb[:payload_bits] & 0xFE) | bits

    # Reshape back to image
    stego_rgb = flat_rgb.reshape((h, w, 3))

    if has_alpha:
        # Recombine with untouched alpha channel
        alpha = arr[:, :, 3]
        out_arr = np.dstack([stego_rgb, alpha])
        return Image.fromarray(out_arr, mode="RGBA")
    else:
        return Image.fromarray(stego_rgb, mode="RGB")


def read_lsb_bytes(image: Image.Image, num_bytes: int) -> bytes:
    """
    Read the first `num_bytes` from the image's RGB LSB bitstream.
    """
    arr, _ = image_to_rgb_array(image)
    flat_rgb = arr[:, :, :3].reshape(-1)
    req_bits = num_bytes * 8

    if len(flat_rgb) < req_bits:
        raise ValueError("Image has fewer pixels than requested byte count.")

    lsb_bits = (flat_rgb[:req_bits] & 1).astype(np.uint8)
    return bytes_from_bits(lsb_bits)


def check_stgc_signature(image: Image.Image) -> tuple[bool, PayloadMetadata | None]:
    """
    Quickly check if the image starts with the STGC signature and valid header.
    Returns:
        (is_stgc: bool, metadata: PayloadMetadata | None)
    """
    try:
        arr, _ = image_to_rgb_array(image)
        flat_rgb = arr[:, :, :3].reshape(-1)

        # Check for MAGIC (4 bytes = 32 bits)
        if len(flat_rgb) < 32:
            return False, None

        first_4_bytes = bytes_from_bits((flat_rgb[:32] & 1).astype(np.uint8))
        if first_4_bytes != MAGIC:
            return False, None

        # Read enough for version byte (5 bytes = 40 bits)
        if len(flat_rgb) < 40:
            return False, None

        version_byte = bytes_from_bits((flat_rgb[:40] & 1).astype(np.uint8))[4]

        # Determine header length to read
        if version_byte == 2:
            req_header_len = HEADER_V2_LEN
        elif version_byte == 1:
            req_header_len = HEADER_V1_LEN
        else:
            return False, None

        if len(flat_rgb) < req_header_len * 8:
            return False, None

        header_bytes = bytes_from_bits((flat_rgb[:req_header_len * 8] & 1).astype(np.uint8))
        meta = parse_header(header_bytes)
        return True, meta
    except Exception:
        return False, None


def extract_payload(image: Image.Image) -> tuple[bytes, PayloadMetadata]:
    """
    Extract StegoCrypt payload from image.
    Reads only as many bits as dictated by header metadata.
    
    Returns:
        tuple (ciphertext_or_vault_bytes: bytes, metadata: PayloadMetadata)
    """
    is_stgc, meta = check_stgc_signature(image)
    if not is_stgc or meta is None:
        raise ValueError(
            "No StegoCrypt vault detected in this image. "
            "(STGC magic signature missing or header corrupted.)"
        )

    arr, _ = image_to_rgb_array(image)
    flat_rgb = arr[:, :, :3].reshape(-1)

    total_bits = meta.total_length * 8
    if len(flat_rgb) < total_bits:
        raise ValueError(
            f"Image corrupted or truncated. Payload requires {meta.total_length:,} bytes, "
            f"but image RGB stream only holds {len(flat_rgb) // 8:,} bytes."
        )

    all_payload_bytes = bytes_from_bits((flat_rgb[:total_bits] & 1).astype(np.uint8))
    ciphertext = all_payload_bytes[meta.header_length : meta.total_length]

    return ciphertext, meta
