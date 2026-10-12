"""
steganography.py
----------------
LSB (Least Significant Bit) steganography for embedding/extracting
a binary payload inside RGB/RGBA PNG images.

Only the R, G, B channels are modified. The alpha channel is left intact.
"""

import numpy as np
from PIL import Image
from crypto_utils import HEADER_LEN, MAGIC, SALT_LEN, NONCE_LEN, LENGTH_LEN, LENGTH_FMT
import struct

# ── Helpers ───────────────────────────────────────────────────────────────────

def _image_to_rgb_array(image: Image.Image) -> tuple[np.ndarray, str]:
    """
    Convert image to RGB numpy array, returning (array, original_mode).
    Handles RGB, RGBA, L, P, etc.
    """
    original_mode = image.mode
    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGB")
    return np.array(image, dtype=np.uint8), original_mode


def _bits_from_bytes(data: bytes) -> np.ndarray:
    """Convert bytes to a flat numpy array of bits (MSB first)."""
    byte_array = np.frombuffer(data, dtype=np.uint8)
    bits = np.unpackbits(byte_array)   # shape: (len(data)*8,)
    return bits


def _bytes_from_bits(bits: np.ndarray) -> bytes:
    """Convert a flat numpy array of bits back to bytes."""
    # Ensure length is multiple of 8
    padded = bits[: (len(bits) // 8) * 8]
    return np.packbits(padded).tobytes()


# ── Capacity ──────────────────────────────────────────────────────────────────

def image_capacity_bytes(image: Image.Image) -> int:
    """
    Maximum bytes that can be hidden in the image's RGB channels (1 bit/channel).
    """
    arr, _ = _image_to_rgb_array(image)
    h, w = arr.shape[:2]
    return (h * w * 3) // 8


# ── Embed ─────────────────────────────────────────────────────────────────────

def embed_payload(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Embed *payload* bytes into the LSBs of *image*'s RGB channels.

    Returns a new PIL Image (PNG-ready) with payload hidden inside.
    """
    if not payload:
        raise ValueError("Payload must not be empty.")

    arr, original_mode = _image_to_rgb_array(image)
    h, w = arr.shape[:2]

    capacity_bits = h * w * 3
    payload_bits  = len(payload) * 8

    if payload_bits > capacity_bits:
        raise ValueError(
            f"The encrypted payload ({len(payload):,} bytes = {payload_bits:,} bits) "
            f"is too large for this image (capacity: {capacity_bits // 8:,} bytes). "
            "Please use a larger image or a shorter message."
        )

    # Flatten only the RGB channels into a 1-D view
    if arr.ndim == 3 and arr.shape[2] >= 3:
        rgb = arr[:, :, :3].copy()         # shape (H, W, 3)
    else:
        raise ValueError("Image must have at least 3 colour channels.")

    flat_rgb = rgb.reshape(-1)             # shape (H*W*3,)

    bits = _bits_from_bytes(payload)       # shape (payload_bits,)

    # Clear LSB of target pixels, then OR in the payload bit
    flat_rgb[:payload_bits] = (flat_rgb[:payload_bits] & 0xFE) | bits

    rgb = flat_rgb.reshape(h, w, 3)

    # Re-assemble image (keep alpha if present)
    if arr.shape[2] == 4:
        out_arr = np.dstack([rgb, arr[:, :, 3]])   # RGBA
    else:
        out_arr = rgb

    stego = Image.fromarray(out_arr, mode=("RGBA" if arr.shape[2] == 4 else "RGB"))
    return stego


# ── Extract ───────────────────────────────────────────────────────────────────

def extract_payload(image: Image.Image) -> bytes:
    """
    Extract the StegoCrypt binary payload from *image*'s LSBs.

    Reads only as many bits as the payload header dictates —
    does NOT blindly read the entire image.

    Raises ValueError if no valid payload is found.
    """
    arr, _ = _image_to_rgb_array(image)

    if arr.ndim == 3 and arr.shape[2] >= 3:
        rgb = arr[:, :, :3]
    else:
        raise ValueError("Image must have at least 3 colour channels.")

    flat_rgb = rgb.reshape(-1)

    total_pixels = len(flat_rgb)

    # ── Step 1: Read the fixed header ─────────────────────────────────────
    header_bits = HEADER_LEN * 8

    if total_pixels < header_bits:
        raise ValueError("Image is too small to contain a StegoCrypt payload.")

    lsbs_header = (flat_rgb[:header_bits] & 1).astype(np.uint8)
    header_bytes = _bytes_from_bits(lsbs_header)

    # Validate magic
    if header_bytes[:4] != MAGIC:
        raise ValueError(
            "No StegoCrypt payload detected in this image. "
            "(Magic header not found — this image was not produced by StegoCrypt.)"
        )

    # Parse ciphertext length from header
    offset = 4 + 1 + SALT_LEN + NONCE_LEN   # magic + version + salt + nonce
    (ct_len,) = struct.unpack(LENGTH_FMT, header_bytes[offset : offset + LENGTH_LEN])

    if ct_len <= 0 or ct_len > 100_000_000:
        raise ValueError("Payload length field is invalid or corrupted.")

    # ── Step 2: Read exactly the right number of bits ─────────────────────
    total_payload_bytes = HEADER_LEN + ct_len
    total_payload_bits  = total_payload_bytes * 8

    if total_pixels < total_payload_bits:
        raise ValueError(
            "Payload claims more data than the image can hold. "
            "The image may be corrupted or altered."
        )

    lsbs_full = (flat_rgb[:total_payload_bits] & 1).astype(np.uint8)
    payload_bytes = _bytes_from_bits(lsbs_full)

    return payload_bytes
