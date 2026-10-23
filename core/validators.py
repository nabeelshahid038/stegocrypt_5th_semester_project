"""
core/validators.py
------------------
Input and image upload validation helpers for StegoCrypt Pro.
"""

import io
import os
from PIL import Image

ALLOWED_IMAGE_EXTENSIONS = {".png", ".bmp", ".jpg", ".jpeg"}
MAX_IMAGE_BYTES = 25 * 1024 * 1024    # 25 MB upload limit
MAX_PIXELS = 8000 * 8000              # 64 Megapixels
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024  # 10 MB per attached file


def validate_image_upload(file_bytes: bytes, filename: str) -> Image.Image:
    """
    Validate uploaded image file bytes and return a verified PIL Image.
    Normalizes color mode to RGB or RGBA.
    """
    if len(file_bytes) > MAX_IMAGE_BYTES:
        raise ValueError(
            f"Image file exceeds size limit ({len(file_bytes) / (1024 * 1024):.1f} MB). "
            f"Maximum allowed size is {MAX_IMAGE_BYTES // (1024 * 1024)} MB."
        )

    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError(
            f"Unsupported file format '{ext}'. "
            f"Allowed image formats: {', '.join(sorted(ALLOWED_IMAGE_EXTENSIONS))}."
        )

    try:
        img_verify = Image.open(io.BytesIO(file_bytes))
        img_verify.verify()
    except Exception:
        raise ValueError(
            "The uploaded file could not be decoded as a valid image. "
            "Please upload a genuine PNG, BMP, or JPEG file."
        )

    # Reopen after verify
    image = Image.open(io.BytesIO(file_bytes))
    image.load()

    w, h = image.size
    if w * h > MAX_PIXELS:
        raise ValueError(
            f"Image dimensions ({w}×{h} = {w*h:,} pixels) exceed safety limit "
            f"of {MAX_PIXELS:,} pixels."
        )

    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGB")

    return image


def validate_vault_files(files: list[tuple[str, bytes]]) -> None:
    """
    Validate files to be added into the vault.
    """
    if not files:
        return

    for name, data in files:
        if len(data) > MAX_SINGLE_FILE_BYTES:
            raise ValueError(
                f"File '{name}' is too large ({len(data) / (1024 * 1024):.1f} MB). "
                f"Maximum allowed size per file is {MAX_SINGLE_FILE_BYTES // (1024 * 1024)} MB."
            )
