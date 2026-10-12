"""
validators.py
-------------
File / image upload validation helpers.
"""

import io
from PIL import Image

ALLOWED_EXTENSIONS = {".png", ".bmp", ".jpg", ".jpeg"}
MAX_IMAGE_BYTES     = 50 * 1024 * 1024   # 50 MB hard limit
MAX_PIXELS          = 8000 * 8000        # ~64 MP


def validate_image_upload(file_bytes: bytes, filename: str) -> Image.Image:
    """
    Validate uploaded file and return an RGB/RGBA PIL Image.

    Checks:
      - Extension is in allowed list
      - File can actually be decoded as an image
      - Image dimensions are within limits
      - File size is within limits

    Raises ValueError with a user-friendly message on failure.
    """
    # Size check
    if len(file_bytes) > MAX_IMAGE_BYTES:
        raise ValueError(
            f"Image file is too large ({len(file_bytes) / 1024 / 1024:.1f} MB). "
            f"Maximum allowed size is {MAX_IMAGE_BYTES // 1024 // 1024} MB."
        )

    # Extension check
    import os
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension '{ext}'. "
            f"Allowed formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )

    # Actual decode check
    try:
        image = Image.open(io.BytesIO(file_bytes))
        image.verify()          # verify does not load pixel data
    except Exception:
        raise ValueError(
            "The file could not be decoded as a valid image. "
            "Please upload a genuine PNG, BMP, or JPEG file."
        )

    # Re-open after verify (verify exhausts the stream)
    image = Image.open(io.BytesIO(file_bytes))
    image.load()

    # Dimension / pixel count check
    w, h = image.size
    if w * h > MAX_PIXELS:
        raise ValueError(
            f"Image is too large ({w}×{h} = {w*h:,} pixels). "
            f"Maximum is {MAX_PIXELS:,} pixels (~{int(MAX_PIXELS**0.5)}×{int(MAX_PIXELS**0.5)})."
        )

    # Normalise to RGB or RGBA
    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGB")

    return image


def image_info(image: Image.Image, filename: str = "") -> dict:
    """Return a dict of human-readable image metadata."""
    w, h = image.size
    from steganography import image_capacity_bytes
    cap = image_capacity_bytes(image)
    return {
        "filename": filename,
        "resolution": f"{w} × {h}",
        "mode": image.mode,
        "capacity_bytes": cap,
        "capacity_kb": cap / 1024,
    }
