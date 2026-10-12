"""
metrics.py
----------
Image quality metrics:
  - PSNR (Peak Signal-to-Noise Ratio)
  - SSIM (Structural Similarity Index)
"""

import numpy as np
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio, structural_similarity


def _to_rgb_array(image: Image.Image) -> np.ndarray:
    """Convert PIL image to uint8 RGB numpy array."""
    if image.mode != "RGB":
        image = image.convert("RGB")
    return np.array(image, dtype=np.uint8)


def compute_psnr(original: Image.Image, stego: Image.Image) -> float:
    """
    Compute PSNR between the original cover image and the stego image.

    Higher values → less distortion.
    A value of inf means the images are identical.
    """
    orig_arr  = _to_rgb_array(original)
    stego_arr = _to_rgb_array(stego)

    if orig_arr.shape != stego_arr.shape:
        # Resize stego to match original if shapes differ
        stego_arr = _to_rgb_array(
            stego.resize((original.width, original.height), Image.LANCZOS)
        )

    return float(peak_signal_noise_ratio(orig_arr, stego_arr, data_range=255))


def compute_ssim(original: Image.Image, stego: Image.Image) -> float:
    """
    Compute SSIM between original and stego images.

    Returns a value in [-1, 1]. Values close to 1 indicate high similarity.
    """
    orig_arr  = _to_rgb_array(original)
    stego_arr = _to_rgb_array(stego)

    if orig_arr.shape != stego_arr.shape:
        stego_arr = _to_rgb_array(
            stego.resize((original.width, original.height), Image.LANCZOS)
        )

    return float(
        structural_similarity(orig_arr, stego_arr, channel_axis=2, data_range=255)
    )


def compute_difference_image(original: Image.Image, stego: Image.Image) -> Image.Image:
    """
    Return an amplified pixel-difference image for visualization.

    Raw differences are typically invisible (1-bit change), so we amplify
    by a factor of 50 to make them visible for educational purposes.
    """
    orig_arr  = _to_rgb_array(original)
    stego_arr = _to_rgb_array(stego)

    if orig_arr.shape != stego_arr.shape:
        stego_arr = _to_rgb_array(
            stego.resize((original.width, original.height), Image.LANCZOS)
        )

    diff = np.abs(orig_arr.astype(np.int16) - stego_arr.astype(np.int16))
    amplified = np.clip(diff * 50, 0, 255).astype(np.uint8)
    return Image.fromarray(amplified, mode="RGB")
