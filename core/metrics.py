"""
core/metrics.py
---------------
Image fidelity and distortion metrics:
  - PSNR (Peak Signal-to-Noise Ratio)
  - SSIM (Structural Similarity Index)
  - MSE (Mean Squared Error)
  - Modified channel count and percentage
  - Amplified Difference Map generator
"""

import numpy as np
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio, structural_similarity


def to_rgb_array(image: Image.Image) -> np.ndarray:
    """Convert PIL image to uint8 RGB numpy array."""
    if image.mode != "RGB":
        image = image.convert("RGB")
    return np.array(image, dtype=np.uint8)


def compute_metrics(original: Image.Image, stego: Image.Image) -> dict:
    """
    Compute comprehensive fidelity metrics comparing the original cover image
    and the stego image.
    
    Returns a dict with:
        mse: Mean Squared Error
        psnr: PSNR in decibels (dB)
        ssim: SSIM index in [-1.0, 1.0]
        changed_channels: number of individual RGB channel bytes modified
        total_channels: total RGB channel bytes
        changed_pct: percentage of channels modified
    """
    orig_arr = to_rgb_array(original)
    stego_arr = to_rgb_array(stego)

    # Ensure identical shape
    if orig_arr.shape != stego_arr.shape:
        stego_arr = to_rgb_array(
            stego.resize((original.width, original.height), Image.LANCZOS)
        )

    # Compute MSE
    diff = orig_arr.astype(np.float64) - stego_arr.astype(np.float64)
    mse = float(np.mean(diff ** 2))

    # Compute PSNR
    if mse == 0.0:
        psnr = float("inf")
    else:
        psnr = float(peak_signal_noise_ratio(orig_arr, stego_arr, data_range=255))

    # Compute SSIM
    ssim = float(
        structural_similarity(orig_arr, stego_arr, channel_axis=2, data_range=255)
    )

    # Modified channel counts
    diff_mask = (orig_arr != stego_arr)
    changed_channels = int(np.count_nonzero(diff_mask))
    total_channels = int(orig_arr.size)
    changed_pct = (changed_channels / total_channels * 100.0) if total_channels > 0 else 0.0

    return {
        "mse": mse,
        "psnr": psnr,
        "ssim": ssim,
        "changed_channels": changed_channels,
        "total_channels": total_channels,
        "changed_pct": changed_pct,
    }


def compute_difference_map(original: Image.Image, stego: Image.Image, amplification: int = 50) -> Image.Image:
    """
    Generate an amplified visual difference map between original and stego images.
    Raw differences in LSB steganography are at most 1 unit per channel,
    which is virtually invisible to the naked eye. We amplify differences by
    a multiplier (default: 50x) and clip to 255.
    """
    orig_arr = to_rgb_array(original)
    stego_arr = to_rgb_array(stego)

    if orig_arr.shape != stego_arr.shape:
        stego_arr = to_rgb_array(
            stego.resize((original.width, original.height), Image.LANCZOS)
        )

    diff = np.abs(orig_arr.astype(np.int16) - stego_arr.astype(np.int16))
    amplified = np.clip(diff * amplification, 0, 255).astype(np.uint8)
    return Image.fromarray(amplified, mode="RGB")
