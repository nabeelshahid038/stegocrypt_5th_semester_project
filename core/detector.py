"""
core/detector.py
----------------
Forensic Hidden-Data Detection & Statistical Steganalysis for StegoCrypt Pro.
Implements:
  1. Exact StegoCrypt signature & payload metadata verification (Category A).
  2. Generic Statistical Steganalysis:
     - LSB zero/one bit distribution & deviation from 50/50
     - Pairs of Values (PoVs) Chi-Square Test (Westfeld & Pfitzmann)
     - Channel and LSB-plane Shannon Entropy
  3. Bit-Plane extraction (Planes 0 to 7) for R, G, B channels
  4. Transparent heuristic suspicion score (0 to 100) and forensic verdict
No artificial intelligence, neural networks, or faked confidence scores.
"""

import math
import numpy as np
from PIL import Image
from scipy.stats import chi2
from dataclasses import dataclass, field
from core.steganography import check_stgc_signature, image_to_rgb_array
from core.payload import PayloadMetadata


@dataclass
class ChannelStats:
    channel_name: str
    zeros_count: int
    ones_count: int
    zeros_pct: float
    ones_pct: float
    dist_from_50: float  # abs(zeros_pct - 50.0)
    channel_entropy: float
    lsb_entropy: float
    chi2_stat: float
    chi2_pvalue: float
    chi2_dof: int


@dataclass
class DetectionReport:
    image_width: int
    image_height: int
    total_pixels: int
    color_mode: str
    
    # StegoCrypt Signature check
    stgc_detected: bool
    payload_metadata: PayloadMetadata | None
    
    # Statistical analysis per channel
    channels: dict[str, ChannelStats]
    
    # Composite metrics
    avg_dist_from_50: float
    avg_lsb_entropy: float
    avg_chi2_pvalue: float
    
    # Forensic score and verdict
    suspicion_score: int          # 0 to 100
    verdict_category: str        # Category A, Category B, or Category C
    verdict_title: str
    verdict_description: str
    evidence_points: list[str] = field(default_factory=list)


def compute_shannon_entropy(values: np.ndarray, num_bins: int = 256) -> float:
    """
    Calculate Shannon entropy H = -sum(p * log2(p)) for an integer array.
    """
    if len(values) == 0:
        return 0.0
    counts = np.bincount(values.reshape(-1), minlength=num_bins)
    total = len(values.reshape(-1))
    probs = counts / total
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def compute_lsb_entropy(lsb_bits: np.ndarray) -> tuple[int, int, float, float, float, float]:
    """
    Compute zero/one counts, percentages, deviation from 50/50, and LSB entropy.
    Returns:
        (zeros_count, ones_count, zeros_pct, ones_pct, dist_from_50, lsb_entropy)
    """
    total = len(lsb_bits)
    if total == 0:
        return 0, 0, 0.0, 0.0, 0.0, 0.0
    ones = int(np.count_nonzero(lsb_bits))
    zeros = total - ones

    zeros_pct = (zeros / total) * 100.0
    ones_pct = (ones / total) * 100.0
    dist_from_50 = abs(zeros_pct - 50.0)

    p0 = zeros / total
    p1 = ones / total
    entropy = 0.0
    if p0 > 0:
        entropy -= p0 * math.log2(p0)
    if p1 > 0:
        entropy -= p1 * math.log2(p1)

    return zeros, ones, zeros_pct, ones_pct, dist_from_50, float(entropy)


def compute_pairs_of_values_chisquare(channel: np.ndarray) -> tuple[float, float, int]:
    """
    Westfeld & Pfitzmann (1999) Chi-Square attack on LSB steganography.
    Analyzes Pairs of Values (PoVs) (2k, 2k+1).
    Under LSB substitution with uniform pseudo-random ciphertext,
    the counts of adjacent values 2k and 2k+1 equalize.
    
    Returns:
        (chi2_statistic: float, p_value: float, degrees_of_freedom: int)
    """
    counts = np.bincount(channel.reshape(-1), minlength=256)
    chi2_stat = 0.0
    dof = 0

    for k in range(128):
        h_even = counts[2 * k]
        h_odd = counts[2 * k + 1]
        pair_sum = h_even + h_odd
        if pair_sum > 0:
            expected = pair_sum / 2.0
            chi2_stat += ((h_even - expected) ** 2) / expected + ((h_odd - expected) ** 2) / expected
            dof += 1

    dof = max(1, dof - 1)
    # p-value: probability of observing such a chi2 statistic under the null hypothesis (equalized pairs)
    # When LSB substitution occurs, chi2 is small and p-value is close to 1.0.
    # In untouched natural images, pair counts vary significantly, chi2 is large and p-value is close to 0.0.
    p_val = float(chi2.sf(chi2_stat, dof))
    return float(chi2_stat), p_val, dof


def extract_bit_plane(image: Image.Image, channel_index: int, bit_index: int) -> Image.Image:
    """
    Extract bit plane `bit_index` (0=LSB, 7=MSB) from channel `channel_index` (0=R, 1=G, 2=B).
    Returns a black & white (mode 'L') PIL Image.
    """
    if not (0 <= channel_index <= 2):
        raise ValueError("channel_index must be 0 (R), 1 (G), or 2 (B).")
    if not (0 <= bit_index <= 7):
        raise ValueError("bit_index must be between 0 (LSB) and 7 (MSB).")

    arr, _ = image_to_rgb_array(image)
    ch = arr[:, :, channel_index]
    bit_plane = ((ch >> bit_index) & 1).astype(np.uint8) * 255
    return Image.fromarray(bit_plane, mode="L")


def analyze_image(image: Image.Image) -> DetectionReport:
    """
    Perform complete forensic scan of an image for hidden data:
      1. Check for StegoCrypt signature and parse header.
      2. Perform channel-wise statistical analysis (LSB ratio, Chi-Square PoV, Entropy).
      3. Compute transparent heuristic suspicion score and forensic verdict.
    """
    w, h = image.size
    total_pixels = w * h
    arr, orig_mode = image_to_rgb_array(image)

    # 1. StegoCrypt Signature check
    stgc_detected, meta = check_stgc_signature(image)

    # 2. Statistical analysis per channel (R, G, B)
    channel_names = ["Red", "Green", "Blue"]
    channels_dict: dict[str, ChannelStats] = {}

    dists_from_50 = []
    lsb_entropies = []
    chi2_pvals = []

    for idx, name in enumerate(channel_names):
        ch = arr[:, :, idx]
        ch_entropy = compute_shannon_entropy(ch, 256)
        lsb_bits = (ch & 1).reshape(-1)

        zeros, ones, zeros_pct, ones_pct, dist_50, lsb_ent = compute_lsb_entropy(lsb_bits)
        chi_stat, p_val, dof = compute_pairs_of_values_chisquare(ch)

        dists_from_50.append(dist_50)
        lsb_entropies.append(lsb_ent)
        chi2_pvals.append(p_val)

        channels_dict[name] = ChannelStats(
            channel_name=name,
            zeros_count=zeros,
            ones_count=ones,
            zeros_pct=zeros_pct,
            ones_pct=ones_pct,
            dist_from_50=dist_50,
            channel_entropy=ch_entropy,
            lsb_entropy=lsb_ent,
            chi2_stat=chi_stat,
            chi2_pvalue=p_val,
            chi2_dof=dof,
        )

    avg_dist_50 = float(np.mean(dists_from_50))
    avg_lsb_ent = float(np.mean(lsb_entropies))
    avg_chi_p = float(np.mean(chi2_pvals))

    evidence: list[str] = []

    # 3. Determine Verdict & Suspicion Score
    if stgc_detected and meta is not None:
        suspicion_score = 100
        verdict_category = "Category A"
        verdict_title = "CONFIRMED STEGOCRYPT PAYLOAD"
        verdict_desc = (
            f"The image contains a verified StegoCrypt cryptographic signature (STGC) "
            f"with format version {meta.version}. A structured, authenticated ciphertext "
            f"payload of approximately {meta.ciphertext_length:,} bytes is embedded inside. "
            f"Vault extraction requires the correct password."
        )
        evidence.append(f"STGC magic signature found at image bitstream offset 0.")
        evidence.append(f"Payload format version: {meta.version} ({'Vault Package' if meta.is_vault else 'Legacy Message'}).")
        evidence.append(f"Ciphertext length: {meta.ciphertext_length:,} bytes ({meta.ciphertext_length / 1024:.1f} KB).")
        if meta.is_compressed:
            evidence.append("Compressed payload flag: Enabled (DEFLATE).")
        if meta.has_files:
            evidence.append("Vault files flag: One or more attached files present.")
        if meta.has_text:
            evidence.append("Secret text flag: Text message present.")
    else:
        # Generic Statistical Steganalysis
        # Heuristic points calculation based on physical phenomena:
        # Point 1: LSB Bit Balance (max 35 points)
        # Random encrypted data forces balance within ~0.2% of 50.0%. Natural images typically have > 1.0% bias.
        score_balance = 0
        if avg_dist_50 < 0.2:
            score_balance = 35
            evidence.append(f"LSB bit balance across RGB channels is extremely close to 50/50 (average deviation: {avg_dist_50:.3f}%).")
        elif avg_dist_50 < 0.6:
            score_balance = 25
            evidence.append(f"LSB bit balance exhibits low deviation from 50/50 ({avg_dist_50:.2f}%).")
        elif avg_dist_50 < 1.2:
            score_balance = 10
        else:
            evidence.append(f"LSB bit balance shows natural bias (average deviation from 50%: {avg_dist_50:.2f}%).")

        # Point 2: LSB Plane Shannon Entropy (max 35 points)
        # Purely encrypted binary payload has entropy H ~= 1.00000.
        score_entropy = 0
        if avg_lsb_ent >= 0.9998:
            score_entropy = 35
            evidence.append(f"LSB plane Shannon entropy is near maximum ({avg_lsb_ent:.5f} / 1.00000), indicative of high-randomness ciphertext.")
        elif avg_lsb_ent >= 0.998:
            score_entropy = 20
            evidence.append(f"LSB plane Shannon entropy is elevated ({avg_lsb_ent:.4f} / 1.00000).")
        elif avg_lsb_ent >= 0.990:
            score_entropy = 10
        else:
            evidence.append(f"LSB plane Shannon entropy is normal for natural textures ({avg_lsb_ent:.4f}).")

        # Point 3: Pairs of Values Chi-Square Equalization (max 30 points)
        # When LSB substitution equalizes pairs, p-value approaches 1.0.
        score_chi = 0
        if avg_chi_p >= 0.95:
            score_chi = 30
            evidence.append(f"Pairs-of-Values (PoVs) Chi-Square test indicates significant equalization of adjacent value pairs (p-value: {avg_chi_p:.4f}).")
        elif avg_chi_p >= 0.70:
            score_chi = 15
            evidence.append(f"Pairs-of-Values Chi-Square test shows moderate pairing regularity (p-value: {avg_chi_p:.4f}).")
        else:
            evidence.append(f"Pairs-of-Values Chi-Square distribution aligns with natural image patterns (p-value: {avg_chi_p:.4f}).")

        suspicion_score = min(100, score_balance + score_entropy + score_chi)

        if suspicion_score >= 60:
            verdict_category = "Category B"
            verdict_title = "SUSPICIOUS — POSSIBLE HIDDEN DATA"
            verdict_desc = (
                "The image does not contain a recognized StegoCrypt payload signature. "
                "However, multiple statistical indicators (LSB distribution balance, elevated plane entropy, "
                "or PoV pair equalization) diverge from typical natural image characteristics. "
                "This may indicate hidden steganographic data, heavy noise injection, "
                "synthetic rendering, or specific lossy-to-lossless conversions. "
                "Classified as Suspicious, not confirmed."
            )
        else:
            verdict_category = "Category C"
            verdict_title = "NO STRONG EVIDENCE FOUND"
            verdict_desc = (
                "The scan detected no StegoCrypt header signature, and generic statistical "
                "steganalysis found no compelling evidence of widespread LSB manipulation. "
                "Bit distribution, entropy, and pair values are consistent with natural image characteristics. "
                "Note: Highly localized or novel steganographic algorithms cannot be universally ruled out."
            )

    return DetectionReport(
        image_width=w,
        image_height=h,
        total_pixels=total_pixels,
        color_mode=orig_mode,
        stgc_detected=stgc_detected,
        payload_metadata=meta,
        channels=channels_dict,
        avg_dist_from_50=avg_dist_50,
        avg_lsb_entropy=avg_lsb_ent,
        avg_chi2_pvalue=avg_chi_p,
        suspicion_score=suspicion_score,
        verdict_category=verdict_category,
        verdict_title=verdict_title,
        verdict_description=verdict_desc,
        evidence_points=evidence,
    )
