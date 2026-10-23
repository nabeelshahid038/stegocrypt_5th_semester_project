# StegoCrypt Pro
## Secure Secret Vault Steganography & Forensic Hidden-Data Detection

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Cryptography](https://img.shields.io/badge/AES--256--GCM-scrypt-green.svg)](https://cryptography.io/)
[![Steganography](https://img.shields.io/badge/LSB-Vectorized%20NumPy-orange.svg)](https://numpy.org/)
[![Steganalysis](https://img.shields.io/badge/Chi--Square%20PoV-Shannon%20Entropy-purple.svg)](https://scipy.org/)
[![Status](https://img.shields.io/badge/Tests-49%20Passed-brightgreen.svg)]()

**StegoCrypt Pro** is a cryptographic security and forensic image analysis suite. It allows users to package confidential text messages and multiple arbitrary binary files (PDFs, images, documents, archives) into an in-memory compressed, AES-256-GCM encrypted **Secret Vault**, and seamlessly conceal it within ordinary images using Least Significant Bit (LSB) steganography.

In addition, StegoCrypt Pro includes a **Forensic Steganalysis Engine** that inspects unknown images for exact StegoCrypt cryptographic signatures and performs generic statistical steganalysis (Pairs-of-Values Chi-Square test, Shannon entropy, bit balance analysis, and interactive bit-plane visualization) without relying on black-box machine learning or faked confidence metrics.

---

## 📑 Table of Contents
1. [Project Overview](#project-overview)
2. [Problem Statement & Objectives](#problem-statement--objectives)
3. [Architecture & Workflow](#architecture--workflow)
4. [Secret Vault Architecture](#secret-vault-architecture)
5. [Cryptographic Design (AES-256-GCM + scrypt)](#cryptographic-design)
6. [Spatial LSB Steganography](#spatial-lsb-steganography)
7. [Structured Binary Payload (STGC v2)](#structured-binary-payload-stgc-v2)
8. [Forensic Hidden-Data Detection Engine](#forensic-hidden-data-detection-engine)
   - [Level 1: Exact Signature Verification](#level-1-exact-signature-verification)
   - [Level 2: Pairs-of-Values (PoVs) Chi-Square Analysis](#level-2-pairs-of-values-povs-chi-square-analysis)
   - [Level 3: Multi-Channel Shannon Entropy](#level-3-multi-channel-shannon-entropy)
   - [Visual Bit-Plane Inspector (Planes 0 to 7)](#visual-bit-plane-inspector)
9. [Fidelity & Quality Metrics (PSNR & SSIM)](#fidelity--quality-metrics-psnr--ssim)
10. [Security & Path-Traversal Protection](#security--path-traversal-protection)
11. [Installation & Quickstart](#installation--quickstart)
12. [Running the Test Suite](#running-the-test-suite)
13. [Limitations & Forensic Disclaimers](#limitations--forensic-disclaimers)
14. [Future Work](#future-work)

---

## 1. Project Overview

StegoCrypt Pro addresses the dual challenge of secure covert communication and digital image forensics:
1. **Creation & Concealment:** Securely aggregate heterogeneous data (text + multiple files) into an encrypted container hidden in pixel color channels.
2. **Extraction & Verification:** Authenticate and restore the vault bit-for-bit with SHA-256 integrity validation.
3. **Forensic Detection:** Inspect suspicious images using scientific, deterministic statistical methods to determine whether covert data is present.

---

## 2. Problem Statement & Objectives

- **The Problem with Raw Encryption:** Standard ciphertext stands out in network traffic or on disk, signaling to censors or adversaries that valuable secrets exist.
- **The Problem with Naive Steganography:** Hiding plaintext directly inside images is insecure against extraction attacks, and delimiter markers (e.g., `###END###`) cause parsing bugs or false positives.
- **The Problem with Black-Box "AI" Steganalysis:** Machine learning detectors often hallucinate false positives, overfit on training datasets, and provide no mathematical transparency.
- **The Solution:** Combine authenticated AES-256-GCM encryption, scrypt KDF, delimiter-free structured binary packaging, and mathematically grounded steganalysis (Chi-Square PoVs and Shannon entropy).

---

## 3. Architecture & Workflow

```
CREATE SECRET VAULT:
Secret Text + Files (PDF, PNG, TXT, DOCX, ZIP)
        ↓
In-Memory ZIP Package (with metadata.json)
        ↓
DEFLATE Level 9 Compression
        ↓
Key Derivation: scrypt(Password, Salt, N=16384, r=8, p=1)
        ↓
AES-256-GCM Authenticated Encryption (+ 16-byte Auth Tag)
        ↓
Structured Binary Payload (b'STGC' + v02 + Flags + Salt + Nonce + Length uint64)
        ↓
Vectorized LSB Substitution (RGB channels only; Alpha preserved)
        ↓
Lossless PNG Output (stegocrypt_vault.png)

OPEN SECRET VAULT:
Stego PNG Image
        ↓
Read STGC Header (Signature & Bitstream Length)
        ↓
Extract Exact Ciphertext Bits
        ↓
Key Derivation via scrypt(Password, Extracted Salt)
        ↓
AES-256-GCM Authenticated Decryption
        ↓
In-Memory Decompression & Path-Traversal Sanitization
        ↓
Recover Original Text & Files (with SHA-256 Verification)

DETECT HIDDEN DATA:
Unknown Image (PNG, BMP, JPEG)
        ↓
Level 1: StegoCrypt Signature Verification (STGC Header)
        ↓
Level 2: Pairs-of-Values (PoVs) Chi-Square Attack
        ↓
Level 3: Multi-Channel & LSB-Plane Shannon Entropy
        ↓
Level 4: LSB Zero/One Distribution & Balance Deviation
        ↓
Transparent Heuristic Suspicion Score (0 - 100)
        ↓
Verdict: Category A / Category B / Category C
```

---

## 4. Secret Vault Architecture

StegoCrypt Pro bundles secrets into a self-contained in-memory archive:
```
Vault
├── metadata.json       # Creation timestamp, version, file records, SHA-256 hashes
├── message.txt         # Secret text message (if provided)
└── files/
    ├── report.pdf      # Attached binary files
    ├── photo.png
    └── notes.txt
```
- **In-Memory Only:** Utilizes `io.BytesIO` and `zipfile.ZipFile(compression=zipfile.ZIP_DEFLATED, compresslevel=9)`.
- **Zero Plaintext Disk Writes:** Unlocked files and archives are generated directly in memory buffers.

---

## 5. Cryptographic Design

- **Cipher:** AES-256 in Galois/Counter Mode (GCM).
- **Key Derivation Function (KDF):** `scrypt` with parameters:
  - $N = 16,384$ ($2^{14}$ CPU/memory cost)
  - $r = 8$ (block size factor)
  - $p = 1$ (parallelization)
  - Derived Key Length = 32 bytes (256 bits)
- **Random Salt:** 16 bytes generated cryptographically (`os.urandom(16)`).
- **Nonce:** 12 bytes generated cryptographically (`os.urandom(12)`).
- **Password Normalization:** Unicode NFKC normalization prior to UTF-8 encoding.
- **Authentication:** AES-GCM 16-byte authentication tag guarantees confidentiality and integrity. If an incorrect password or modified image byte is supplied, decryption fails cleanly with `InvalidTag` and displays:
  > *"Unable to unlock vault. Incorrect password or corrupted data."*

---

## 6. Spatial LSB Steganography

- **Channel Isolation:** Only Red, Green, and Blue channels are used. Alpha transparency channels (in RGBA images) are left untouched to avoid transparency distortions.
- **Substitution Formula:**
  $$\text{Pixel}_{\text{new}} = (\text{Pixel}_{\text{old}} \ \& \ \text{0xFE}) \ | \ \text{SecretBit}$$
- **Vectorized Embedding:** Executed via NumPy bitwise SIMD operations for instantaneous processing across multi-megapixel images.
- **Format Guarantee:** Cover images may be uploaded as PNG, BMP, or JPEG (converted to RGB/RGBA internally). Stego output is **always exported as lossless PNG** because lossy compression (such as JPEG's Discrete Cosine Transform quantization) alters pixel values and corrupts LSB bitstreams.

---

## 7. Structured Binary Payload (STGC v2)

StegoCrypt Pro rejects delimiter strings (e.g., `###END###`) because encrypted ciphertext is arbitrary binary data that can naturally contain any sequence of bytes. Instead, a strict, length-prefixed header is used:

### Header Layout (Version 2 — 42 bytes fixed):
| Offset | Field | Size | Data Type | Purpose |
|---|---|---|---|---|
| `0..3` | Magic Header | 4 bytes | `b'STGC'` | Exact StegoCrypt signature |
| `4` | Version | 1 byte | `0x02` | Format version identifier |
| `5` | Flags | 1 byte | `uint8` bitmask | Bit 0: Compressed, Bit 1: Vault, Bit 2: Files, Bit 3: Text |
| `6..21` | Salt | 16 bytes | raw bytes | scrypt key derivation salt |
| `22..33`| Nonce | 12 bytes | raw bytes | AES-GCM nonce |
| `34..41`| Ciphertext Length | 8 bytes | `uint64` (big-endian `>Q`) | Exact payload byte count |
| `42..N` | Ciphertext | Variable | raw bytes | Encrypted vault archive + 16-byte GCM auth tag |

*Note: StegoCrypt Pro includes backward compatibility to read Version 1 (37-byte legacy headers with uint32 lengths).*

---

## 8. Forensic Hidden-Data Detection Engine

The forensic module inspects images without relying on opaque machine learning:

### Level 1: Exact Signature Verification
- Evaluates the initial 32 bits of the image's RGB LSB bitstream for `b'STGC'`.
- If present and valid, parses the header and issues:
  - **Verdict:** `Category A: CONFIRMED STEGOCRYPT PAYLOAD`
  - **Suspicion Score:** `100 / 100`
  - **Metadata:** Format version, vault flag, compression flag, file count flag, and exact embedded ciphertext size.

### Level 2: Pairs-of-Values (PoVs) Chi-Square Analysis
- Based on the seminal research by **Westfeld & Pfitzmann (1999)**.
- Spatial LSB replacement swaps values between adjacent pairs of values $(2k, 2k+1)$.
- As embedding increases, the observed counts of $2k$ and $2k+1$ equalize toward their average $E_k = \frac{h(2k) + h(2k+1)}{2}$.
- Chi-square statistic:
  $$\chi^2 = \sum_{k=0}^{127} \frac{(h(2k) - h(2k+1))^2}{2 E_k}$$
- Under the null hypothesis of equalized pairs (LSB steganography present), $\chi^2$ drops and the $p$-value approaches $1.0$.

### Level 3: Multi-Channel Shannon Entropy
- Measures informational disorder across each RGB channel and isolated LSB planes:
  $$H = -\sum_{i} p_i \log_2(p_i)$$
- In natural images, LSB planes exhibit correlations with surrounding textures ($H_{LSB} \approx 0.95 - 0.99$).
- Encrypted binary data acts as a uniform Bernoulli process with $p \approx 0.5$, producing $H_{LSB} \approx 1.0000$ bits/pixel.

### Visual Bit-Plane Inspector
- Renders individual bit planes ($0$ to $7$) for Red, Green, and Blue channels as black-and-white visual maps.
- Allows visual inspection of high-frequency noise patterns in Bit Plane 0 (LSB).

### Forensic Verdict Categories:
- **Category A:** `CONFIRMED STEGOCRYPT PAYLOAD` (Signature confirmed).
- **Category B:** `SUSPICIOUS — POSSIBLE HIDDEN DATA` (Suspicion score $\ge 60$ based on statistical anomalies).
- **Category C:** `NO STRONG EVIDENCE FOUND` (Suspicion score $< 60$).

---

## 9. Fidelity & Quality Metrics

- **Peak Signal-to-Noise Ratio (PSNR):**
  $$MSE = \frac{1}{3 W H} \sum_{x,y,c} (I_{\text{orig}}(x,y,c) - I_{\text{stego}}(x,y,c))^2$$
  $$PSNR = 10 \cdot \log_{10}\left(\frac{255^2}{MSE}\right)$$
  Typical StegoCrypt Pro outputs yield **$55 - 65$ dB**, indicating imperceptible differences.
- **Structural Similarity Index (SSIM):**
  $$SSIM(x,y) = \frac{(2\mu_x\mu_y + C_1)(2\sigma_{xy} + C_2)}{(\mu_x^2 + \mu_y^2 + C_1)(\sigma_x^2 + \sigma_y^2 + C_2)}$$
  Typical outputs yield **$\ge 0.9999$**.
- **Amplified Difference Map:** Computes $|I_{\text{orig}} - I_{\text{stego}}| \times 50$, highlighting modified pixels.

---

## 10. Security & Path-Traversal Protection

- **ZIP Path Traversal Prevention:** Any filename containing `../`, `..\`, absolute root slashes, or Windows drive paths (e.g. `../../evil.exe`) is strictly sanitized using `os.path.basename` and regex scrubbing.
- **SHA-256 Hash Integrity:** Pre-embedding and post-extraction hashes are computed and verified to guarantee zero byte corruption.
- **Memory Safety:** Decryption and extraction operate strictly in volatile memory.

---

## 11. Installation & Quickstart

### Prerequisites
- Python 3.11 or higher
- Windows, macOS, or Linux

### Installation
```bash
# Clone or navigate to the repository
cd stegocrypt

# Install dependencies
python -m pip install -r requirements.txt
```

### Running the Application
**On Windows:**
Double-click `run.bat` or run:
```powershell
python -m streamlit run app.py
```

---

## 12. Running the Test Suite

Execute the comprehensive test suite (49 automated unit and end-to-end integration tests):
```powershell
python -m pytest tests -v
```

All tests verify:
- In-memory ZIP packaging and extraction
- Directory traversal attack mitigation
- Unicode (English, Urdu, Arabic, Sindhi, Emoji) preservation
- scrypt key derivation and AES-256-GCM encryption/decryption
- Wrong-password rejection
- STGC v2 payload packing and v1 legacy backwards compatibility
- Vectorized LSB embedding and RGBA alpha preservation
- Chi-Square PoV and Shannon Entropy calculations
- End-to-End Master Demo (Section 68 of specification)

---

## 13. Limitations & Forensic Disclaimers

1. **Format Specificity:** StegoCrypt payloads can be reliably identified by their cryptographic header. However, unknown or custom third-party steganography cannot be universally detected.
2. **Statistical Steganalysis Constraints:** Generic statistical steganalysis produces evidence, not guaranteed proof. Natural camera noise, image editing, sharpening filters, or synthetic rendering may trigger false positives or false negatives.
3. **Lossy Compression Vulnerability:** Converting a stego image to JPEG, WebP, or sending it via platforms that compress images (e.g., standard WhatsApp, Discord) will destroy LSB payload data. Stego images must be transmitted losslessly as PNG.

---

## 14. Future Work

The following enhancements may be explored in future releases:
- Frequency-domain steganography (Discrete Cosine Transform / Discrete Wavelet Transform) for lossy compression resilience.
- Error-Correcting Codes (Reed-Solomon / LDPC) for noise tolerance.
- Asymmetric public-key authentication (ECDSA / Ed25519) for signed vaults.
- Mobile companion application and browser extension.
