# StegoCrypt

> **Secure Image Steganography with AES-256-GCM Encryption**

StegoCrypt is a password-protected image steganography application that encrypts secret text messages using AES-256-GCM and hides the encrypted payload inside a PNG image using LSB (Least Significant Bit) steganography. The authorized receiver can extract and decrypt the original message using the correct password.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Features](#features)
- [Architecture](#architecture)
- [Encryption Workflow](#encryption-workflow)
- [Steganography Workflow](#steganography-workflow)
- [Decryption Workflow](#decryption-workflow)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Usage Guide](#usage-guide)
- [Why PNG?](#why-png)
- [AES-GCM Explained](#aes-gcm-explained)
- [LSB Explained](#lsb-explained)
- [PSNR Explained](#psnr-explained)
- [SSIM Explained](#ssim-explained)
- [Security Considerations](#security-considerations)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)

---

## Project Overview

StegoCrypt combines two complementary security techniques:

| Technique | Purpose |
|-----------|---------|
| **Steganography** | Hides the *existence* of the message inside an image |
| **Encryption** | Protects the *content* of the message with AES-256-GCM |

Even if an observer detects there is a hidden payload (by performing steganalysis), they cannot read the plaintext without the correct password — the ciphertext is protected by AES-256-GCM with a scrypt-derived key.

---

## Problem Statement

Transmitting sensitive information over digital channels poses two distinct risks:

1. **Interception** — an eavesdropper reads the message content.
2. **Detection** — an observer notices that a secret communication exists at all.

Standard encryption solves (1) but not (2). StegoCrypt addresses both by hiding encrypted data inside ordinary-looking images.

---

## Objectives

- Implement AES-256-GCM encryption with scrypt password-based key derivation.
- Implement LSB (Least Significant Bit) image steganography.
- Combine both techniques into a seamless, user-friendly desktop application.
- Provide image quality metrics (PSNR, SSIM) to verify minimal visual distortion.
- Support Unicode messages (English, Urdu, Arabic, emoji, etc.).

---

## Features

- **AES-256-GCM Encryption** with authenticated encryption (confidentiality + integrity).
- **scrypt Key Derivation** — password is never used directly as the AES key.
- **LSB Steganography** — modifies only the least significant bit of RGB channels.
- **Structured Binary Payload** with magic header, version, salt, nonce, and length metadata.
- **Capacity Validation** — prevents overflow with a clear error message.
- **PSNR & SSIM Metrics** — measures image quality degradation (typically negligible).
- **Unicode Support** — secret messages can be in any UTF-8 language or contain emoji.
- **Streamlit UI** — clean, professional dark-themed two-tab interface.
- **In-memory Processing** — no plaintext or passwords are written to disk.

---

## Architecture

```
Secret Text
    │
    ▼
AES-256-GCM  ◄── scrypt(password + salt) → 256-bit key
    │
    ▼
Encrypted Payload (STGC binary format)
    │
    ▼
LSB Embedding (modify RGB channel LSBs)
    │
    ▼
Stego PNG


Stego PNG
    │
    ▼
LSB Extraction (read RGB channel LSBs)
    │
    ▼
Encrypted Payload
    │
    ▼
AES-256-GCM  ◄── scrypt(password + salt from payload) → key
    │
    ▼
Secret Text
```

---

## Encryption Workflow

```
Secret Message (UTF-8 text)
         │
         ▼
    Validate input
         │
         ▼
    Generate random 16-byte salt
    Generate random 12-byte nonce
         │
         ▼
    scrypt(password, salt) → 256-bit AES key
         │
         ▼
    AES-256-GCM encrypt(key, nonce, plaintext)
         │
         ▼
    Build STGC binary payload:
      [STGC][v1][salt][nonce][length][ciphertext]
         │
         ▼
    Payload bytes
```

### STGC Binary Payload Format

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `STGC` ASCII header |
| Version | 1 byte | `0x01` |
| Salt | 16 bytes | Random scrypt salt |
| Nonce | 12 bytes | Random AES-GCM nonce |
| Length | 4 bytes | Ciphertext length (big-endian uint32) |
| Ciphertext | N bytes | AES-GCM ciphertext + 16-byte auth tag |

---

## Steganography Workflow

```
Cover Image (PNG/BMP/JPEG)
         │
         ▼
    Convert to RGB/RGBA array
         │
         ▼
    Check capacity: width × height × 3 ÷ 8 bytes
         │
         ▼
    Convert payload bytes → bit array
         │
         ▼
    For each payload bit:
      channel_byte = (channel_byte & 0xFE) | payload_bit
         │
         ▼
    Reconstruct image
         │
         ▼
    Save as PNG (lossless)
```

Only the R, G, B channels are modified. The alpha channel (if present) is left intact.

---

## Decryption Workflow

```
Stego PNG
         │
         ▼
    Read RGB channel LSBs
         │
         ▼
    Read fixed-size header (37 bytes)
         │
         ▼
    Validate magic header b'STGC'
    Extract: salt, nonce, ciphertext length
         │
         ▼
    Read exactly ciphertext_length bytes
         │
         ▼
    scrypt(password, salt) → 256-bit key
         │
         ▼
    AES-256-GCM decrypt(key, nonce, ciphertext)
    (fails cleanly if wrong password or corrupted data)
         │
         ▼
    Decode UTF-8 → Secret Text
```

---

## Installation

### Requirements

- Python 3.11 or newer
- pip

### Steps

```bash
# Clone or download the project
cd stegocrypt

# (Optional but recommended) Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

---

## How to Run

### Windows (easiest)

```
Double-click run.bat
```

Or from the terminal:

```bash
streamlit run app.py
```

Then open [http://localhost:8501](http://localhost:8501) in your browser.

### Run Tests

```bash
pytest tests/ -v
```

---

## Usage Guide

### Encrypt & Hide

1. Upload a **cover image** (PNG, BMP, or JPEG).
2. Type your **secret message** (any language, emoji supported).
3. Enter and confirm a **password** (minimum 8 characters; 12+ recommended).
4. Click **Encrypt & Hide in Image**.
5. Review PSNR/SSIM metrics and visual comparison.
6. Click **Download stegocrypt_output.png** to save the stego image.

### Extract & Decrypt

1. Upload the **stego PNG** file.
2. Enter the **same password** used during encryption.
3. Click **Extract & Decrypt Message**.
4. Read the recovered secret message.

---

## Why PNG?

JPEG uses *lossy compression* that permanently alters pixel values by large amounts — this destroys LSB-encoded data. PNG uses *lossless compression* that preserves every pixel value exactly. BMP is also lossless.

> **Rule:** Always share stego images as PNG. Never re-save them as JPEG.

---

## AES-GCM Explained

**AES-256-GCM** (Advanced Encryption Standard, Galois/Counter Mode) is a symmetric authenticated encryption scheme.

- **AES-256** — a 256-bit key provides 2²⁵⁶ possible keys; computationally infeasible to brute-force.
- **GCM (Galois/Counter Mode)** — provides both *confidentiality* (the message is unreadable without the key) and *integrity/authentication* (any tampering with the ciphertext causes decryption to fail).
- **scrypt Key Derivation** — the user's password is never used directly. Instead, scrypt derives a 256-bit key from the password and a random salt, making brute-force dictionary attacks expensive.
- **Random nonce** — a fresh 12-byte nonce is generated for every encryption, ensuring that encrypting the same message twice with the same password produces different ciphertext.

---

## LSB Explained

**LSB (Least Significant Bit) Steganography** hides data by replacing the lowest-order bit of each colour channel byte:

```
Original pixel channel byte:  1 1 0 1 0 1 1 0  (= 214)
                                               ↑
                                        LSB position

Secret bit to hide: 1

Modified byte:                1 1 0 1 0 1 1 1  (= 215)
```

The change from 214 to 215 is invisible to the human eye. Three RGB channels per pixel → 3 bits per pixel → `width × height × 3 / 8` bytes of capacity.

---

## PSNR Explained

**PSNR (Peak Signal-to-Noise Ratio)** measures the ratio of maximum possible signal power to noise power (distortion):

```
PSNR = 10 · log₁₀(MAX² / MSE)
```

where MAX = 255 (for 8-bit images) and MSE is the mean squared error between original and stego images.

- Higher PSNR → less distortion.
- Typical LSB steganography produces PSNR > 50 dB, which is negligible visually.

> ⚠️ Note: High PSNR and SSIM values *typically* indicate very small visual differences, but no single threshold guarantees perfect imperceptibility.

---

## SSIM Explained

**SSIM (Structural Similarity Index)** measures perceived image quality by comparing luminance, contrast, and structure between two images. Values range from -1 to 1; values close to 1 indicate very high similarity.

LSB steganography typically achieves SSIM ≥ 0.999, meaning the images are perceptually nearly identical.

---

## Security Considerations

| Consideration | StegoCrypt Approach |
|---------------|---------------------|
| Password storage | Never stored — exists only in memory during processing |
| Plaintext storage | Never written to disk — processed in memory |
| Key derivation | scrypt with random 16-byte salt (resistant to rainbow tables) |
| Nonce reuse | Fresh random 12-byte nonce per encryption — no reuse |
| Authentication | AES-GCM auth tag detects tampering or wrong password |
| Payload detection | Magic header `STGC` allows clean error on non-stego images |

**Security model:**
- **Steganography** hides the *existence* of the message.
- **Encryption** protects the *content* of the message.
- An attacker who extracts the payload cannot read the plaintext without the password (AES-256-GCM provides 256-bit security).

---

## Limitations

| Limitation | Details |
|------------|---------|
| Lossy compression destroys payload | Do not re-save the stego image as JPEG |
| Resizing destroys payload | Any image resize operation will corrupt embedded data |
| Editing destroys payload | Filters, colour adjustments, and cropping will corrupt data |
| Text only | This version hides UTF-8 text only, not binary files |
| Password loss | If the password is forgotten, the message cannot be recovered |
| Large payload requires large image | A 1 MP image holds ~375 KB; plan image size accordingly |
| No error correction | Bit errors cannot be corrected; payload is all-or-nothing |

---

## Future Improvements

The following features are not implemented in this version but could be added in future:

- **DCT-based steganography** — embeds in the frequency domain (more robust to JPEG compression).
- **Randomized embedding positions** — uses a PRNG seeded from the key to scatter bits pseudo-randomly.
- **Error-correcting codes (ECC)** — adds redundancy to recover from minor bit errors.
- **Binary file hiding** — support hiding any file type, not just text.
- **Multi-image payload splitting** — split a large payload across multiple carrier images.
- **Desktop executable** — package with PyInstaller for a standalone `.exe`.
- **Mobile app** — Kivy or React Native frontend with a Python backend.
- **Zstandard compression** — compress the plaintext before encryption to increase effective capacity.

---

## Project Structure

```
stegocrypt/
├── app.py              ← Streamlit UI entry point
├── crypto_utils.py     ← AES-256-GCM encryption / decryption
├── steganography.py    ← LSB embed / extract
├── metrics.py          ← PSNR, SSIM, difference visualization
├── validators.py       ← Image upload validation
├── conftest.py         ← pytest sys.path setup
├── requirements.txt    ← Python dependencies
├── README.md           ← This file
├── run.bat             ← Windows launch script
├── .gitignore
└── tests/
    ├── test_crypto.py          ← Crypto unit tests
    └── test_steganography.py   ← Steganography unit tests
```

---

*Built with Python · Streamlit · Pillow · NumPy · cryptography · scikit-image*
