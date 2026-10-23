"""
app.py
------
StegoCrypt Pro — Secure Secret Vault Steganography & Hidden-Data Detection.
Desktop & Web application built with Streamlit.
"""

import io
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import streamlit as st
from PIL import Image

from core.crypto import (
    validate_password,
    password_strength,
    encrypt_bytes,
    decrypt_bytes,
)
from core.vault import (
    create_vault,
    extract_vault,
    VaultContent,
    sanitize_filename,
)
from core.payload import (
    pack_payload_v2,
    parse_header,
    FLAG_COMPRESSED,
    FLAG_VAULT,
    FLAG_FILES_PRESENT,
    FLAG_TEXT_PRESENT,
)
from core.steganography import (
    calculate_capacity,
    embed_payload,
    extract_payload,
    check_stgc_signature,
)
from core.metrics import (
    compute_metrics,
    compute_difference_map,
)
from core.validators import (
    validate_image_upload,
    validate_vault_files,
    MAX_IMAGE_BYTES,
)
from core.detector import (
    analyze_image,
    extract_bit_plane,
)

# ── Streamlit Page Configuration ──────────────────────────────────────────────
st.set_page_config(
    page_title="StegoCrypt Pro — Secret Vaults & Detection",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS for Polished Dark UI ───────────────────────────────────────────
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #8b5cf6, #3b82f6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .subtitle {
        color: #94a3b8;
        font-size: 1.05rem;
        margin-bottom: 1.2rem;
    }
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    .metric-val {
        font-size: 1.5rem;
        font-weight: 700;
        color: #f8fafc;
    }
    .metric-lbl {
        font-size: 0.8rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .verdict-box {
        border-radius: 12px;
        padding: 18px 22px;
        margin: 16px 0;
    }
    .verdict-cat-a {
        background: linear-gradient(135deg, #064e3b, #0f172a);
        border: 2px solid #10b981;
    }
    .verdict-cat-b {
        background: linear-gradient(135deg, #78350f, #0f172a);
        border: 2px solid #f59e0b;
    }
    .verdict-cat-c {
        background: linear-gradient(135deg, #1e3a8a, #0f172a);
        border: 2px solid #3b82f6;
    }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔐 StegoCrypt Pro")
    st.caption("Version 2.0.0 — Production Release")
    st.markdown("---")
    st.markdown("""
    **Core Capabilities:**
    - 📦 Multi-file Secret Vaults
    - 🔒 AES-256-GCM + scrypt KDF
    - 🖼️ Lossless LSB Image Steganography
    - 🕵️ Statistical Steganalysis
    - 📊 Chi-Square PoV & Shannon Entropy
    - 👁️ Visual Bit-Plane Inspector
    """)
    st.markdown("---")
    st.info("💡 **Security Tip:** Lossy formats like JPEG destroy LSB data during compression. Stego images must always be exported and stored as **PNG**.")


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown('<div class="main-title">StegoCrypt Pro</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Secure Secret Vaults Hidden Inside Images & Forensic Steganalysis</div>', unsafe_allow_html=True)
st.markdown("Encrypt text and files, hide them inside ordinary images, recover them with a password, or inspect unknown images for signs of hidden data.")

# ── Tabs Navigation ───────────────────────────────────────────────────────────
tab_create, tab_open, tab_detect, tab_help = st.tabs([
    "🔐 Create Secret Vault",
    "🔓 Open Secret Vault",
    "🕵️ Detect Hidden Data",
    "ℹ️ How It Works",
])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: CREATE SECRET VAULT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_create:
    st.header("🔐 Create Secret Vault & Embed into Image")
    st.markdown("Package secret text and attached files into a compressed, AES-256-GCM encrypted vault, then conceal it within a cover image.")

    col_cov, col_vlt = st.columns([1, 1], gap="large")

    with col_cov:
        st.subheader("1. Cover Image")
        cover_file = st.file_uploader(
            "Upload Cover Image (PNG, BMP, or JPEG)",
            type=["png", "bmp", "jpg", "jpeg"],
            key="cover_uploader",
            help="Images are internally converted to RGB/RGBA; output is always saved as lossless PNG.",
        )

        cover_img: Image.Image | None = None
        cap_info: dict | None = None

        if cover_file is not None:
            try:
                cover_img = validate_image_upload(cover_file.getvalue(), cover_file.name)
                cap_info = calculate_capacity(cover_img)
                st.image(cover_img, caption=f"Cover Image: {cover_file.name} ({cover_img.width}×{cover_img.height})", use_container_width=True)

                mcol1, mcol2, mcol3 = st.columns(3)
                with mcol1:
                    st.metric("Resolution", f"{cover_img.width} × {cover_img.height}")
                with mcol2:
                    st.metric("Color Mode", cover_img.mode)
                with mcol3:
                    st.metric("Max Capacity", f"{cap_info['capacity_kb']:.1f} KB")
            except Exception as e:
                st.error(f"Image Error: {e}")
                cover_img = None

    with col_vlt:
        st.subheader("2. Vault Contents & Security")
        secret_text = st.text_area(
            "Secret Message (Optional if files attached):",
            placeholder="Type your confidential message, notes, or credentials here... (Supports Unicode, Urdu, Arabic, Emoji 🔐)",
            height=120,
        )

        vault_files_uploaded = st.file_uploader(
            "Attach Secret Files (TXT, PDF, PNG, JPG, JSON, ZIP, DOCX, etc.):",
            accept_multiple_files=True,
            key="vault_files_uploader",
        )

        st.subheader("3. Encryption Password")
        pass_col1, pass_col2 = st.columns(2)
        with pass_col1:
            pwd = st.text_input("Password", type="password", key="create_pwd", placeholder="Min 8 chars (12+ recommended)")
        with pass_col2:
            pwd_confirm = st.text_input("Confirm Password", type="password", key="create_pwd_confirm")

        if pwd:
            strength = password_strength(pwd)
            st.caption(f"Password Strength: **{strength['label']}**")
            st.progress(strength["score"] / 100)

    # ── Live Vault Preview ─────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("4. Vault Capacity & Pre-flight Inspection")

    files_to_embed: list[tuple[str, bytes]] = []
    if vault_files_uploaded:
        for f in vault_files_uploaded:
            files_to_embed.append((f.name, f.getvalue()))

    has_content = bool(secret_text and secret_text.strip()) or bool(files_to_embed)

    if has_content:
        # Pre-calculate compressed size
        try:
            sample_zip, sample_content = create_vault(message=secret_text, files=files_to_embed)
            est_cipher_len = len(sample_zip) + 16  # AES-GCM tag
            est_total_payload = 42 + est_cipher_len

            pcol1, pcol2, pcol3, pcol4 = st.columns(4)
            with pcol1:
                st.metric("Original Size", f"{sample_content.original_size / 1024:.1f} KB")
            with pcol2:
                st.metric("Compressed Vault", f"{sample_content.compressed_size / 1024:.1f} KB", delta=f"-{sample_content.compression_saved_pct:.1f}%")
            with pcol3:
                st.metric("Encrypted Payload", f"{est_total_payload / 1024:.1f} KB")
            with pcol4:
                if cap_info:
                    usage = (est_total_payload / cap_info["capacity_bytes"]) * 100.0
                    st.metric("Capacity Usage", f"{usage:.2f}%")
                    if usage > 100.0:
                        st.error("⚠️ Vault exceeds cover image capacity! Please upload a larger image or remove files.")
                else:
                    st.metric("Capacity Usage", "Upload cover first")
        except Exception as ex:
            st.warning(f"Vault preview: {ex}")

    # ── Action Button ─────────────────────────────────────────────────────────
    create_clicked = st.button("🚀 CREATE SECRET VAULT & EMBED", type="primary", use_container_width=True)

    if create_clicked:
        if not cover_img:
            st.error("Please upload a cover image first.")
        elif not has_content:
            st.error("Vault cannot be empty. Please enter a secret message or attach at least one file.")
        elif not pwd:
            st.error("Please enter an encryption password.")
        elif len(pwd) < 8:
            st.error("Password must be at least 8 characters long.")
        elif pwd != pwd_confirm:
            st.error("Passwords do not match. Please verify your password entry.")
        else:
            with st.spinner("Compacting vault, deriving scrypt key, and embedding into image pixels..."):
                try:
                    # 1. Create compressed in-memory vault
                    zip_bytes, vault_obj = create_vault(message=secret_text, files=files_to_embed)

                    # 2. Encrypt with AES-256-GCM
                    salt, nonce, ciphertext = encrypt_bytes(zip_bytes, pwd)

                    # 3. Assemble Version 2 binary payload
                    payload = pack_payload_v2(
                        salt=salt,
                        nonce=nonce,
                        ciphertext=ciphertext,
                        is_compressed=True,
                        is_vault=True,
                        has_files=len(files_to_embed) > 0,
                        has_text=bool(secret_text and secret_text.strip()),
                    )

                    # 4. Embed into Cover Image
                    stego_img = embed_payload(cover_img, payload)

                    # 5. Compute Metrics
                    metrics = compute_metrics(cover_img, stego_img)
                    diff_map = compute_difference_map(cover_img, stego_img, amplification=50)

                    # Convert stego image to PNG bytes for download
                    stego_buf = io.BytesIO()
                    stego_img.save(stego_buf, format="PNG")
                    stego_bytes = stego_buf.getvalue()

                    st.success("✅ **Secret Vault Successfully Created & Embedded!**")

                    # Display metrics
                    st.markdown("### 📊 Embedding Quality Metrics")
                    m1, m2, m3, m4, m5 = st.columns(5)
                    with m1:
                        st.metric("PSNR", f"{metrics['psnr']:.2f} dB" if metrics['psnr'] != float('inf') else "∞ dB")
                    with m2:
                        st.metric("SSIM", f"{metrics['ssim']:.5f}")
                    with m3:
                        st.metric("MSE", f"{metrics['mse']:.4f}")
                    with m4:
                        st.metric("Modified Channels", f"{metrics['changed_channels']:,}")
                    with m5:
                        st.metric("Channel Change %", f"{metrics['changed_pct']:.2f}%")

                    st.caption("ℹ️ *PSNR values above 50 dB and SSIM near 1.0 indicate virtually imperceptible pixel-level distortion.*")

                    # Visual Comparison
                    st.markdown("### 👁️ Visual Comparison")
                    cmp_col1, cmp_col2, cmp_col3 = st.columns(3)
                    with cmp_col1:
                        st.image(cover_img, caption="Original Cover Image", use_container_width=True)
                    with cmp_col2:
                        st.image(stego_img, caption="Stego PNG (With Hidden Vault)", use_container_width=True)
                    with cmp_col3:
                        st.image(diff_map, caption="Amplified Difference Map (50×)", use_container_width=True)

                    st.download_button(
                        label="⬇️ DOWNLOAD STEGO IMAGE (stegocrypt_vault.png)",
                        data=stego_bytes,
                        file_name="stegocrypt_vault.png",
                        mime="image/png",
                        type="primary",
                        use_container_width=True,
                    )
                except Exception as e:
                    st.error(f"Error creating vault: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: OPEN SECRET VAULT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_open:
    st.header("🔓 Open Secret Vault")
    st.markdown("Upload a StegoCrypt image, enter the password, and recover all hidden text and files.")

    open_cov_col, open_pwd_col = st.columns([1, 1], gap="large")

    with open_cov_col:
        stego_file = st.file_uploader(
            "Upload Stego PNG Image",
            type=["png", "bmp"],
            key="stego_uploader",
            help="Lossless image containing the hidden StegoCrypt vault.",
        )
        if stego_file:
            st.image(stego_file, caption=f"Uploaded Stego Image: {stego_file.name}", use_container_width=True)

    with open_pwd_col:
        unlock_pwd = st.text_input("Enter Vault Password", type="password", key="unlock_pwd")
        unlock_btn = st.button("🔓 UNLOCK VAULT", type="primary", use_container_width=True)

    if unlock_btn:
        if not stego_file:
            st.error("Please upload a stego image.")
        elif not unlock_pwd:
            st.error("Please enter the vault password.")
        else:
            with st.spinner("Extracting bitstream, decrypting AES-256-GCM payload, and restoring vault..."):
                try:
                    loaded_img = Image.open(io.BytesIO(stego_file.getvalue()))
                    loaded_img.load()

                    # Extract binary payload & header metadata
                    ciphertext, meta = extract_payload(loaded_img)

                    # Decrypt ciphertext
                    decrypted_bytes = decrypt_bytes(
                        ciphertext=ciphertext,
                        password=unlock_pwd,
                        salt=meta.salt,
                        nonce=meta.nonce,
                    )

                    # Handle Version 1 vs Version 2
                    if meta.version == 1 or not meta.is_vault:
                        # Legacy single text message payload
                        msg = decrypted_bytes.decode("utf-8")
                        st.success("🔓 **Legacy Secret Message Unlocked!**")
                        st.markdown("### 📝 Secret Message")
                        st.code(msg, language="text")
                    else:
                        # Version 2 secret vault
                        vault = extract_vault(decrypted_bytes)
                        st.success("🔓 **Secret Vault Successfully Unlocked!**")

                        # Display Message if present
                        if vault.message:
                            st.markdown("### 📝 Secret Message")
                            st.code(vault.message, language="text")

                        # Display Files if present
                        if vault.files:
                            st.markdown(f"### 📂 Recovered Files ({len(vault.files)})")
                            for idx, vf in enumerate(vault.files):
                                f_col1, f_col2, f_col3, f_col4 = st.columns([3, 2, 2, 2])
                                with f_col1:
                                    st.write(f"📄 **{vf.name}**")
                                with f_col2:
                                    st.caption(f"Size: {vf.size / 1024:.1f} KB")
                                with f_col3:
                                    st.caption(f"SHA-256: `{vf.sha256[:10]}...`")
                                with f_col4:
                                    st.download_button(
                                        label=f"⬇️ Download",
                                        data=vf.data,
                                        file_name=vf.name,
                                        mime=vf.mime_type,
                                        key=f"dl_file_{idx}",
                                    )

                        # Metadata expander
                        with st.expander("🔍 Vault Package Metadata", expanded=False):
                            st.json(vault.metadata)

                except ValueError as ve:
                    st.error(f"❌ {ve}")
                except Exception as ex:
                    st.error("❌ Unable to unlock vault. Incorrect password or corrupted data.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: DETECT HIDDEN DATA
# ═══════════════════════════════════════════════════════════════════════════════
with tab_detect:
    st.header("🕵️ Forensic Hidden-Data Detection & Steganalysis")
    st.markdown("Inspect an unknown image for exact StegoCrypt signatures or generic LSB steganographic anomalies.")

    detect_file = st.file_uploader(
        "Upload Image to Scan (PNG, BMP, or JPEG)",
        type=["png", "bmp", "jpg", "jpeg"],
        key="detect_uploader",
    )

    if detect_file:
        det_img = Image.open(io.BytesIO(detect_file.getvalue()))
        det_img.load()

        d_col1, d_col2 = st.columns([1, 2])
        with d_col1:
            st.image(det_img, caption=f"{detect_file.name} ({det_img.width}×{det_img.height})", use_container_width=True)
            scan_btn = st.button("🔍 SCAN IMAGE FOR HIDDEN DATA", type="primary", use_container_width=True)

        with d_col2:
            if scan_btn or "last_report" in st.session_state:
                if scan_btn:
                    with st.spinner("Performing multi-channel forensic steganalysis..."):
                        report = analyze_image(det_img)
                        st.session_state["last_report"] = report
                        st.session_state["scanned_img"] = det_img
                else:
                    report = st.session_state["last_report"]

                # Render Verdict Box
                v_class = "verdict-cat-c"
                if report.verdict_category == "Category A":
                    v_class = "verdict-cat-a"
                elif report.verdict_category == "Category B":
                    v_class = "verdict-cat-b"

                st.markdown(f"""
                <div class="verdict-box {v_class}">
                    <h3 style="margin:0 0 6px 0; color:#fff;">{report.verdict_category}: {report.verdict_title}</h3>
                    <p style="color:#e2e8f0; margin-bottom:10px;">{report.verdict_description}</p>
                </div>
                """, unsafe_allow_html=True)

                # Suspicion Score Meter
                s_col1, s_col2 = st.columns([1, 3])
                with s_col1:
                    st.metric("Suspicion Score", f"{report.suspicion_score} / 100")
                with s_col2:
                    st.write("")
                    st.progress(report.suspicion_score / 100)
                    st.caption("ℹ️ *Heuristic Suspicion Score derived from real statistical metrics. Not an AI confidence or probability.*")

                # Evidence Breakdown
                st.markdown("#### 🔍 Forensic Evidence Points")
                for pt in report.evidence_points:
                    st.markdown(f"- {pt}")

                # Channel Statistics Table
                st.markdown("#### 📊 Channel-Level Statistics")
                stat_data = []
                for name, s in report.channels.items():
                    stat_data.append({
                        "Channel": name,
                        "LSB 0s (%)": f"{s.zeros_pct:.2f}%",
                        "LSB 1s (%)": f"{s.ones_pct:.2f}%",
                        "Dev from 50%": f"{s.dist_from_50:.3f}%",
                        "Channel Entropy": f"{s.channel_entropy:.4f}",
                        "LSB Entropy": f"{s.lsb_entropy:.5f}",
                        "PoV Chi² Stat": f"{s.chi2_stat:.1f}",
                        "Chi² p-value": f"{s.chi2_pvalue:.4f}",
                    })
                st.table(stat_data)

        # ── Interactive Bit-Plane Viewer ──────────────────────────────────────
        st.markdown("---")
        st.subheader("👁️ Visual Bit-Plane Inspector")
        st.caption("Inspect individual bit planes (0 = LSB, 7 = MSB) for each color channel. Random high-frequency noise in Plane 0 often reveals embedded steganographic payloads.")

        b_ch_col, b_idx_col = st.columns(2)
        with b_ch_col:
            selected_channel = st.selectbox("Select Color Channel", options=["Red (Channel 0)", "Green (Channel 1)", "Blue (Channel 2)"])
            ch_idx = 0 if "Red" in selected_channel else (1 if "Green" in selected_channel else 2)
        with b_idx_col:
            bit_idx = st.slider("Select Bit Plane (0 = LSB, 7 = MSB)", min_value=0, max_value=7, value=0)

        plane_img = extract_bit_plane(det_img, channel_index=ch_idx, bit_index=bit_idx)
        st.image(plane_img, caption=f"{selected_channel} — Bit Plane {bit_idx} {'(Least Significant Bit)' if bit_idx == 0 else ('(Most Significant Bit)' if bit_idx == 7 else '')}", use_container_width=True)

        # ── Matplotlib Channel Histograms ─────────────────────────────────────
        st.markdown("---")
        st.subheader("📈 RGB Intensity & LSB Distribution Histograms")
        
        arr = np.array(det_img.convert("RGB"), dtype=np.uint8)
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4), facecolor="#0e1726")
        
        # Color histogram
        for i, col in enumerate(["red", "green", "blue"]):
            hist, bins = np.histogram(arr[:, :, i].ravel(), bins=256, range=[0, 256])
            ax1.plot(hist, color=col, alpha=0.8, label=col.capitalize())
        ax1.set_title("Color Channel Histograms", color="#f8fafc")
        ax1.set_facecolor("#1e293b")
        ax1.tick_params(colors="#94a3b8")
        ax1.legend(facecolor="#1e293b", edgecolor="#475569", labelcolor="#e2e8f0")

        # LSB 0/1 counts bar chart
        ch_names = ["Red", "Green", "Blue"]
        zeros_counts = [np.count_nonzero((arr[:, :, i] & 1) == 0) for i in range(3)]
        ones_counts = [np.count_nonzero((arr[:, :, i] & 1) == 1) for i in range(3)]
        
        x = np.arange(len(ch_names))
        width = 0.35
        ax2.bar(x - width/2, zeros_counts, width, label='LSB 0', color='#3b82f6')
        ax2.bar(x + width/2, ones_counts, width, label='LSB 1', color='#8b5cf6')
        ax2.set_title("LSB Zero / One Bit Counts", color="#f8fafc")
        ax2.set_xticks(x)
        ax2.set_xticklabels(ch_names, color="#94a3b8")
        ax2.set_facecolor("#1e293b")
        ax2.tick_params(colors="#94a3b8")
        ax2.legend(facecolor="#1e293b", edgecolor="#475569", labelcolor="#e2e8f0")

        st.pyplot(fig)
        plt.close(fig)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: HOW IT WORKS
# ═══════════════════════════════════════════════════════════════════════════════
with tab_help:
    st.header("ℹ️ Architecture & Scientific Principles")
    st.markdown(r"""
    ### 1. High-Level Cryptographic Architecture
    StegoCrypt Pro combines military-grade authenticated encryption with spatial-domain steganography:
    
    ```
    CREATE VAULT FLOW:
    Secret Text + Files 
        ↓
    In-Memory ZIP Package (with metadata.json)
        ↓
    Compression (DEFLATE level 9)
        ↓
    Password Key Derivation (scrypt, N=16384, r=8, p=1)
        ↓
    AES-256-GCM Encryption (with 16-byte Auth Tag)
        ↓
    Structured Binary Payload (STGC Header + Flags + uint64 Length)
        ↓
    Vectorized LSB Embedding (RGB channels only)
        ↓
    Lossless PNG Output
    ```

    ---

    ### 2. Forensic Steganalysis Techniques
    Module 3 performs deep forensic inspection without machine learning:
    
    - **Level 1 — Signature Verification:** Detects the fixed `b'STGC'` magic signature and decodes version flags and embedded payload size.
    - **Pairs of Values (PoVs) Chi-Square Test:** Based on the seminal research by Westfeld & Pfitzmann (1999). LSB substitution swaps adjacent values $(2k, 2k+1)$, causing their histogram frequencies to equalize. A high $p$-value close to 1.0 indicates pairing regularity.
    - **Shannon Entropy Analysis:** Measures informational entropy in both the overall color channels and isolated LSB planes ($H_{LSB} = -\sum p_i \log_2 p_i$). Encrypted binary payloads exhibit maximum entropy near $1.0000$ bits/pixel.
    - **LSB Bit Balance:** Natural camera sensor noise usually shows a slight bias (e.g. 48/52%). AES-GCM ciphertext enforces a near-perfect Bernoulli trial ($50.0\% / 50.0\%$).

    ---

    ### 3. Image Fidelity Metrics
    - **PSNR (Peak Signal-to-Noise Ratio):** Measures logarithmic ratio between maximum pixel power ($255^2$) and Mean Squared Error ($MSE$). Higher values ($>50$ dB) signify imperceptible changes.
    - **SSIM (Structural Similarity Index):** Models human visual perception by comparing luminance, contrast, and structure ($[-1.0, 1.0]$). Values $\ge 0.999$ confirm preservation of structural fidelity.
    """)
