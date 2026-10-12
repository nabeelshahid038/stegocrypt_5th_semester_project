"""
app.py
------
StegoCrypt — Secure Image Steganography with AES Encryption
Streamlit UI entry point.
"""

import io
import streamlit as st
from PIL import Image

from crypto_utils import (
    encrypt_message, decrypt_message,
    validate_password, password_strength,
    MIN_PASSWORD_LEN,
)
from steganography import embed_payload, extract_payload, image_capacity_bytes
from metrics import compute_psnr, compute_ssim, compute_difference_image
from validators import validate_image_upload, image_info

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="StegoCrypt",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base ── */
body, .stApp { background-color: #0e1117; color: #e0e0e0; }

/* ── Header ── */
.main-header {
    text-align: center;
    padding: 1.5rem 0 0.5rem;
}
.main-header h1 {
    font-size: 2.8rem;
    font-weight: 800;
    background: linear-gradient(135deg, #6ee7f7 0%, #a78bfa 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0;
}
.main-header p {
    color: #9ca3af;
    font-size: 1.05rem;
    margin-top: 0.3rem;
}

/* ── Cards ── */
.card {
    background: #1a1f2e;
    border: 1px solid #2d3348;
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
}
.card-title {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #6b7280;
    margin-bottom: 0.4rem;
}
.card-value {
    font-size: 1.15rem;
    font-weight: 600;
    color: #e2e8f0;
}

/* ── Metric row ── */
.metric-row { display: flex; gap: 1rem; flex-wrap: wrap; }
.metric-box {
    flex: 1;
    min-width: 130px;
    background: #141929;
    border: 1px solid #2d3348;
    border-radius: 10px;
    padding: 0.9rem 1rem;
    text-align: center;
}
.metric-box .label { font-size: 0.75rem; color: #6b7280; margin-bottom: 0.2rem; }
.metric-box .value { font-size: 1.3rem; font-weight: 700; color: #a78bfa; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab"] { font-size: 1rem; font-weight: 600; }

/* ── Alerts ── */
.success-box {
    background: #052e16;
    border: 1px solid #16a34a;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    color: #bbf7d0;
}
.error-box {
    background: #2d0f0f;
    border: 1px solid #dc2626;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    color: #fca5a5;
}
.info-note {
    background: #0f172a;
    border-left: 3px solid #6ee7f7;
    padding: 0.6rem 1rem;
    border-radius: 0 8px 8px 0;
    color: #94a3b8;
    font-size: 0.88rem;
}

/* ── Progress bar color ── */
.stProgress > div > div > div > div { background: #a78bfa; }

/* ── Download button ── */
.stDownloadButton > button {
    background: linear-gradient(135deg, #6ee7f7 0%, #a78bfa 100%) !important;
    color: #0e1117 !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 8px !important;
}
</style>
""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
  <h1>🔐 StegoCrypt</h1>
  <p>Secure Image Steganography with AES-256-GCM Encryption</p>
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Helper: image to PNG bytes ────────────────────────────────────────────────

def pil_to_png_bytes(image: Image.Image) -> bytes:
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


# ── Helper: capacity bar ──────────────────────────────────────────────────────

def _cap_color(pct: float) -> str:
    if pct < 50:
        return "🟢"
    elif pct < 80:
        return "🟡"
    return "🔴"


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_enc, tab_dec = st.tabs(["🔐  Encrypt & Hide", "🔓  Extract & Decrypt"])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — ENCRYPT & HIDE
# ═══════════════════════════════════════════════════════════════════════════════
with tab_enc:
    st.markdown("### Step 1 — Upload a Cover Image")
    uploaded_cover = st.file_uploader(
        "Choose an image (PNG, BMP, JPEG)",
        type=["png", "bmp", "jpg", "jpeg"],
        key="cover_uploader",
    )

    cover_image: Image.Image | None = None
    cover_info: dict = {}

    if uploaded_cover:
        try:
            cover_image = validate_image_upload(
                uploaded_cover.read(), uploaded_cover.name
            )
            cover_info = image_info(cover_image, uploaded_cover.name)

            # Display image info
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown('<div class="card"><div class="card-title">Resolution</div>'
                            f'<div class="card-value">{cover_info["resolution"]}</div></div>',
                            unsafe_allow_html=True)
            with col2:
                st.markdown('<div class="card"><div class="card-title">Format / Mode</div>'
                            f'<div class="card-value">{uploaded_cover.name.split(".")[-1].upper()} / {cover_info["mode"]}</div></div>',
                            unsafe_allow_html=True)
            with col3:
                cap_kb = cover_info["capacity_kb"]
                st.markdown('<div class="card"><div class="card-title">Max Payload Capacity</div>'
                            f'<div class="card-value">{cap_kb:.1f} KB</div></div>',
                            unsafe_allow_html=True)

            st.image(cover_image, caption="Cover Image Preview", use_container_width=True)

        except ValueError as e:
            st.error(str(e))
            cover_image = None

    st.markdown("---")
    st.markdown("### Step 2 — Enter Your Secret Message")
    secret_message = st.text_area(
        "Secret Message (supports English, Urdu, Arabic, emoji, any UTF-8 text)",
        height=150,
        placeholder="Type your secret message here…  e.g. السلام علیکم 🔐",
        key="secret_msg",
    )
    if secret_message:
        msg_bytes = secret_message.encode("utf-8")
        st.caption(f"Message size: {len(msg_bytes):,} bytes ({len(msg_bytes)/1024:.2f} KB)")

    st.markdown("---")
    st.markdown("### Step 3 — Enter a Password")
    col_pw1, col_pw2 = st.columns(2)
    with col_pw1:
        password = st.text_input(
            "Password",
            type="password",
            placeholder=f"Minimum {MIN_PASSWORD_LEN} characters",
            key="enc_password",
        )
    with col_pw2:
        confirm_pw = st.text_input(
            "Confirm Password",
            type="password",
            placeholder="Re-enter password",
            key="enc_confirm_pw",
        )

    # Password strength indicator
    if password:
        strength = password_strength(password)
        color_map = {"Weak": "🔴", "Fair": "🟡", "Strong": "🟢", "Very Strong": "🟣"}
        st.caption(f"Password strength: {color_map.get(strength, '')} **{strength}**")
        if len(password) < 12:
            st.caption("💡 Tip: 12+ character passwords are recommended.")

    st.markdown("---")
    st.markdown("### Step 4 — Encrypt & Hide")

    st.markdown(
        '<div class="info-note">ℹ️ Stego images are exported as <strong>PNG</strong> '
        'because lossless formats preserve hidden LSB data. JPEG compression would destroy it.</div>',
        unsafe_allow_html=True,
    )
    st.markdown("")

    if st.button("🔐 Encrypt & Hide in Image", type="primary", use_container_width=True):
        errors = []

        if not cover_image:
            errors.append("Please upload a cover image.")
        if not secret_message.strip():
            errors.append("Secret message must not be empty.")
        if not password:
            errors.append("Password must not be empty.")
        elif len(password) < MIN_PASSWORD_LEN:
            errors.append(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        elif password != confirm_pw:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                st.error(e)
        else:
            with st.spinner("🔒 Encrypting and embedding… please wait."):
                try:
                    # Encrypt
                    payload = encrypt_message(secret_message, password)

                    # Check capacity
                    cap = image_capacity_bytes(cover_image)
                    if len(payload) > cap:
                        st.error(
                            f"The encrypted payload ({len(payload):,} bytes) is too large "
                            f"for this image (capacity: {cap:,} bytes). "
                            "Please use a larger image or a shorter message."
                        )
                        st.stop()

                    # Embed
                    stego_image = embed_payload(cover_image, payload)

                    # Metrics
                    psnr_val = compute_psnr(cover_image, stego_image)
                    ssim_val = compute_ssim(cover_image, stego_image)
                    diff_img = compute_difference_image(cover_image, stego_image)

                    # Stats
                    payload_kb  = len(payload) / 1024
                    cap_kb_val  = cap / 1024
                    used_pct    = (len(payload) / cap) * 100
                    remain_kb   = (cap - len(payload)) / 1024

                    st.markdown('<div class="success-box">✅ <strong>Encryption & Embedding Successful!</strong></div>',
                                unsafe_allow_html=True)
                    st.markdown("")

                    # ── Stats row ──────────────────────────────────────────────
                    st.markdown(f"""
<div class="metric-row">
  <div class="metric-box"><div class="label">Encryption</div><div class="value" style="font-size:0.9rem">AES-256-GCM</div></div>
  <div class="metric-box"><div class="label">Steganography</div><div class="value" style="font-size:0.9rem">LSB</div></div>
  <div class="metric-box"><div class="label">Payload Size</div><div class="value">{payload_kb:.2f} KB</div></div>
  <div class="metric-box"><div class="label">Capacity Used</div><div class="value">{used_pct:.1f}%</div></div>
  <div class="metric-box"><div class="label">Remaining</div><div class="value">{remain_kb:.1f} KB</div></div>
  <div class="metric-box"><div class="label">PSNR</div><div class="value">{psnr_val:.1f} dB</div></div>
  <div class="metric-box"><div class="label">SSIM</div><div class="value">{ssim_val:.4f}</div></div>
</div>
""", unsafe_allow_html=True)

                    # Capacity bar
                    st.markdown("")
                    st.caption(f"{_cap_color(used_pct)} Capacity used: {used_pct:.1f}%")
                    st.progress(min(used_pct / 100, 1.0))
                    st.caption(
                        "ℹ️ High PSNR and SSIM values typically indicate very small "
                        "visual differences between the cover and stego images."
                    )

                    # ── Image comparison ───────────────────────────────────────
                    st.markdown("#### Visual Comparison")
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.image(cover_image, caption="Original Cover Image", use_container_width=True)
                    with c2:
                        st.image(stego_image, caption="Stego Image (with hidden data)", use_container_width=True)
                    with c3:
                        st.image(diff_img, caption="Enhanced Difference ×50 (educational)", use_container_width=True)

                    # ── Download ───────────────────────────────────────────────
                    st.markdown("#### Step 5 — Download Your Stego Image")
                    stego_bytes = pil_to_png_bytes(stego_image)
                    st.download_button(
                        label="⬇️ Download stegocrypt_output.png",
                        data=stego_bytes,
                        file_name="stegocrypt_output.png",
                        mime="image/png",
                        use_container_width=True,
                    )

                except ValueError as e:
                    st.error(str(e))
                except Exception as e:
                    st.error(f"Unexpected error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — EXTRACT & DECRYPT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_dec:
    st.markdown("### Step 1 — Upload a Stego Image")
    uploaded_stego = st.file_uploader(
        "Upload the stego PNG image produced by StegoCrypt",
        type=["png", "bmp"],
        key="stego_uploader",
    )

    stego_image_dec: Image.Image | None = None

    if uploaded_stego:
        try:
            stego_image_dec = validate_image_upload(
                uploaded_stego.read(), uploaded_stego.name
            )
            st.image(stego_image_dec, caption="Stego Image Preview", use_container_width=True)
        except ValueError as e:
            st.error(str(e))
            stego_image_dec = None

    st.markdown("---")
    st.markdown("### Step 2 — Enter Your Password")
    dec_password = st.text_input(
        "Password",
        type="password",
        placeholder="Enter the password used during encryption",
        key="dec_password",
    )

    st.markdown("---")
    st.markdown("### Step 3 — Extract & Decrypt")

    if st.button("🔓 Extract & Decrypt Message", type="primary", use_container_width=True):
        errors = []
        if not stego_image_dec:
            errors.append("Please upload a stego image.")
        if not dec_password:
            errors.append("Password must not be empty.")

        if errors:
            for e in errors:
                st.error(e)
        else:
            with st.spinner("🔍 Extracting and decrypting… please wait."):
                try:
                    payload   = extract_payload(stego_image_dec)
                    plaintext = decrypt_message(payload, dec_password)

                    st.markdown('<div class="success-box">✅ <strong>Extraction & Decryption Successful!</strong></div>',
                                unsafe_allow_html=True)
                    st.markdown("")
                    st.markdown("#### 📨 Recovered Secret Message")
                    st.text_area(
                        "Secret Message (select all to copy)",
                        value=plaintext,
                        height=200,
                        key="dec_result",
                    )
                    st.caption(
                        f"Message size: {len(plaintext.encode('utf-8')):,} bytes  |  "
                        f"Characters: {len(plaintext):,}"
                    )

                except ValueError as e:
                    st.markdown(
                        f'<div class="error-box">❌ <strong>Error:</strong> {e}</div>',
                        unsafe_allow_html=True,
                    )
                except Exception as e:
                    st.error(f"Unexpected error: {e}")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align:center; color:#4b5563; font-size:0.82rem;'>"
    "StegoCrypt &nbsp;|&nbsp; AES-256-GCM + LSB Steganography &nbsp;|&nbsp; "
    "All processing is done locally in memory. No data is stored or transmitted."
    "</div>",
    unsafe_allow_html=True,
)
