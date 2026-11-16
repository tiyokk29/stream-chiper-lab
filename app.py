"""Interactive Stream Cipher and ChaCha20 learning laboratory."""

from __future__ import annotations

import streamlit as st

from src.chacha20 import (
    MAX_COUNTER,
    crypt,
    decrypt_base64,
    decrypt_hex,
    encrypt_base64,
    encrypt_hex,
    generate_key,
    generate_nonce,
    sample_block,
)
from src.xor_cipher import journal_preset, parse_binary_tokens, printable_ascii, xor_detail

st.set_page_config(
    page_title="Stream Cipher Lab",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
:root { --ink:#07131d; --surface:#0d202d; --line:#1e4150; --cyan:#45d6e8; --amber:#f6bd60; --muted:#9bb3bd; }
html { color-scheme: dark; }
html, body, [class*="css"] { font-family: "DM Sans", sans-serif; }
body { background: var(--ink); }
code, pre, .stCode, [data-testid="stDataFrame"] { font-family: "JetBrains Mono", monospace !important; }
*:focus-visible { outline: 2px solid var(--cyan); outline-offset: 3px; }
.hero { border-left: 4px solid var(--cyan); padding: 1.2rem 1.5rem; margin-bottom: 1.5rem; background: linear-gradient(110deg, #0d202d 0%, #091923 75%); }
.hero h1 { margin: 0; letter-spacing: -0.04em; font-size: clamp(2rem, 5vw, 4.2rem); }
.hero p { color: var(--muted); max-width: 720px; margin: .55rem 0 0; font-size: 1.05rem; }
.eyebrow { color: var(--cyan); font-family: "JetBrains Mono", monospace; font-size: .75rem; letter-spacing: .12em; text-transform: uppercase; }
.metric-strip { display:flex; gap: .75rem; flex-wrap:wrap; margin: 1rem 0 1.75rem; }
.metric { border: 1px solid var(--line); background: rgba(13,32,45,.8); padding: .8rem 1rem; min-width: 145px; }
.metric strong { display:block; font-family:"JetBrains Mono", monospace; color:var(--cyan); font-size:1.15rem; }
.metric span { color:var(--muted); font-size:.78rem; }
.warning { border-left: 3px solid var(--amber); padding: .75rem 1rem; background: rgba(246,189,96,.08); }
.stTabs [data-baseweb="tab-list"] { gap: .35rem; }
.stTabs [data-baseweb="tab"] { border: 1px solid var(--line); padding: .55rem 1rem; }
@media (max-width: 700px) { .hero { padding: 1rem; } .metric { min-width: 120px; } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; scroll-behavior: auto !important; } }
</style>
""",
    unsafe_allow_html=True,
)


def hex_bytes(value: str, label: str, expected: int | None = None) -> bytes:
    """Parse a hex field and enforce an optional byte length."""

    try:
        result = bytes.fromhex(value.strip())
    except ValueError as error:
        raise ValueError(f"{label} harus berupa hexadecimal yang valid.") from error
    if expected is not None and len(result) != expected:
        raise ValueError(f"{label} harus berukuran {expected} byte.")
    return result


def show_result_row(title: str, value: bytes) -> None:
    """Render one technical byte representation row."""

    columns = st.columns([1.2, 2, 1.2, 1.6])
    columns[0].markdown(f"**{title}**")
    columns[1].code(" ".join(f"{byte:08b}" for byte in value))
    columns[2].code(value.hex(" ").upper())
    columns[3].code(printable_ascii(value))


def render_xor_tab() -> None:
    """Render the XOR visualizer."""

    st.subheader("Bitwise XOR visualizer")
    st.caption("C = P XOR K dan P = C XOR K. Operasi simetris ini adalah inti stream cipher.")
    mode = st.radio("Sumber data", ["Preset jurnal", "Teks kustom", "Biner kustom"], horizontal=True)
    if mode == "Preset jurnal":
        result = journal_preset()
    else:
        if mode == "Teks kustom":
            plaintext = st.text_input("Plaintext", "STREAM")
            key = st.text_input("Key dengan panjang sama", "CIPHER")
            left, right = plaintext.encode("utf-8"), key.encode("utf-8")
        else:
            left_text = st.text_input("Plaintext biner (token 8-bit)", "10110010")
            right_text = st.text_input("Key biner (token 8-bit)", "01101001")
            try:
                left, right = parse_binary_tokens(left_text), parse_binary_tokens(right_text)
            except ValueError as error:
                st.error(str(error))
                return
        try:
            result = xor_detail(left, right)
        except ValueError as error:
            st.error(str(error))
            return
    st.markdown("**P / K / C**")
    show_result_row("P", result.plaintext)
    show_result_row("K", result.key)
    show_result_row("C", result.ciphertext)
    st.info("Dekripsi identik: C XOR K menghasilkan kembali P.")


def render_chacha_tab() -> None:
    """Render the ChaCha20 engine."""

    st.subheader("ChaCha20 engine — RFC 8439")
    st.caption("ARX: addition modulo 2³², rotation, dan XOR selama 20 putaran.")
    left, right = st.columns(2)
    with left:
        key_text = st.text_input("Key (64 hex karakter)", bytes(32).hex(), key="chacha_key")
        nonce_text = st.text_input("Nonce (24 hex karakter)", bytes(12).hex(), key="chacha_nonce")
        counter = st.number_input("Block counter", 0, MAX_COUNTER, 1, key="chacha_counter")
    with right:
        message = st.text_area("Pesan UTF-8", "ChaCha20 membuat aliran kunci untuk setiap byte.")
        output_format = st.selectbox("Format ciphertext", ["Hex", "Base64"])
        operation = st.radio("Operasi", ["Enkripsi", "Dekripsi"], horizontal=True)
    try:
        key = hex_bytes(key_text, "Key", 32)
        nonce = hex_bytes(nonce_text, "Nonce", 12)
        sample = sample_block(key, nonce, counter)
        if operation == "Enkripsi":
            output = encrypt_hex(message, key, nonce, counter) if output_format == "Hex" else encrypt_base64(message, key, nonce, counter)
            st.success("Ciphertext berhasil dibuat.")
            st.code(output)
        else:
            output = decrypt_hex(message, key, nonce, counter) if output_format == "Hex" else decrypt_base64(message, key, nonce, counter)
            st.success("Plaintext berhasil dipulihkan.")
            st.code(output)
    except ValueError as error:
        st.error(str(error))
        return
    st.markdown("**State awal 4 × 4 (16 word little-endian)**")
    st.dataframe(sample.initial_state, use_container_width=True, hide_index=True)
    st.markdown("**Keystream block pertama**")
    st.code(sample.block_hex)


def render_reuse_tab() -> None:
    """Render the keystream reuse demonstration."""

    st.subheader("Keystream reuse attack")
    st.markdown('<div class="warning">Jangan pernah memakai pasangan key + nonce yang sama untuk dua pesan berbeda.</div>', unsafe_allow_html=True)
    left, right = st.columns(2)
    with left:
        message_one = st.text_area("Pesan 1", "Transfer dana: 100000", key="reuse_one")
        message_two = st.text_area("Pesan 2", "Transfer dana: 900000", key="reuse_two")
        key = generate_key()
        shared_nonce = generate_nonce()
        unique_nonce = generate_nonce()
        st.caption("Key dan nonce dibuat ulang secara aman saat sesi dihitung ulang.")
    with right:
        same_nonce = st.toggle("Gunakan nonce yang sama", value=True)
        active_nonce_two = shared_nonce if same_nonce else unique_nonce
        cipher_one = crypt(message_one.encode(), key, shared_nonce)
        cipher_two = crypt(message_two.encode(), key, active_nonce_two)
        common_length = min(len(cipher_one), len(cipher_two))
        xor_ciphertext = bytes(a ^ b for a, b in zip(cipher_one[:common_length], cipher_two[:common_length]))
        xor_plaintext = bytes(a ^ b for a, b in zip(message_one.encode()[:common_length], message_two.encode()[:common_length]))
        st.metric("Byte yang dibandingkan", common_length)
        st.code(f"C1 XOR C2\n{xor_ciphertext.hex().upper()}\n\nP1 XOR P2\n{xor_plaintext.hex().upper()}")
        if same_nonce:
            st.error("Terbukti: C1 XOR C2 = P1 XOR P2 untuk prefix yang sama.")
        else:
            st.success("Nonce unik memutus hubungan langsung antara XOR ciphertext dan XOR plaintext.")


def render_comparison_tab() -> None:
    """Render algorithm comparison tables."""

    st.subheader("Peta algoritma stream cipher")
    rows = [
        {"Algoritma": "RC4", "Keluarga": "Stream cipher", "Status": "Deprecated", "Kelebihan": "Sederhana, historis luas", "Kekurangan": "Bias keystream dan kelemahan nonce"},
        {"Algoritma": "Salsa20", "Keluarga": "ARX", "Status": "Aktif", "Kelebihan": "Cepat, desain terbuka", "Kekurangan": "Tidak menyediakan autentikasi sendiri"},
        {"Algoritma": "ChaCha20-Poly1305", "Keluarga": "Modern AEAD", "Status": "Direkomendasikan", "Kelebihan": "Enkripsi + integritas", "Kekurangan": "API nonce tetap harus benar"},
        {"Algoritma": "Grain", "Keluarga": "Lightweight", "Status": "Niche", "Kelebihan": "Hemat resource", "Kekurangan": "Ruang penggunaan lebih spesifik"},
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.subheader("Stream cipher versus block cipher")
    st.dataframe(
        [
            {"Aspek": "Unit operasi", "Stream cipher": "Byte/bit berurutan", "Block cipher": "Blok berukuran tetap"},
            {"Aspek": "Latensi", "Stream cipher": "Rendah; cocok untuk aliran", "Block cipher": "Bergantung mode dan buffering"},
            {"Aspek": "Risiko utama", "Stream cipher": "Nonce/keystream reuse", "Block cipher": "Mode operasi dan padding"},
            {"Aspek": "Contoh", "Stream cipher": "ChaCha20, Salsa20", "Block cipher": "AES, Camellia"},
        ],
        use_container_width=True,
        hide_index=True,
    )


st.markdown(
    '<section class="hero"><div class="eyebrow">Kelompok 19 · Teknik Informatika</div>'
    "<h1>Stream Cipher Lab</h1>"
    "<p>Simulator interaktif untuk melihat bagaimana bit, keystream, dan nonce "
    "membentuk keamanan informasi digital.</p></section>",
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="metric-strip"><div class="metric"><strong>32 B</strong><span>key ChaCha20</span></div>'
    '<div class="metric"><strong>12 B</strong><span>nonce RFC 8439</span></div>'
    '<div class="metric"><strong>20×</strong><span>round ARX</span></div>'
    '<div class="metric"><strong>4</strong><span>modul pembelajaran</span></div></div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### Lab controls")
    st.caption("Gunakan tab untuk berpindah eksperimen.")
    st.markdown("---")
    st.markdown("**Catatan keamanan**")
    st.caption("Simulator ini untuk pembelajaran. Untuk aplikasi nyata, gunakan AEAD seperti ChaCha20-Poly1305.")

tab_xor, tab_chacha, tab_reuse, tab_compare = st.tabs(
    ["01 · XOR Lab", "02 · ChaCha20 Engine", "03 · Keystream Reuse", "04 · Comparison"]
)
with tab_xor:
    render_xor_tab()
with tab_chacha:
    render_chacha_tab()
with tab_reuse:
    render_reuse_tab()
with tab_compare:
    render_comparison_tab()
