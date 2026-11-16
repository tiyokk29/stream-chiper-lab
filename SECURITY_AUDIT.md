# Security Audit

Tanggal: 2026-11-17

## Cakupan

Audit manual terhadap seluruh file Python pada simulator: `app.py`,
`src/xor_cipher.py`, `src/chacha20.py`, dan `tests/test_crypto.py`.

## Temuan

- **Randomness:** key dan nonce acak hanya dibuat melalui
  `secrets.token_bytes` di `src/chacha20.py`; tidak ada penggunaan modul
  `random`.
- **Validasi:** ChaCha20 menolak key 32 byte, nonce 12 byte, dan counter di luar
  rentang RFC. XOR menolak operand dengan panjang berbeda dan parser biner
  menolak token yang tidak tepat 8 bit.
- **Output Streamlit:** `unsafe_allow_html=True` hanya dipakai untuk stylesheet
  dan markup dekoratif statis yang ditulis pengembang. Nilai pengguna dirender
  melalui `st.code`, `st.caption`, `st.dataframe`, `st.error`, dan komponen
  Streamlit sehingga tidak disisipkan sebagai HTML mentah.
- **Dekripsi:** format hex/Base64 dan UTF-8 divalidasi dengan error eksplisit;
  tidak ada fallback diam-diam.
- **Ruang lingkup kriptografi:** engine ini tidak mengklaim integritas atau
  autentikasi. UI menyarankan ChaCha20-Poly1305 untuk penggunaan nyata.

## Batasan residual

ChaCha20 mentah tanpa autentikasi tidak melindungi integritas pesan. Aplikasi
ini adalah simulator lokal dan tidak menyimpan key, nonce, atau plaintext ke
database maupun mengirimkannya ke layanan eksternal. Untuk sistem produksi,
gunakan library kriptografi teruji dengan mode AEAD dan manajemen nonce yang
terkontrol.

## Status

Tidak ditemukan celah XSS langsung, penggunaan PRNG tidak aman, atau validasi
panjang kunci/nonce yang hilang pada cakupan audit ini.
