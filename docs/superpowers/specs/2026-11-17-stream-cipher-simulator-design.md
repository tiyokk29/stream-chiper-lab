# Stream Cipher & ChaCha20 Simulator — Design

## Intent

Membangun simulator pembelajaran berbasis Streamlit untuk membantu mahasiswa
memahami XOR bit-per-bit, alur internal ChaCha20 RFC 8439, bahaya penggunaan
ulang keystream, dan posisi algoritma stream cipher terhadap block cipher.
Simulator ini ditujukan untuk eksperimen lokal; bukan library produksi atau
pengganti ChaCha20-Poly1305 yang terautentikasi.

## Goals

- Menyediakan empat area interaktif yang dapat diuji tanpa memenuhi satu layar.
- Memisahkan seluruh logika kriptografi dari UI agar dapat diuji dengan unittest.
- Menggunakan implementasi ChaCha20 murni Python dengan validasi panjang input,
  vektor RFC 8439, format hex/Base64, dan visualisasi state 4x4.
- Menjelaskan secara eksplisit risiko nonce reuse dan perbedaan stream/block
  cipher.
- Menjalankan aplikasi dengan `streamlit run app.py` menggunakan dependensi
  minimal.

## Non-goals and anti-goals

- Tidak menyediakan autentikasi, penyimpanan pesan, koneksi jaringan, atau
  layanan produksi.
- Tidak mengimplementasikan MAC/AEAD secara parsial; label ChaCha20-Poly1305
  hanya digunakan pada tabel perbandingan.
- Tidak menggunakan `random` untuk material kriptografis.
- Tidak merender input pengguna sebagai HTML mentah.

## Constraints

- Python dengan type hints dan docstring.
- Modul logika berada di `src/xor_cipher.py` dan `src/chacha20.py`.
- UI berada di `app.py`; konfigurasi tema berada di `.streamlit/config.toml`.
- Kunci, nonce, dan contoh acak dibuat dengan `secrets.token_bytes`.
- Tampilan bertema lab keamanan siber, kontras tinggi, responsif, dan
  menggunakan monospace untuk bit, hex, serta state matrix.

## Approaches

1. **Dashboard tunggal dengan empat tab (dipilih)**: satu entry point dan
   navigasi yang cepat untuk demo kelas; logika tetap modular di `src/`.
2. **Multipage Streamlit**: tiap modul lebih luas, tetapi menambah navigasi dan
   file boilerplate tanpa manfaat penting untuk simulator ini.
3. **Frontend terpisah + API Python**: fleksibel untuk deployment besar, namun
   tidak proporsional untuk eksperimen lokal dan memperbesar permukaan risiko.

Pendekatan pertama dipilih karena memenuhi kebutuhan pengujian cepat, menjaga
implementasi kriptografi tetap dapat dipakai ulang, dan meminimalkan setup.

## Structure and behavior

```text
stream-chiper-lab/
├── app.py
├── requirements.txt
├── SECURITY_AUDIT.md
├── .streamlit/config.toml
├── src/
│   ├── __init__.py
│   ├── xor_cipher.py
│   └── chacha20.py
└── tests/
    ├── __init__.py
    └── test_crypto.py
```

Tab 1, **XOR Lab**, menerima preset jurnal atau input teks/biner dan
menampilkan P/K/C dalam biner, hex, dan ASCII. Tab 2, **ChaCha20 Engine**,
memvalidasi key 32 byte, nonce 12 byte, dan counter 32-bit, lalu menampilkan
enkripsi/dekripsi, Base64/hex, dan state matrix sebelum/selama blok pertama.
Tab 3, **Keystream Reuse**, mengenkripsi dua pesan dengan nonce sama lalu
nonce berbeda dan menampilkan perbandingan XOR ciphertext terhadap XOR
plaintext. Tab 4, **Comparison**, menampilkan tabel algoritma jurnal dan
perbandingan stream cipher dengan block cipher.

UI menggunakan sidebar untuk mode dan parameter global, tab untuk pemisahan
fitur, `st.code`/tabel untuk data teknis, dan pesan validasi yang jelas.
HTML kustom dibatasi pada stylesheet statis; nilai dari pengguna ditampilkan
melalui komponen Streamlit ter-escape.

## Cryptographic design

`xor_cipher.py` menyediakan operasi XOR byte yang simetris, representasi
format, dan helper validasi biner. `chacha20.py` menyediakan `rotl32`,
`quarter_round`, state initialization, 20-round block function, keystream
generation, dan `crypt` yang sama untuk enkripsi/dekripsi. Semua operasi
word menggunakan modulo 2^32 dan little-endian sesuai RFC 8439. Random
material dibuat hanya ketika diminta UI atau helper generator.

## Verification

- Unit tests untuk preset XOR, round-trip ChaCha20, validasi input, dan vektor
  RFC 8439.
- Smoke test import dan `streamlit run app.py --server.headless true`.
- Jika muncul kegagalan, investigasi mengikuti systematic debugging:
  reproduksi, baca traceback, telusuri data flow, buat hipotesis tunggal,
  perbaiki akar masalah, lalu ulangi verifikasi.
- Audit akhir seluruh file Python mendokumentasikan penggunaan randomness,
  escaping output, dan batasan keamanan di `SECURITY_AUDIT.md`.

## Builder calls

- Pilihan dashboard tunggal, bukan multipage, karena simulator dipakai sebagai
  satu alur pembelajaran.
- Komponen Streamlit digunakan untuk output pengguna; tidak ada kebutuhan
  rendering HTML dinamis.
- Kode implementasi boleh menetapkan detail minor seperti nama fungsi internal,
  wording label, dan layout kolom selama kontrak di atas tetap terpenuhi.
- Preset XOR mencakup contoh jurnal `10110010 XOR 01101001 =
  11011011`; input byte dengan panjang berbeda ditolak agar hasil tidak ambigu.
- Input biner kustom menggunakan token 8-bit yang dipisahkan spasi atau koma;
  token yang bukan tepat 8 bit ditolak dengan pesan validasi.
- Visualisasi ChaCha20 menampilkan state awal dan state hasil block pertama;
  detail seluruh 20 putaran tetap tersedia melalui fungsi engine, bukan
  memenuhi UI utama.
- Generator memvalidasi rentang counter dan mencegah overflow ketika jumlah
  blok diminta. Demo reuse membandingkan prefix sepanjang pesan terpendek dan
  menyediakan kontrol nonce bersama versus nonce unik.
- Tabel perbandingan wajib memuat RC4, Salsa20, ChaCha20-Poly1305, dan Grain,
  serta ringkasan kelebihan/kekurangan stream cipher dan block cipher seperti
  yang diminta.
