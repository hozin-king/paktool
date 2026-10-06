# paktool — unpack/repack UE4 .pak (Python, tanpa library tambahan)

Tool untuk membaca dan membangun ulang file `.pak` Unreal Engine 4.
Ditulis murni Python stdlib — jalan di Termux / PC tanpa `pip install` apa pun.

---

## Tutorial lengkap

### 1. Persiapan (Termux)

```bash
pkg install python git -y
git clone https://github.com/hozin-king/paktool
cd paktool
```

Di PC/laptop: install Python 3.10+ dari python.org, lalu clone repo yang sama.

### 2. Cara pakai — tool gabungan (RECOMMENDED)

```bash
python3 paktool_tui.py
```

Satu tool untuk semuanya — pas dijalankan muncul menu:

```
1. Unpack .pak (auto-detect format)
2. Repack folder -> .pak
3. Find SM4 (scan libUE4.so)
4. List isi .pak
5. Keluar
```

- **Auto-scan**: tiap menu tampil, folder di-scan ulang — file `.pak`
  yang baru ditambah langsung muncul di daftar, tanpa restart tool.
- **Auto-detect format**: unpack/list otomatis mengenali format
  **PUBG Mobile asli** (footer ZUC, index AES/RSA, payload
  SIMPLE1/SIMPLE2/SM4-custom Tencent) atau UE4 standar (fallback).
  Kunci SM4 per-file diturunkan otomatis — tidak perlu input manual.
- **Find SM4**: scan `libUE4.so` untuk mencari secret SM4 yang dikenal
  + kandidat secret pola baru (buat versi game yang lebih baru).
- **Repack**: membangun pak format UE4 standar. Catatan jujur: repack
  ke format PUBG Mobile tidak bisa tanpa private key RSA milik game.

### 3. Cara pakai — CLI (perintah langsung, buat scripting)

```bash
python3 paktool.py list game.pak
python3 paktool.py unpack game.pak -o hasil/
python3 paktool.py --key <32 hex char> unpack game.pak -o hasil/
python3 paktool.py repack folder_sumber -o baru.pak
python3 paktool.py --key <32 hex char> repack folder_sumber -o baru.pak
```

`--key` = kunci SM4 (16 byte dalam 32 karakter hex), mis. hasil dari
SM4 finder. **Kunci tidak pernah disimpan** — hanya dipakai saat run.

### 4. Cara pakai — GUI (tampilan jendela, khusus PC/laptop)

```bash
python3 paktool_gui.py
```

Ada tombol Pilih file, kolom kunci SM4, tombol List / Unpack / Repack,
dan panel log. Catatan: butuh layar grafis, jadi tidak jalan di Termux.

### 5. Alur modding lengkap (contoh PUBG Mobile)

```bash
# 1. Cari kunci SM4 versi gamemu pakai SM4 finder (dari libUE4.so),
#    mis. dapat: aJ4pV7iZ7pU4wP2aC2cZ... (32 hex char)

# 2. Unpack pak gamenya
python3 paktool.py --key <key> unpack game_patch_4.6.0.21542.pak -o bongkar/

# 3. Edit file di dalam folder bongkar/ sesukamu

# 4. Repack lagi (pakai key yang sama biar game bisa baca)
python3 paktool.py --key <key> repack bongkar/ -o game_patch_4.6.0.21542_baru.pak
```

### 6. Kalau error

| Pesan | Artinya | Solusi |
|---|---|---|
| `footer pak tidak dikenali` | layout footer beda dari standar | sesuaikan `FOOTER_CANDIDATES` di `paktool.py` |
| `terenkripsi — berikan --key` | butuh kunci SM4 | isi `--key` / kolom kunci |
| `metode kompresi 'X' belum didukung` | pakai kompresi selain zlib | laporkan biar ditambahkan |
| `jumlah entry tidak wajar` | index gagal diparse (mungkin diobfuscate) | pak versi itu butuh penanganan khusus |

---

## Format PUBG Mobile asli (rewrite 6 Okt 2026)

Tool ini sekarang mengikuti format asli PUBG Mobile (hasil riset GitHub/forum):
- Footer 45 byte + extended — field di-obfuscate cipher ZUC-128
- Index: AES-256-CBC (pak v>7, kunci via unwrap RSA) atau XOR 0x79 (v≤7)
- Payload per-file: SIMPLE1 (XOR 0x79), SIMPLE2 (rolling XOR `0xE55B4ED1`),
  atau SM4 **custom Tencent** (SBOX/FK/CK beda dari SM4 standar!) dengan
  kunci per-file `SHA1(nama_file + secret)`
- Semua kripto ditulis murni Python stdlib (`zuc.py`, `pyaes.py`, `tsm4.py`)
- Referensi: [iMikano/PUBG-Unpacker](https://github.com/iMikano/PUBG-Unpacker)
- Batasan jujur: belum ada repacker open-source terverifikasi untuk
  era SM4 — tool ini unpack-only untuk format PUBG (repack = UE4 standar)

## Yang sudah terverifikasi (dites di sini)

- **SM4** (`sm4.py`): lolos test vector standar GB/T 32907-2016
  (`key=plain=0123456789abcdeffedcba9876543210` → `681edf34...e4246`)
  + 30 blok acak cocok dengan implementasi referensi (gmssl).
- **Round-trip**: repack → unpack → file identik byte-per-byte, untuk:
  - tanpa enkripsi dan dengan enkripsi SM4,
  - file kosong, file kecil, file kelipatan 16 byte, file 16 KB acak,
    nama file berisi spasi, folder bertingkat.
- Footer terdeteksi adaptif (coba 48/49/65 byte, validasi magic + offset index).

## Yang BELUM terverifikasi (butuh tes di file asli)

- **Pak PUBG Mobile asli**: format dasarnya standar UE4, tapi versi 4.6.0
  memakai ofbuskasi index ("SIMPLE2" menurut tool komunitas) dan layout
  footer yang mungkin beda dari yang ditulis tool ini. Kalau `list` gagal /
  entry ngaco di file asli, sesuaikan `FOOTER_CANDIDATES` / parsing index
  di `paktool.py`.
- **Repack untuk dipakai game**: repack di sini valid secara struktural
  (hash index SHA1 dihitung ulang), tapi game bisa menolak pak yang
  tanda tangannya tidak cocok — itu di luar jangkauan tool ini.

## Catatan

- Folder kosong tidak disimpan di dalam pak (hanya file).
- Metode kompresi yang didukung: none + zlib. Metode lain → error jelas.
- Kunci SM4 yang benar per versi game — cari dengan SM4 finder dari
  `libUE4.so` game yang sesuai versinya.
