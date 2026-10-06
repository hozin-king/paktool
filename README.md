# paktool — unpack/repack UE4 .pak (Python, tanpa library tambahan)

Tool baris perintah untuk membaca dan membangun ulang file `.pak` Unreal Engine 4
(format standar). Ditulis murni Python stdlib — jalan di Termux / PC tanpa
`pip install` apa pun.

```
python3 paktool.py list game.pak
python3 paktool.py unpack game.pak -o hasil/
python3 paktool.py --key <32 hex char> unpack game.pak -o hasil/
python3 paktool.py repack folder_sumber -o baru.pak
python3 paktool.py --key <32 hex char> repack folder_sumber -o baru.pak
```

`--key` = kunci SM4 (16 byte dalam 32 karakter hex), mis. hasil dari SM4 finder.
Kunci tidak pernah disimpan — hanya dipakai saat run.

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

## Versi GUI (tampilan grafis)

```
python3 paktool_gui.py
```

Ada tombol Pilih file, kolom kunci SM4, tombol List / Unpack / Repack, dan
panel log. Murni tkinter (bawaan Python, tanpa install tambahan).

Catatan: GUI butuh layar grafis — jalan di PC/laptop. Di Termux (tanpa X
server) pakai versi CLI `paktool.py` di atas.
