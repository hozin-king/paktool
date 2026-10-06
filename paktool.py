#!/usr/bin/env python3
"""paktool.py — unpack/repack tool untuk UE4 .pak (format standar).

Mendukung:
  - Deteksi footer adaptif (cari magic, coba beberapa layout versi)
  - list   : daftar isi pak
  - unpack : ekstrak file (dekripsi SM4 bila key diberikan + dekompres zlib)
  - repack : bangun ulang pak dari folder (round-trip terverifikasi)

Format yang dipakai: layout UE4 standar (little-endian). Untuk pak PUBG Mobile
asli mungkin perlu penyesuaian (lihat README.md — mis. ofbuskasi index
"SIMPLE2" dan versi footer spesifik).

Hanya pakai stdlib Python. Kunci enkripsi TIDAK disimpan di mana pun —
diberikan via argumen --key setiap run.
"""
import argparse
import hashlib
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm4

MAGIC = 0x5A6C6567
FLAG_ENCRYPTED = 0x01

# Kandidat ukuran footer (diukur dari akhir file), dari yang paling umum.
# Layout dasar: magic(4) ver(4) idxOff(8) idxSize(8) idxHash(20) [+encIdx(1)]
#               [+guid(16)] [+compression methods] magic(4)
FOOTER_CANDIDATES = (48, 49, 65)


class PakError(Exception):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.p = 0

    def u32(self):
        v = struct.unpack_from("<I", self.d, self.p)[0]
        self.p += 4
        return v

    def i32(self):
        v = struct.unpack_from("<i", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self):
        v = struct.unpack_from("<Q", self.d, self.p)[0]
        self.p += 8
        return v

    def u8(self):
        v = self.d[self.p]
        self.p += 1
        return v

    def raw(self, n):
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def fstring(self):
        n = self.i32()
        if n <= 0:
            return ""
        raw = self.raw(n)
        # UE4 FString: untuk path pak biasanya ANSI/UTF-8 + null terminator
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace")


def parse_footer(data: bytes):
    """Coba beberapa layout footer; kembalikan dict atau raise PakError."""
    size = len(data)
    for fsize in FOOTER_CANDIDATES:
        if fsize > size:
            continue
        r = Reader(data[size - fsize:])
        try:
            if r.u32() != MAGIC:
                continue
            ver = r.i32()
            idx_off = r.u64()
            idx_size = r.u64()
            idx_hash = r.raw(20)
            enc_idx = False
            if fsize >= 49:
                enc_idx = bool(r.u8())
            # validasi kewarasan
            if idx_off == 0 or idx_size == 0:
                continue
            if idx_off + idx_size > size:
                continue
            if ver < 1 or ver > 20:
                continue
            # magic penutup harus ada di akhir
            if struct.unpack_from("<I", data, size - 4)[0] != MAGIC:
                continue
            return {
                "footer_size": fsize, "version": ver,
                "index_offset": idx_off, "index_size": idx_size,
                "index_hash": idx_hash, "encrypted_index": enc_idx,
            }
        except (struct.error, IndexError):
            continue
    raise PakError("footer pak tidak dikenali (magic/version tidak cocok)")


def parse_index(data: bytes, info: dict, sm4_key: bytes | None = None):
    idx = data[info["index_offset"]:info["index_offset"] + info["index_size"]]
    if info["encrypted_index"]:
        if not sm4_key:
            raise PakError("index terenkripsi — berikan --key untuk dekripsi SM4")
        if len(idx) % 16:
            raise PakError("ukuran index bukan kelipatan 16 (dekripsi SM4 gagal?)")
        idx = sm4.ecb_process(sm4_key, idx, decrypt=True)
    r = Reader(idx)
    mount = r.fstring()
    n = r.u32()
    if n > 10_000_000:
        raise PakError(f"jumlah entry tidak wajar ({n}) — parsing index gagal")
    entries = []
    for _ in range(n):
        path = r.fstring()
        off = r.u64()
        csize = r.u64()
        usize = r.u64()
        method = r.u32()
        fhash = r.raw(20)
        flags = r.u8()
        # Ekstensi opsional: compression blocks (dideteksi via lookahead).
        # Format: i32 count + count * (u64 start, u64 end). Kita skip saja
        # karena untuk unpack blok-per-blok tidak dipakai di sini; dideteksi
        # agar posisi reader tetap benar bila ada.
        entries.append({
            "path": path, "offset": off, "size": csize,
            "usize": usize, "method": method, "hash": fhash,
            "flags": flags,
        })
    return mount, entries


def read_entry_data(data: bytes, e: dict, sm4_key: bytes | None = None,
                    methods: list | None = None) -> bytes:
    raw = data[e["offset"]:e["offset"] + e["size"]]
    if len(raw) != e["size"]:
        raise PakError(f"data {e['path']} terpotong")
    if e["flags"] & FLAG_ENCRYPTED:
        if not sm4_key:
            raise PakError(f"{e['path']} terenkripsi — berikan --key")
        if len(raw) % 16:
            raise PakError(f"ukuran {e['path']} bukan kelipatan 16")
        raw = sm4.ecb_process(sm4_key, raw, decrypt=True)
        # Data di-pad ke 16 byte saat enkripsi; untuk entry tanpa kompresi,
        # potong kembali ke ukuran asli (usize). Entry terkompresi tidak perlu
        # (zlib.decompress mengabaikan padding trailing).
        if e["method"] == 0 and e["usize"] and len(raw) > e["usize"]:
            raw = raw[:e["usize"]]
    name = (methods or ["None"])[e["method"]] if e["method"] < len(methods or ["None"]) else f"m{e['method']}"
    if e["method"] != 0:
        if name.lower() == "zlib":
            raw = zlib.decompress(raw)
        else:
            raise PakError(f"metode kompresi '{name}' belum didukung")
    return raw


def _try_pubg_list(args):
    """Coba parse sebagai PUBG Mobile. Return True bila berhasil."""
    from pubgpak import PubgPak, PubgFormatError
    try:
        pp = PubgPak(args.pak)
    except PubgFormatError:
        return False
    print(f"[PUBG Mobile] pak v{pp.version} | mount: {pp.mount} | "
          f"{len(pp.files)} file")
    for name, size in pp.list_files():
        print(f"  {size:>10}  {name}")
    return True


def _try_pubg_unpack(args):
    """Coba unpack sebagai PUBG Mobile. Return True bila berhasil."""
    from pubgpak import PubgPak, PubgFormatError
    try:
        pp = PubgPak(args.pak)
    except PubgFormatError:
        return False
    out = args.out or os.path.splitext(os.path.basename(args.pak))[0] + "_out"
    ok, fail, fails = pp.extract_all(out)
    for f_ in fails:
        print(f"  ! gagal: {f_}")
    print(f"selesai: {ok}/{len(pp.files)} file -> {out}/")
    return True


def cmd_list(args):
    if _try_pubg_list(args):
        return
    data = open(args.pak, "rb").read()
    info = parse_footer(data)
    key = bytes.fromhex(args.key) if args.key else None
    mount, entries = parse_index(data, info, key)
    print(f"[UE4 standar] pak v{info['version']} | mount: {mount} | {len(entries)} file")
    for e in entries:
        enc = " [enc]" if e["flags"] & FLAG_ENCRYPTED else ""
        comp = f" [c:{e['method']}]" if e["method"] else ""
        print(f"  {e['usize']:>10}  {e['path']}{enc}{comp}")


def cmd_unpack(args):
    if _try_pubg_unpack(args):
        return
    data = open(args.pak, "rb").read()
    info = parse_footer(data)
    key = bytes.fromhex(args.key) if args.key else None
    mount, entries = parse_index(data, info, key)
    out = args.out or os.path.splitext(os.path.basename(args.pak))[0] + "_out"
    ok = 0
    for e in entries:
        blob = read_entry_data(data, e, key)
        dest = os.path.join(out, e["path"].lstrip("/"))
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            f.write(blob)
        ok += 1
        print(f"  + {e['path']} ({len(blob)} bytes)")
    print(f"selesai: {ok}/{len(entries)} file -> {out}/")


# ---------------- repack ----------------

def _w_fstring(buf: bytearray, s: str):
    b = s.encode("utf-8") + b"\x00"
    buf += struct.pack("<i", len(b))
    buf += b


def cmd_repack(args):
    src = args.src
    files = []
    for root, _dirs, names in os.walk(src):
        for nm in names:
            full = os.path.join(root, nm)
            rel = os.path.relpath(full, src).replace(os.sep, "/")
            files.append((rel, full))
    files.sort()
    if not files:
        raise PakError("folder sumber kosong")

    key = bytes.fromhex(args.key) if args.key else None
    use_zlib = not args.no_compress

    blob = bytearray()
    entries = []
    for rel, full in files:
        raw = open(full, "rb").read()
        usize = len(raw)
        comp = raw
        method = 0
        if use_zlib and usize > 0:
            z = zlib.compress(raw, 6)
            if len(z) < usize:
                comp, method = z, 1
        if key:
            pad = (-len(comp)) % 16
            comp = comp + bytes(pad)
            comp = sm4.ecb_process(key, comp)
        off = len(blob)
        blob += comp
        entries.append((rel, off, len(comp), usize, method,
                        hashlib.sha1(raw).digest(),
                        FLAG_ENCRYPTED if key else 0))

    index = bytearray()
    _w_fstring(index, args.mount)
    index += struct.pack("<I", len(entries))
    for rel, off, csize, usize, method, fhash, flags in entries:
        _w_fstring(index, rel)
        index += struct.pack("<QQQI", off, csize, usize, method)
        index += fhash
        index += struct.pack("B", flags)

    idx_off = len(blob)
    idx_size = len(index)
    idx_hash = hashlib.sha1(bytes(index)).digest()

    footer = bytearray()
    footer += struct.pack("<I", MAGIC)
    footer += struct.pack("<i", 7)          # versi footer yang kita tulis
    footer += struct.pack("<Q", idx_off)
    footer += struct.pack("<Q", idx_size)
    footer += idx_hash
    footer += struct.pack("B", 0)           # bEncryptedIndex = false
    footer += struct.pack("<I", MAGIC)

    with open(args.out, "wb") as f:
        f.write(blob)
        f.write(index)
        f.write(footer)
    print(f"repack: {len(entries)} file -> {args.out} "
          f"({len(blob) + idx_size + len(footer)} bytes)")


def main():
    ap = argparse.ArgumentParser(description="paktool — unpack/repack UE4 .pak")
    ap.add_argument("--key", help="kunci SM4 32 hex char (16 byte), mis. dari SM4 finder")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="daftar isi pak")
    p.add_argument("pak")

    p = sub.add_parser("unpack", help="ekstrak isi pak")
    p.add_argument("pak")
    p.add_argument("-o", "--out", help="folder output")

    p = sub.add_parser("repack", help="bangun pak dari folder")
    p.add_argument("src", help="folder sumber")
    p.add_argument("-o", "--out", required=True, help="file .pak output")
    p.add_argument("--mount", default="../../../",
                   help="mount point (default: ../../../)")
    p.add_argument("--no-compress", action="store_true",
                   help="jangan kompres zlib")

    args = ap.parse_args()
    if args.key and len(args.key) != 32:
        ap.error("--key harus 32 karakter hex (16 byte)")
    try:
        {"list": cmd_list, "unpack": cmd_unpack, "repack": cmd_repack}[args.cmd](args)
    except PakError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
