#!/usr/bin/env python3
"""paktool TUI — antarmuka terminal ala tool modding (ANSI colors).

Murni Python stdlib, tanpa dependensi. Jalan di Termux, Linux, Mac, Windows 10+.

Jalankan:  python3 paktool_tui.py
"""
import glob
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paktool  # noqa: E402
import sm4  # noqa: E402  (pastikan modul termuat)

USE_COLOR = sys.stdout.isatty()

C = {
    "green": "\033[1;32m", "yellow": "\033[1;33m", "red": "\033[1;31m",
    "cyan": "\033[1;36m", "white": "\033[1;37m", "dim": "\033[2m",
    "reset": "\033[0m",
}


def c(name, s):
    return f"{C[name]}{s}{C['reset']}" if USE_COLOR else s


def banner():
    t = time.strftime("%d-%m-%Y %H:%M:%S")
    w = 56
    print(c("green", "┌" + "─" * w + "┐"))
    print(c("green", "│") + c("yellow", "  ⚡  P A K T O O L  ⚡".center(w)) + c("green", "│"))
    print(c("green", "│") + c("cyan", f"  {t}".ljust(w)) + c("green", "│"))
    print(c("green", "│") + c("dim", "  UE4 .pak unpack / repack (SM4)".ljust(w)) + c("green", "│"))
    print(c("green", "└" + "─" * w + "┘"))


def box_btn(label):
    print(c("cyan", f"  ┌{'─' * (len(label) + 4)}┐"))
    print(c("cyan", "  │ ") + c("white", f" {label} ") + c("cyan", " │"))
    print(c("cyan", f"  └{'─' * (len(label) + 4)}┘"))


def progress(done, total, prefix=""):
    width = 34
    pct = done / total if total else 1
    fill = int(width * pct)
    bar = "█" * fill + "░" * (width - fill)
    line = f"\r{prefix} [{bar}] {pct * 100:5.1f}%  ({done}/{total})"
    sys.stdout.write(c("yellow", line) if USE_COLOR else line)
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")


def pause():
    input(c("yellow", "\nPress Enter untuk lanjut..."))


def pick_pak():
    files = sorted(glob.glob("*.pak") + glob.glob("*.PAK"))
    if files:
        print(c("white", "\n  File .pak di folder ini:"))
        for i, f in enumerate(files, 1):
            print(f"   {c('cyan', str(i))}. {f}")
        print(f"   {c('cyan', '0')}. ketik path manual")
        try:
            n = int(input(c("yellow", "  Pilih [0-%d]: " % len(files))) or "0")
        except (ValueError, EOFError):
            return None
        if 1 <= n <= len(files):
            return files[n - 1]
    p = input(c("yellow", "  Path file .pak: ")).strip()
    return p or None


def ask_key():
    k = input(c("yellow", "  Kunci SM4 (32 hex, kosongkan bila tidak dienkripsi): ")).strip()
    if not k:
        return None
    if len(k) != 32 or any(ch not in "0123456789abcdefABCDEF" for ch in k):
        print(c("red", "  ✗ kunci harus 32 karakter hex!"))
        return "INVALID"
    return bytes.fromhex(k)


def do_list():
    pak = pick_pak()
    if not pak or not os.path.isfile(pak):
        print(c("red", "  ✗ file tidak ditemukan")); return
    key = ask_key()
    if key == "INVALID":
        return
    try:
        data = open(pak, "rb").read()
        info = paktool.parse_footer(data)
        mount, entries = paktool.parse_index(data, info, key)
        print(c("green", f"\n  ✓ {len(entries)} file  |  pak v{info['version']}  |  mount: {mount}"))
        for e in entries:
            tag = c("red", " [enc]") if e["flags"] & paktool.FLAG_ENCRYPTED else ""
            print(f"    {e['usize']:>10}  {e['path']}{tag}")
    except paktool.PakError as e:
        print(c("red", f"  ✗ error: {e}"))
    pause()


def do_unpack():
    pak = pick_pak()
    if not pak or not os.path.isfile(pak):
        print(c("red", "  ✗ file tidak ditemukan")); return
    key = ask_key()
    if key == "INVALID":
        return
    out = input(c("yellow", "  Folder output [hasil_unpack]: ")).strip() or "hasil_unpack"
    try:
        data = open(pak, "rb").read()
        info = paktool.parse_footer(data)
        mount, entries = paktool.parse_index(data, info, key)
        print(c("yellow", f"\n  ▶ UNPACKING {os.path.basename(pak)}"))
        ok, fail = 0, 0
        for i, e in enumerate(entries, 1):
            try:
                blob = paktool.read_entry_data(data, e, key)
                dest = os.path.join(out, e["path"].lstrip("/"))
                os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(blob)
                ok += 1
            except paktool.PakError:
                fail += 1
            progress(i, len(entries), prefix="  ")
        print(c("green", f"  ✓ Done: {ok}") + (c("red", f"   ✗ Errors: {fail}") if fail else ""))
        print(c("green", f"  ✓ Unpacked to: {os.path.abspath(out)}"))
    except paktool.PakError as e:
        print(c("red", f"  ✗ error: {e}"))
    pause()


def do_repack():
    src = input(c("yellow", "  Folder sumber: ")).strip()
    if not src or not os.path.isdir(src):
        print(c("red", "  ✗ folder tidak ditemukan")); return
    out = input(c("yellow", "  Nama file .pak output [baru.pak]: ")).strip() or "baru.pak"
    key = ask_key()
    if key == "INVALID":
        return
    z = input(c("yellow", "  Kompres zlib? [Y/n]: ")).strip().lower() != "n"
    print(c("yellow", f"\n  ▶ REPACKING -> {out}"))
    files = []
    for root, _d, names in os.walk(src):
        for nm in names:
            full = os.path.join(root, nm)
            files.append((os.path.relpath(full, src).replace(os.sep, "/"), full))
    files.sort()
    import hashlib
    import struct
    import zlib as _zlib
    blob = bytearray()
    entries = []
    for i, (rel, full) in enumerate(files, 1):
        raw = open(full, "rb").read()
        comp, method = (raw, 0) if not z else (_zlib.compress(raw, 6), 1)
        if z and len(comp) >= len(raw):
            comp, method = raw, 0
        if key:
            comp = comp + bytes((-len(comp)) % 16)
            comp = sm4.ecb_process(key, comp)
        off = len(blob)
        blob += comp
        entries.append((rel, off, len(comp), len(raw), method,
                        hashlib.sha1(raw).digest(),
                        paktool.FLAG_ENCRYPTED if key else 0))
        progress(i, len(files), prefix="  ")
    index = bytearray()
    # mount point sebagai FString
    mb = "../../../".encode() + b"\x00"
    index += struct.pack("<i", len(mb)) + mb
    index += struct.pack("<I", len(entries))
    for rel, off, csz, usz, method, fh, fl in entries:
        b = rel.encode() + b"\x00"
        index += struct.pack("<i", len(b)) + b
        index += struct.pack("<QQQI", off, csz, usz, method) + fh + struct.pack("B", fl)
    idx_off, idx_size = len(blob), len(index)
    footer = struct.pack("<IiQQ", paktool.MAGIC, 7, idx_off, idx_size)
    footer += hashlib.sha1(bytes(index)).digest() + struct.pack("B", 0)
    footer += struct.pack("<I", paktool.MAGIC)
    with open(out, "wb") as f:
        f.write(blob); f.write(index); f.write(footer)
    print(c("green", f"  ✓ Done: {len(entries)} files -> {out}"))
    pause()


def main():
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        banner()
        print(c("yellow", "\n  ▶ PILIH MODE\n"))
        box_btn("1. List isi .pak")
        box_btn("2. Unpack .pak")
        box_btn("3. Repack folder -> .pak")
        box_btn("4. Keluar")
        try:
            ch = input(c("white", "\n  > ")).strip()
        except EOFError:
            break
        if ch == "1":
            do_list()
        elif ch == "2":
            do_unpack()
        elif ch == "3":
            do_repack()
        elif ch == "4":
            print(c("green", "\n  Bye! 👋\n"))
            break


if __name__ == "__main__":
    main()
