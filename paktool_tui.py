#!/usr/bin/env python3
"""paktool TUI — tool gabungan: Unpack / Repack / Find SM4 / List.

- Auto-scan file .pak di folder tiap menu ditampilkan (file yang baru
  ditambah langsung kebaca, tanpa restart).
- Format terdeteksi otomatis: PUBG Mobile (footer ZUC, index AES/RSA,
  payload SIMPLE1/SIMPLE2/SM4-custom) atau UE4 standar (fallback).
- Murni Python stdlib, tanpa dependensi. Jalan di Termux.

Jalankan:  python3 paktool_tui.py
"""
import glob
import os
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import paktool as _cli  # parser UE4 standar (fallback) + repack
from pubgpak import PubgPak, PubgFormatError
from sm4finder import find_secrets

USE_COLOR = sys.stdout.isatty()

C = {
    "green": "\033[1;32m", "yellow": "\033[1;33m", "red": "\033[1;31m",
    "cyan": "\033[1;36m", "white": "\033[1;37m", "dim": "\033[2m",
    "reset": "\033[0m",
}


def c(name, s):
    return f"{C[name]}{s}{C['reset']}" if USE_COLOR else s


def banner(n_pak):
    t = time.strftime("%d-%m-%Y %H:%M:%S")
    w = 56
    print(c("green", "┌" + "─" * w + "┐"))
    print(c("green", "│") + c("yellow", "  ⚡  P A K T O O L  ⚡".center(w)) + c("green", "│"))
    print(c("green", "│") + c("cyan", f"  {t}".ljust(w)) + c("green", "│"))
    print(c("green", "│") + c("dim", f"  {n_pak} file .pak terdeteksi di folder ini".ljust(w)) + c("green", "│"))
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


def scan_paks():
    """Auto-scan .pak — dipanggil tiap menu tampil, jadi file baru kebaca."""
    return sorted(glob.glob("*.pak") + glob.glob("*.PAK"))


def pick_pak(files):
    if files:
        print(c("white", "\n  File .pak terdeteksi:"))
        for i, f in enumerate(files, 1):
            sz = os.path.getsize(f)
            unit = "MB" if sz > 1 << 20 else "KB"
            v = sz / (1 << 20) if sz > 1 << 20 else sz / 1024
            print(f"   {c('cyan', str(i))}. {f}  {c('dim', f'({v:.1f} {unit})')}")
        print(f"   {c('cyan', '0')}. ketik path manual")
        try:
            n = int(input(c("yellow", "  Pilih [0-%d]: " % len(files))) or "0")
        except (ValueError, EOFError):
            return None
        if 1 <= n <= len(files):
            return files[n - 1]
    p = input(c("yellow", "  Path file .pak: ")).strip()
    return p or None


def open_pak(path):
    """Buka pak: coba format PUBG Mobile dulu, fallback ke UE4 standar."""
    try:
        pp = PubgPak(path)
        return ("pubg", pp)
    except PubgFormatError:
        pass
    except Exception as e:
        return ("error", f"{e}")
    # fallback UE4 standar
    try:
        data = open(path, "rb").read()
        info = _cli.parse_footer(data)
        return ("ue4", (data, info))
    except _cli.PakError as e:
        return ("error", f"bukan format PUBG Mobile maupun UE4 standar: {e}")


def do_list(files):
    pak = pick_pak(files)
    if not pak or not os.path.isfile(pak):
        print(c("red", "  ✗ file tidak ditemukan"))
        return
    kind, obj = open_pak(pak)
    if kind == "error":
        print(c("red", f"  ✗ {obj}"))
        return
    if kind == "pubg":
        print(c("green", f"\n  ✓ format: PUBG Mobile  |  pak v{obj.version}  |  {len(obj.files)} file"))
        print(c("dim", f"    mount: {obj.mount}"))
        for name, size in obj.list_files():
            print(f"    {size:>10}  {name}")
    else:
        data, info = obj
        key = _ask_key_std()
        if key == "INVALID":
            return
        try:
            mount, entries = _cli.parse_index(data, info, key)
        except _cli.PakError as e:
            print(c("red", f"  ✗ {e}"))
            return
        print(c("green", f"\n  ✓ format: UE4 standar  |  {len(entries)} file  |  mount: {mount}"))
        for e in entries:
            print(f"    {e['usize']:>10}  {e['path']}")
    pause()


def _ask_key_std():
    k = input(c("yellow", "  Kunci SM4 (32 hex, kosongkan bila tidak perlu): ")).strip()
    if not k:
        return None
    if len(k) != 32 or any(ch not in "0123456789abcdefABCDEF" for ch in k):
        print(c("red", "  ✗ kunci harus 32 karakter hex!"))
        return "INVALID"
    return bytes.fromhex(k)


def do_unpack(files):
    pak = pick_pak(files)
    if not pak or not os.path.isfile(pak):
        print(c("red", "  ✗ file tidak ditemukan"))
        return
    out = input(c("yellow", "  Folder output [hasil_unpack]: ")).strip() or "hasil_unpack"
    kind, obj = open_pak(pak)
    if kind == "error":
        print(c("red", f"  ✗ {obj}"))
        return
    print(c("yellow", f"\n  ▶ UNPACKING {os.path.basename(pak)}"))
    if kind == "pubg":
        def cb(i, total):
            progress(i, total, prefix="  ")
        ok, fail, fails = obj.extract_all(out, progress_cb=cb)
        print(c("green", f"  ✓ Done: {ok} file") +
              (c("red", f"   ✗ gagal: {fail}") if fail else ""))
        for f_ in fails[:10]:
            print(c("red", f"    - {f_}"))
        if len(fails) > 10:
            print(c("dim", f"    ... +{len(fails) - 10} lagi"))
        print(c("green", f"  ✓ Hasil di: {os.path.abspath(out)}"))
    else:
        data, info = obj
        key = _ask_key_std()
        if key == "INVALID":
            return
        try:
            _mount, entries = _cli.parse_index(data, info, key)
        except _cli.PakError as e:
            print(c("red", f"  ✗ {e}"))
            return
        ok = fail = 0
        for i, e in enumerate(entries, 1):
            try:
                blob = _cli.read_entry_data(data, e, key)
                dest = os.path.join(out, e["path"].lstrip("/"))
                os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(blob)
                ok += 1
            except _cli.PakError:
                fail += 1
            progress(i, len(entries), prefix="  ")
        print(c("green", f"  ✓ Done: {ok}") + (c("red", f"   ✗ gagal: {fail}") if fail else ""))
        print(c("green", f"  ✓ Hasil di: {os.path.abspath(out)}"))
    pause()


def do_repack():
    src = input(c("yellow", "  Folder sumber: ")).strip()
    if not src or not os.path.isdir(src):
        print(c("red", "  ✗ folder tidak ditemukan"))
        return
    out = input(c("yellow", "  Nama file .pak output [baru.pak]: ")).strip() or "baru.pak"
    key = _ask_key_std()
    if key == "INVALID":
        return
    z = input(c("yellow", "  Kompres zlib? [Y/n]: ")).strip().lower() != "n"
    print(c("yellow", f"\n  ▶ REPACKING -> {out}"))
    print(c("dim", "    (format UE4 standar — repack format PUBG butuh private key RSA game)"))
    n = [0]
    import io
    from contextlib import redirect_stdout
    args = SimpleNamespace(key=key, src=src, out=out,
                           mount="../../../", no_compress=not z)
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            _cli.cmd_repack(args)
        print(c("green", f"  ✓ {buf.getvalue().strip()}"))
    except _cli.PakError as e:
        print(c("red", f"  ✗ {e}"))
    pause()


def do_find_sm4():
    sos = sorted(glob.glob("*.so") + glob.glob("*.SO"))
    so = None
    if sos:
        print(c("white", "\n  File .so terdeteksi:"))
        for i, f in enumerate(sos, 1):
            print(f"   {c('cyan', str(i))}. {f}")
        print(f"   {c('cyan', '0')}. ketik path manual")
        try:
            n = int(input(c("yellow", "  Pilih [0-%d]: " % len(sos))) or "0")
        except (ValueError, EOFError):
            return
        if 1 <= n <= len(sos):
            so = sos[n - 1]
    if not so:
        so = input(c("yellow", "  Path libUE4.so: ")).strip()
    if not so or not os.path.isfile(so):
        print(c("red", "  ✗ file tidak ditemukan"))
        return
    print(c("yellow", f"\n  ▶ SCANNING {os.path.basename(so)} ..."))
    try:
        res = find_secrets(so)
    except Exception as e:
        print(c("red", f"  ✗ {e}"))
        return
    mb = res["scanned_bytes"] / (1 << 20)
    print(c("dim", f"    discan: {mb:.1f} MB"))
    known = res["known_found"]
    if known:
        print(c("green", f"\n  ✓ Secret dikenal ditemukan ({len(known)}):"))
        for k in known:
            print(f"    {c('green', '●')} {k}")
        print(c("dim", "\n    Secret ini dipakai menurunkan kunci SM4 per-file saat unpack."))
        print(c("dim", "    Unpack PUBG otomatis pakai secret bawaan — tidak perlu input manual."))
    else:
        print(c("yellow", "\n  ! tidak ada secret yang dikenal — versi game mungkin lebih baru"))
    c16, c20 = res["candidates_16"], res["candidates_20hex"]
    if c16 or c20:
        print(c("yellow", f"\n  ? Kandidat pola secret ({len(c16) + len(c20)}):"))
        for s_ in (c16 + c20)[:15]:
            print(f"    - {s_}")
        if len(c16) + len(c20) > 15:
            print(c("dim", f"    ... +{len(c16) + len(c20) - 15} lagi"))
        print(c("dim", "    Kandidat belum tentu secret asli — cocokkan dengan hasil unpack."))
    pause()


def main():
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        files = scan_paks()  # auto-scan tiap menu tampil
        banner(len(files))
        print(c("yellow", "\n  ▶ PILIH MODE\n"))
        box_btn("1. Unpack .pak (auto-detect format)")
        box_btn("2. Repack folder -> .pak")
        box_btn("3. Find SM4 (scan libUE4.so)")
        box_btn("4. List isi .pak")
        box_btn("5. Keluar")
        try:
            ch = input(c("white", "\n  > ")).strip()
        except EOFError:
            break
        if ch == "1":
            do_unpack(files)
        elif ch == "2":
            do_repack()
        elif ch == "3":
            do_find_sm4()
        elif ch == "4":
            do_list(files)
        elif ch == "5":
            print(c("green", "\n  Bye! 👋\n"))
            break


if __name__ == "__main__":
    main()
