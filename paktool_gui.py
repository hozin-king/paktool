#!/usr/bin/env python3
"""paktool GUI — antarmuka grafis (tkinter, stdlib saja) untuk paktool.py.

Jalankan:  python3 paktool_gui.py
Butuh display grafis (jalan di PC/laptop; di Termux pakai CLI paktool.py).
"""
import io
import os
import queue
import sys
import threading
from contextlib import redirect_stdout
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import paktool  # noqa: E402


def run_paktool(cmd, key=None, **kwargs):
    """Jalankan perintah paktool, kembalikan (sukses: bool, output: str).

    Fungsi ini murni logika (tanpa tkinter) sehingga bisa dites headless.
    """
    if key:
        key = key.strip()
        if len(key) != 32 or any(c not in "0123456789abcdefABCDEF" for c in key):
            return False, "error: kunci SM4 harus 32 karakter hex (16 byte)"
    args = SimpleNamespace(key=key or None, **kwargs)
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            {"list": paktool.cmd_list,
             "unpack": paktool.cmd_unpack,
             "repack": paktool.cmd_repack}[cmd](args)
        return True, buf.getvalue()
    except paktool.PakError as e:
        return False, f"error: {e}\n{buf.getvalue()}"
    except Exception as e:  # noqa: BLE001
        return False, f"error tak terduga: {e}\n{buf.getvalue()}"


# ---------------- GUI ----------------

def main_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("paktool — UE4 .pak unpack / repack")
    root.geometry("640x520")

    log_q = queue.Queue()

    # --- form ---
    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="x")

    pak_var = tk.StringVar()
    key_var = tk.StringVar()
    out_var = tk.StringVar()
    src_var = tk.StringVar()
    repack_out_var = tk.StringVar()
    zlib_var = tk.BooleanVar(value=True)

    def row(label, var, browse, browsetype="file"):
        ttk.Label(frm, text=label).pack(anchor="w")
        r = ttk.Frame(frm)
        r.pack(fill="x", pady=(0, 6))
        ent = ttk.Entry(r, textvariable=var)
        ent.pack(side="left", fill="x", expand=True)
        def pick():
            if browsetype == "file":
                p = filedialog.askopenfilename(filetypes=[("Pak files", "*.pak"), ("All", "*.*")])
            else:
                p = filedialog.askdirectory()
            if p:
                var.set(p)
        ttk.Button(r, text="Pilih...", command=pick).pack(side="left", padx=(6, 0))
        return ent

    row("File .pak:", pak_var, True, "file")
    key_ent = row("Kunci SM4 (opsional, 32 hex char):", key_var, False)
    key_ent.config(show="*")
    row("Folder output (unpack):", out_var, True, "dir")
    row("Folder sumber (repack):", src_var, True, "dir")

    ttk.Label(frm, text="Nama file .pak output (repack):").pack(anchor="w")
    ttk.Entry(frm, textvariable=repack_out_var).pack(fill="x", pady=(0, 6))
    ttk.Checkbutton(frm, text="Kompres zlib saat repack", variable=zlib_var).pack(anchor="w")

    # --- tombol ---
    btns = ttk.Frame(root, padding=(10, 0))
    btns.pack(fill="x")
    btn_list = ttk.Button(btns, text="List isi")
    btn_unpack = ttk.Button(btns, text="Unpack")
    btn_repack = ttk.Button(btns, text="Repack")
    for b in (btn_list, btn_unpack, btn_repack):
        b.pack(side="left", padx=(0, 8))

    # --- log ---
    log = tk.Text(root, height=14, state="disabled", wrap="word")
    log.pack(fill="both", expand=True, padx=10, pady=10)
    scroll = ttk.Scrollbar(log, command=log.yview)
    scroll.pack(side="right", fill="y")
    log.config(yscrollcommand=scroll.set)

    def log_write(s):
        log.config(state="normal")
        log.insert("end", s)
        log.see("end")
        log.config(state="disabled")

    def poll():
        while True:
            try:
                line = log_q.get_nowait()
            except queue.Empty:
                break
            if line is None:  # selesai
                for b in (btn_list, btn_unpack, btn_repack):
                    b.config(state="normal")
            else:
                log_write(line)
        root.after(120, poll)

    def run_async(cmd, **kwargs):
        key = key_var.get().strip() or None
        for b in (btn_list, btn_unpack, btn_repack):
            b.config(state="disabled")
        log_write(f"\n$ paktool {cmd} ...\n")

        def worker():
            ok, out = run_paktool(cmd, key=key, **kwargs)
            log_q.put(out if out.endswith("\n") else out + "\n")
            if not ok:
                log_q.put("SELESAI DENGAN ERROR\n")
            else:
                log_q.put("SELESAI\n")
            log_q.put(None)

        threading.Thread(target=worker, daemon=True).start()

    def need_pak():
        p = pak_var.get().strip()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("paktool", "Pilih file .pak dulu.")
            return None
        return p

    btn_list.config(command=lambda: (lambda p: p and run_async("list", pak=p))(need_pak()))

    def do_unpack():
        p = need_pak()
        if not p:
            return
        o = out_var.get().strip() or None
        run_async("unpack", pak=p, out=o)

    def do_repack():
        s = src_var.get().strip()
        o = repack_out_var.get().strip()
        if not s or not os.path.isdir(s):
            messagebox.showwarning("paktool", "Pilih folder sumber dulu.")
            return
        if not o:
            messagebox.showwarning("paktool", "Isi nama file .pak output.")
            return
        run_async("repack", src=s, out=o, mount="../../../",
                  no_compress=not zlib_var.get())

    btn_unpack.config(command=do_unpack)
    btn_repack.config(command=do_repack)

    root.after(120, poll)
    root.mainloop()


if __name__ == "__main__":
    main_gui()
