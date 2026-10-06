#!/usr/bin/env python3
"""Pemindai secret SM4 di libUE4.so — pure Python stdlib.

Mencari string secret yang dipakai PUBG Mobile untuk derivasi kunci
SM4 per-file (key = SHA1(lowercase(stem) + secret)[:16]).

Cara pakai:
    python3 sm4finder.py libUE4.so
"""
import hashlib
import re
import sys

# daftar secret yang dikenal (disalin dari referensi format PUBG Mobile)
SM4_SECRET_2 = "Q0hVTKey$as*1ZFlQCiA"
SM4_SECRET_4 = "eb691efea914241317a8"
SM4_SECRET_NEW = [
    "xG2qW5lP7lV2iN5fN5pG", "xT1cJ6dL5wC0kK1rB4dK",
    "qC4jS5bZ6fL5xE6nD4zA", "gD4jQ2aL3bS3lC3xT0iW",
    "xU1yQ8wE9zY3gZ3bT5aE", "uQ3cO2dX7xY4xU7gH7iS",
    "gW1fR0jK6wQ4oN0oK1kZ", "aJ4pV7iZ7pU4wP2aC2cZ",
    "cX6jT3cM2oT3vK0kJ1qN", "iT2vS0cS6yT6cZ1sE1lO",
    "hM1pH9iY8wM9hT4lN5uJ", "kG6bC8jK0fL0dE4sH4mL",
    "dB6lB3vE0eZ8wM8rI0aC", "tP7sP7nI9rA2vQ4cV5yQ",
    "aT0cL1yN4pT3sZ7eM2vY", "uV6fU8fC9zN3mP5dH8mN",
    "rT6aQ6oZ1yM0gO5tO1aN", "jU5bH7lQ0fM9hK2kI0oF",
    "iQ0eM0mJ7uT0kV6kL5zY", "wD2rP3lP9xF4mE1eC5jS",
    "rG0lR2rZ5vM6mW5lM1rR", "fO3kW1fE6eD0pU1kY7xK",
]
DYN_SM4_SECRETS = {
    0: "edbcba1dc6b11068b44a", 1: "4fdf06dd5830dea4a927",
    2: "92bd3c6ca58d471b03df", 3: "5267814520c2b1904294",
    4: "f31085d8cefbf7e4adaf", 5: "589df0f2a3203ef9b9cc",
    6: "354d3b38e8e518477d8c", 7: "b57b1eeeed9d590e4692",
    8: "2cbdd9c8cc6d20867fa2", 9: "d47158ca2923a75af7ef",
    10: "2a1138b5e375c7c9101a", 11: "c9347da5d7111fe9f1d9",
    12: "8e74503f8a94724dbb08", 13: "0259d21abd4adf59ca05",
    14: "18ca7d8e7b13f4760404", 15: "e9528dbafe091b886af5",
    16: "d6860287a330f9a92210", 17: "751a5feeb49616d1cceb",
    18: "6955d9dfab070681d752", 19: "068b4cfc607fa13a1ffb",
    20: "4fb7a2e36b9d156b79f8", 21: "44e497e008d6789f2dbf",
    22: "0dc887496bb94080f2c4", 23: "032a5c6c206b96db376a",
    24: "e4bb6ceb363e5841d946", 25: "06d780b85eade141e5fd",
    26: "a6a915cd11add12a94e9", 27: "5967e403b057bc02a8a9",
    28: "87bae21ce1a1631ad6c9", 29: "14f8efdb5552af690d44",
    30: "9477ecd3fee28c7d2a34", 31: "b4ecef20999b7ccb205e",
    32: "ec7c6575fc2a54caeb0d", 33: "afa22d65c9f5a95f0f73",
    34: "e5901d4631734da09feb", 35: "e31c6f4e994cb4330504",
    36: "df473da3aa9b5704ce73", 42: "56eed0401753d9e5ee86",
}

_RE_16 = re.compile(r"^[A-Za-z0-9]{16}$")
_RE_20HEX = re.compile(r"^[0-9a-fA-F]{20}$")


def _known_targets():
    t = {"SM4_SECRET_2": SM4_SECRET_2, "SM4_SECRET_4": SM4_SECRET_4}
    for i, s in enumerate(SM4_SECRET_NEW):
        t[f"SM4_SECRET_NEW[{i}]"] = s
    for kid, s in DYN_SM4_SECRETS.items():
        t[f"DYN_{kid}"] = s
    return t


def _extract_strings(data: bytes, minlen: int = 8):
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)


def find_secrets(so_path: str) -> dict:
    """Pindai libUE4.so, kembalikan dict hasil temuan."""
    with open(so_path, "rb") as f:
        data = f.read()
    # tokenisasi: pecah run printable pada whitespace agar secret yang
    # menempel teks lain tetap terdeteksi
    uniq = set()
    for m in _extract_strings(data):
        for tok in m.split():
            if len(tok) >= 8:
                uniq.add(tok.decode("ascii"))

    targets = _known_targets()
    known_vals = set(targets.values())
    known_found = sorted(n for n, s in targets.items() if s in uniq)
    # substring fallback: secret yang menempel teks lain tanpa whitespace
    # (mis. di-dump berderet) tetap terdeteksi
    if len(known_found) < len(targets):
        for n, s in targets.items():
            if n not in known_found and s.encode() in data:
                known_found.append(n)
        known_found.sort()

    c16, c20 = [], []
    for s in sorted(uniq):
        if s in known_vals:
            continue
        if len(s) == 16 and _RE_16.match(s):
            c16.append(s)
        elif len(s) == 20 and _RE_20HEX.match(s):
            c20.append(s)
        if len(c16) >= 50 and len(c20) >= 50:
            break

    return {
        "known_found": known_found,
        "candidates_16": c16[:50],
        "candidates_20hex": c20[:50],
        "scanned_bytes": len(data),
    }


def derive_key_for_file(stem: str, method: int, secret: str) -> bytes:
    """Derivasi kunci SM4 untuk validasi kandidat secret."""
    return hashlib.sha1((stem.lower() + secret).encode()).digest()[:16]


def _self_test():
    import os
    import tempfile
    dummy = (
        b"\x7fELF" + b"\x00" * 100
        + b"noise Q0hVTKey$as*1ZFlQCiA padding\x00"
        + b"junk edbcba1dc6b11068b44a tail\x00"
        + b"xx Ab3dEf7hIj2kLm5n yy\x00"      # kandidat 16-char
        + b"zz 0123456789abcdef0123 ww\x00"    # kandidat 20-hex
        + b"\x00" * 50
    )
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f:
        f.write(dummy)
        path = f.name
    try:
        r = find_secrets(path)
        assert "SM4_SECRET_2" in r["known_found"], r["known_found"]
        assert "DYN_0" in r["known_found"], r["known_found"]
        assert "Ab3dEf7hIj2kLm5n" in r["candidates_16"], r["candidates_16"]
        assert "0123456789abcdef0123" in r["candidates_20hex"], r["candidates_20hex"]
        # secret yang dikenal tidak boleh muncul sebagai kandidat
        assert "Q0hVTKey$as*1ZFlQCiA" not in r["candidates_16"]
        assert r["scanned_bytes"] == len(dummy)
        k = derive_key_for_file("DefaultEngine", 2, "Q0hVTKey$as*1ZFlQCiA")
        assert len(k) == 16
        assert k == derive_key_for_file("defaultengine", 2, "Q0hVTKey$as*1ZFlQCiA")
    finally:
        os.unlink(path)
    print("sm4finder self-test: LULUS")


def main(argv):
    if len(argv) != 2:
        print(f"pakai: {argv[0]} libUE4.so")
        return 1
    r = find_secrets(argv[1])
    print(f"[*] dipindai: {r['scanned_bytes']} byte")
    print(f"[*] secret dikenal ditemukan ({len(r['known_found'])}):")
    for n in r["known_found"]:
        print(f"    + {n}")
    print(f"[*] kandidat 16-char ({len(r['candidates_16'])}):")
    for s in r["candidates_16"][:20]:
        print(f"    ? {s}")
    if len(r["candidates_16"]) > 20:
        print(f"    ... (+{len(r['candidates_16']) - 20} lagi)")
    print(f"[*] kandidat 20-hex ({len(r['candidates_20hex'])}):")
    for s in r["candidates_20hex"][:20]:
        print(f"    ? {s}")
    if len(r["candidates_20hex"]) > 20:
        print(f"    ... (+{len(r['candidates_20hex']) - 20} lagi)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        sys.exit(main(sys.argv))
