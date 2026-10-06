#!/usr/bin/env python3
"""Parser format .pak asli PUBG Mobile — pure Python stdlib.

Format PUBG Mobile BUKAN UE4 standar:
- footer 45 byte di-obfuscate cipher ZUC (key/IV fixed),
- index dienkripsi AES-256-CBC (v>7, key/IV di-unwrap RSA dari footer)
  atau XOR 0x79 (v<=7),
- payload per-file: SIMPLE1 (XOR 0x79), SIMPLE2 (rolling XOR),
  atau SM4 custom Tencent (ECB per 16-byte block, key per-file).

Dependensi modul sejawat (lazy import, ditulis terpisah):
  zuc.zuc_keystream() -> list[int] (16 word)
  pyaes.aes256_cbc_decrypt(key, iv, data) -> bytes
  pyaes.pkcs7_unpad(data) -> bytes
  tsm4.TencentSM4(key).decrypt_block(block16) -> bytes
"""
import hashlib
import os
import struct
import zlib
from pathlib import PurePosixPath


class PubgFormatError(Exception):
    """File bukan .pak PUBG Mobile / struktur tidak dikenali."""


# ---------------- konstanta ----------------

MAGIC_STD = 0x5A6F12E1
MAGIC_LQTC = 0x4C515443  # "LQTC", normal untuk core_patch_*.pak

SIMPLE1_KEY = 0x79
SIMPLE2_KEY0 = 0xE55B4ED1

EM_SIMPLE1 = 1
EM_SIMPLE2 = 16
EM_SM4_2 = 2
EM_SM4_4 = 4
EM_DYN_SM4 = 17
EM_SM4_NEW_BASE = 31

CM_ZLIB = 1
CM_ZSTD = 6
CM_ZSTD_DICT = 8

RSA_MOD_1 = (
    "CBE8B9F2504050EF9831B719E9A6249A6D238505ADE909BDE78C180DED6072A0C"
    "3347B8AF4780E1F212D952D82D4BF7F233C1ECA499E1F9D9A85B4FAD759F54BAB"
    "C1666C5DE411EA9E4B2374425DD6C6F54333BBC8F2610FE6063E4D0D6C21A671"
    "A8F7C3740555E5DC06D4E1691C456DB4116C0C012BF7B206E8311AAAEC689952"
    "BF804EF638F09D5822B4117B114208F14DEB459E80CB770E5B0D7978E21F5E6C"
    "ED4999D3583108221A7AB28B960277ADB5690A332784019D9C195BE4EA9EA0A0"
    "9459010F236465DE0D59C3EF7324E954E1118D93EE19F299760C2CDB963CE879"
    "73EA5ECC9BBE81C27D4C7C8572AC07E9BCEAC9BD72AB7A56A3C0AD736ABCE4"
)
RSA_MOD_2 = (
    "7F58E8A39A4DA4E87357DDD650EAA16D3B5CE95B213D1030A662566444796A7"
    "8A84AE9AC3DBFFDE7F41094896696835DAF13B89E6EC2B84963B1B1BAF7151D"
    "A245C3FBFAE2A6AE18B2684D03F9229DE2C91440F2A3A3BCDE1E5680C16722A8"
    "8039C73560D5D43F4B6562C2EEA5B1D926D86B51108A2643C70FB74D6442CE3"
    "A08339B8FD8F660AE88129B7AB8C46F2FA58124485CCCB1E987B05A6DA65A01"
    "858ED3F89905449AE42BB07290FCB9994BF22E26610BCABB9804783A3B95879"
    "17F3D97316EDDA15C5E13F79066407B55A93B291B68A4AC42A98D6E35FED84B"
    "14A792D154E62028DDAD20FC301951E5924BE9AD62FB719DD94CC30CAB871BE"
    "C4377A8"
)

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
EM_SM4_NEW_END = EM_SM4_NEW_BASE + len(SM4_SECRET_NEW) - 1  # 52
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


# ---------------- util ----------------

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _hash_expand(data: bytes, length: int) -> bytes:
    out = b""
    while len(out) < length:
        out += hashlib.sha1(data).digest()
    return out[:length]


def _zuc_keystream():
    try:
        from zuc import zuc_keystream
    except ImportError:
        raise PubgFormatError("modul zuc.py belum tersedia")
    return zuc_keystream()


class _Reader:
    def __init__(self, buf: bytes, pos: int = 0):
        self._b = buf
        self._p = pos

    def u1(self) -> int:
        v = self._b[self._p]
        self._p += 1
        return v

    def u4(self) -> int:
        v = struct.unpack_from("<I", self._b, self._p)[0]
        self._p += 4
        return v

    def i4(self) -> int:
        v = struct.unpack_from("<i", self._b, self._p)[0]
        self._p += 4
        return v

    def u8(self) -> int:
        v = struct.unpack_from("<Q", self._b, self._p)[0]
        self._p += 8
        return v

    def raw(self, n: int) -> bytes:
        v = self._b[self._p:self._p + n]
        self._p += n
        return bytes(v)

    def fstring(self) -> str:
        n = self.i4()
        if n <= 0:
            return ""
        s = self.raw(n).rstrip(b"\x00")
        return s.decode("utf-8", "replace")


# ---------------- footer ----------------

def _footer_ext_size(version: int) -> int:
    s = 0
    if version >= 7:
        s += 32
    if version >= 8:
        s += 768
    if version >= 9:
        s += 8
    if version >= 12:
        s += 20
    return s


def parse_footer(data: bytes, keystream=None) -> dict:
    """Parse footer PUBG Mobile. keystream opsional (untuk testing)."""
    if len(data) < 45:
        raise PubgFormatError("file terlalu kecil untuk footer PUBG Mobile")
    ks = keystream if keystream is not None else _zuc_keystream()

    r = _Reader(data[-45:])
    index_encrypted = ((r.u1() ^ ks[3]) & 0xFF) == 1
    magic = r.u4() ^ ks[2]
    version = r.u4()
    if magic not in (MAGIC_STD, MAGIC_LQTC):
        raise PubgFormatError("bukan format PUBG Mobile")

    info = {"magic": magic, "version": version}
    if version >= 6:
        enc = r.raw(20)
        info["index_hash"] = _xor_bytes(enc, struct.pack("<5I", *ks[4:9]))
    else:
        info["index_hash"] = b""
    info["index_size"] = r.u8() ^ ((ks[10] << 32) | ks[11])
    info["index_offset"] = r.u8() ^ ((ks[0] << 32) | ks[1])
    if version <= 3:
        index_encrypted = False
    info["index_encrypted"] = index_encrypted

    # extended footer, tepat sebelum base footer
    ext_size = _footer_ext_size(version)
    info.update({"unk1": b"", "packed_key": b"", "packed_iv": b"",
                 "packed_index_hash": b"", "stem_hash": 0, "unk2": 0,
                 "content_hash": b""})
    if ext_size:
        if len(data) < 45 + ext_size:
            raise PubgFormatError("extended footer terpotong")
        e = _Reader(data[-(45 + ext_size):-45])
        if version >= 7:
            enc = e.raw(32)
            info["unk1"] = _xor_bytes(enc, struct.pack("<8I", *ks[7:15]))
        if version >= 8:
            info["packed_key"] = e.raw(256)
            info["packed_iv"] = e.raw(256)
            info["packed_index_hash"] = e.raw(256)
        if version >= 9:
            info["stem_hash"] = e.u4() ^ ks[8]
            info["unk2"] = e.u4() ^ ks[9]
        if version >= 12:
            info["content_hash"] = e.raw(20)
    return info


# ---------------- RSA unwrap & index decrypt ----------------

def rsa_pub_pow(sig: bytes, mod_hex: str) -> bytes:
    """Langkah RSA saja: m = sig^e mod n (256 byte LE)."""
    c = int.from_bytes(sig, "little")
    n = int.from_bytes(bytes.fromhex(mod_hex), "little")
    return pow(c, 0x10001, n).to_bytes(256, "little")


def oaep_unmask(m: bytes) -> bytes:
    """Unmasking OAEP-like Tencent: m (256B) -> payload (32B) atau b''."""
    m = m.rstrip(b"\x00")
    m += b"\x00" * ((4 - len(m) % 4) % 4)
    if len(m) < 43:
        return b""
    x1 = m[1:21]
    x2 = m[21:]
    x1 = _xor_bytes(x1, _hash_expand(x2, 20))
    x2 = _xor_bytes(x2, _hash_expand(x1, len(x2)))
    if x2[:20] != hashlib.sha1(b"\x00" * 20).digest():
        return b""
    i = next((i for i in range(20, len(x2)) if x2[i] != 0), len(x2) - 20)
    return x2[1 + i:]


def rsa_unwrap(sig: bytes, mod_hex: str) -> bytes:
    return oaep_unmask(rsa_pub_pow(sig, mod_hex))


def decrypt_index(ciphertext: bytes, info: dict) -> bytes:
    if not info["index_encrypted"]:
        return ciphertext
    if info["version"] > 7:
        key = rsa_unwrap(info["packed_key"], RSA_MOD_1)
        iv = rsa_unwrap(info["packed_iv"], RSA_MOD_1)
        if len(key) != 32 or len(iv) != 32:
            raise PubgFormatError("gagal unwrap kunci/IV index (RSA)")
        try:
            from pyaes import aes256_cbc_decrypt, pkcs7_unpad
        except ImportError:
            raise PubgFormatError("modul pyaes.py belum tersedia")
        return pkcs7_unpad(aes256_cbc_decrypt(key, iv[:16], ciphertext))
    return bytes(b ^ SIMPLE1_KEY for b in ciphertext)


def verify_index(index_plain: bytes, info: dict):
    if info["version"] >= 8:
        expected = rsa_unwrap(info["packed_index_hash"], RSA_MOD_2)
    else:
        expected = info["index_hash"]
    if expected and expected != hashlib.sha1(index_plain).digest():
        raise ValueError("Index hash mismatch")


# ---------------- SIMPLE2 & SM4 ----------------

def simple2_decrypt(data: bytes) -> bytes:
    assert len(data) % 16 == 0, "SIMPLE2 butuh panjang kelipatan 16"
    key = SIMPLE2_KEY0
    out = bytearray()
    for (w,) in struct.iter_unpack("<I", data):
        key ^= w
        out += struct.pack("<I", key & 0xFFFFFFFF)
    return bytes(out)


def is_sm4_method(m: int) -> bool:
    return m in (EM_SM4_2, EM_SM4_4) or EM_SM4_NEW_BASE <= m <= EM_SM4_NEW_END


def is_block_cipher(m: int) -> bool:
    return is_sm4_method(m) or m == EM_DYN_SM4


def derive_sm4_key(stem: str, method: int) -> bytes:
    stem = stem.lower()
    if method == EM_SM4_2:
        secret = SM4_SECRET_2
    elif method == EM_SM4_4:
        secret = SM4_SECRET_4
    elif EM_SM4_NEW_BASE <= method <= EM_SM4_NEW_END:
        secret = SM4_SECRET_NEW[method - EM_SM4_NEW_BASE] + str(method)
    else:
        raise ValueError(f"method SM4 tidak didukung: {method}")
    return hashlib.sha1((stem + secret).encode()).digest()[:16]


def derive_dynamic_sm4_key(key_id: int) -> bytes:
    secret = DYN_SM4_SECRETS.get(key_id & 0xFFFFFF)
    if secret is None:
        raise ValueError(
            f"secret DYN_SM4 untuk key_id {key_id & 0xFFFFFF} tidak diketahui "
            "(tabel tidak lengkap — file ini memang tidak bisa didekripsi)")
    return hashlib.sha1(secret.encode()).digest()[:16]


def decrypt_payload_block(block: bytes, stem: str, method: int, key_id: int = 0) -> bytes:
    """Decrypt satu chunk (sudah kelipatan 16 untuk block cipher)."""
    if method == EM_SIMPLE1 or method == 0:
        # method 0 = flag encrypted tanpa encryption_method (pak lama) → SIMPLE1
        return bytes(b ^ SIMPLE1_KEY for b in block)
    if method == EM_SIMPLE2:
        return simple2_decrypt(block)
    if method == EM_DYN_SM4:
        key = derive_dynamic_sm4_key(key_id)
    elif is_sm4_method(method):
        key = derive_sm4_key(stem, method)
    else:
        raise ValueError(f"method enkripsi tak dikenal: {method}")
    try:
        from tsm4 import TencentSM4
    except ImportError:
        raise PubgFormatError("modul tsm4.py belum tersedia")
    sm4 = TencentSM4(key)
    out = bytearray()
    for i in range(0, len(block), 16):
        chunk = block[i:i + 16]
        if len(chunk) < 16:
            chunk = chunk + b"\x00" * (16 - len(chunk))
        out += sm4.decrypt_block(chunk)
    return bytes(out)


def lcg_inverse_permutation(n: int):
    """Inverse LCG block permutation (file SM4 terkompresi)."""
    if n <= 1:
        return list(range(n))

    def wrap(x: int) -> int:
        x &= 0xFFFFFFFF
        return x if not x & 0x80000000 else ((x + 0x80000000) & 0xFFFFFFFF) - 0x80000000

    state = n
    perm = []
    while len(perm) < n:
        x1 = wrap(0x41C64E6D * state)
        state = wrap(x1 + 12345)
        x2 = wrap(x1 + 0x13038) if state < 0 else state
        idx = (((x2 >> 16) & 0xFFFFFFFF) % 0x7FFF) % n
        if idx not in perm:
            perm.append(idx)
    inv = [0] * n
    for i, x in enumerate(perm):
        inv[x] = i
    return inv


# ---------------- entry & index ----------------

class PubgEntry:
    def __init__(self):
        self.path = ""
        self.offset = 0
        self.usize = 0
        self.size = 0
        self.comp_method = 0
        self.blocks = []          # list[(start, end)]
        self.encrypted = False
        self.enc_method = 0
        self.key_id = 0

    @property
    def stem(self) -> str:
        name = self.path.rsplit("/", 1)[-1]
        return name.rsplit(".", 1)[0] if "." in name else name


def _parse_entry(r: _Reader, version: int) -> PubgEntry:
    e = PubgEntry()
    e.content_hash = r.raw(20)
    if version <= 1:
        r.u8()
    e.offset = r.u8()
    e.usize = r.u8()
    e.comp_method = r.u4() & 0xF
    e.size = r.u8()
    if version >= 5:
        r.u1()
        r.raw(20)
    if e.comp_method != 0 and version >= 3:
        bc = r.u4()
        e.blocks = [(r.u8(), r.u8()) for _ in range(bc)]
    if version >= 4:
        r.u4()  # block_size
    if version >= 4:
        e.encrypted = r.u1() == 1
    if version >= 12:
        e.enc_method = r.u4()
        e.key_id = r.u4()
    return e


def _safe_join(base: str, rel: str) -> str:
    parts = [p for p in PurePosixPath(rel).parts if p not in ("..", ".", "")]
    return os.path.join(base, *parts) if parts else base


class PubgPak:
    """Parser + extractor .pak PUBG Mobile."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.info = parse_footer(self.data)
        self.version = self.info["version"]
        self._parse_index()

    # -- index --
    def _parse_index(self):
        off, size = self.info["index_offset"], self.info["index_size"]
        if off + size > len(self.data):
            raise PubgFormatError("index_offset/size di luar file")
        raw = self.data[off:off + size]
        plain = decrypt_index(bytes(raw), self.info)
        verify_index(plain, self.info)

        r = _Reader(plain)
        self.mount = r.fstring()
        file_count = r.u4()
        entries = [_parse_entry(r, self.version) for _ in range(file_count)]

        self.files = []
        self.zstd_dict = None
        dir_count = r.u8()
        for _ in range(dir_count):
            dir_path = r.fstring()
            nfiles = r.u8()
            for _ in range(nfiles):
                filename = r.fstring()
                file_idx = ~r.i4()
                if not (0 <= file_idx < len(entries)):
                    raise PubgFormatError("file_idx index rusak")
                e = entries[file_idx]
                e.path = str(PurePosixPath(dir_path) / filename)
                self.files.append(e)
                if ("zstddic" in dir_path.lower() and not e.encrypted
                        and e.comp_method == 0 and self.zstd_dict is None):
                    self.zstd_dict = self._load_zstd_dict(e)

    def _load_zstd_dict(self, e: PubgEntry):
        blob = self.data[e.offset:e.offset + e.size]
        r = _Reader(blob)
        dict_size = r.u8()
        r.u4()
        if r.u4() != dict_size:
            return None
        return r.raw(dict_size)

    # -- API --
    def list_files(self):
        return [(e.path, e.usize) for e in self.files]

    def extract_one(self, entry: PubgEntry, outdir: str) -> str:
        dest = _safe_join(outdir, entry.path)
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        data = self._read_entry(entry)
        with open(dest, "wb") as f:
            f.write(data)
        return dest

    def extract_all(self, outdir: str, progress_cb=None):
        ok, fail, fails = 0, 0, []
        total = len(self.files)
        for i, e in enumerate(self.files, 1):
            try:
                self.extract_one(e, outdir)
                ok += 1
            except Exception as ex:  # noqa: BLE001
                fail += 1
                fails.append(f"{e.path}: {ex}")
            if progress_cb:
                progress_cb(i, total)
        return ok, fail, fails

    # -- baca + decrypt + decompress --
    def _read_entry(self, e: PubgEntry) -> bytes:
        if e.comp_method == 0:
            size = e.size
            if e.encrypted and (e.enc_method == EM_SIMPLE2 or is_block_cipher(e.enc_method)):
                size = ((size + 15) // 16) * 16
            blob = bytes(self.data[e.offset:e.offset + size])
            if e.encrypted:
                blob = decrypt_payload_block(blob, e.stem, e.enc_method, e.key_id)
            return blob[:e.size]

        n = len(e.blocks)
        order = lcg_inverse_permutation(n) if (
            e.encrypted and is_block_cipher(e.enc_method)) else list(range(n))
        out = bytearray()
        for idx in order:
            start, end = e.blocks[idx]
            size = end - start
            if e.encrypted and (e.enc_method == EM_SIMPLE2 or is_block_cipher(e.enc_method)):
                size = ((size + 15) // 16) * 16
            blob = bytes(self.data[start:start + size])
            if e.encrypted:
                blob = decrypt_payload_block(blob, e.stem, e.enc_method, e.key_id)
            out += self._decompress(blob, e.comp_method)
        return bytes(out)

    def _decompress(self, data: bytes, method: int) -> bytes:
        if method == CM_ZLIB:
            return zlib.decompress(data)
        if method in (CM_ZSTD, CM_ZSTD_DICT):
            try:
                import zstandard
            except ImportError:
                raise PubgFormatError(
                    "butuh modul 'zstandard' untuk dekompresi ZSTD: pip install zstandard")
            if method == CM_ZSTD_DICT and self.zstd_dict:
                d = zstandard.ZstdDecompressor(
                    dict_data=zstandard.ZstdCompressionDict(self.zstd_dict))
            else:
                d = zstandard.ZstdDecompressor()
            return d.decompress(data)
        raise PubgFormatError(f"metode kompresi tak dikenal: {method}")


# ---------------- self-test ----------------

def _self_test():
    # footer sintetis dengan keystream palsu (tidak butuh modul zuc)
    ks = [(0x11111111 * (i + 1)) & 0xFFFFFFFF for i in range(16)]
    version, index_offset, index_size = 8, 1234, 567
    index_hash = bytes(range(20))

    base = bytearray()
    base += struct.pack("B", (1 ^ (ks[3] & 0xFF)) & 0xFF)
    base += struct.pack("<I", MAGIC_STD ^ ks[2])
    base += struct.pack("<I", version)
    base += _xor_bytes(index_hash, struct.pack("<5I", *ks[4:9]))
    base += struct.pack("<Q", index_size ^ ((ks[10] << 32) | ks[11]))
    base += struct.pack("<Q", index_offset ^ ((ks[0] << 32) | ks[1]))
    assert len(base) == 45

    ext = bytearray()
    ext += _xor_bytes(bytes(range(32)), struct.pack("<8I", *ks[7:15]))
    ext += b"\xAA" * 256 + b"\xBB" * 256 + b"\xCC" * 256
    data = b"\x00" * 3000 + bytes(ext) + bytes(base)

    info = parse_footer(data, keystream=ks)
    assert info["magic"] == MAGIC_STD, hex(info["magic"])
    assert info["version"] == 8
    assert info["index_encrypted"] is True
    assert info["index_offset"] == 1234
    assert info["index_size"] == 567
    assert info["index_hash"] == index_hash
    assert len(info["packed_key"]) == 256 and len(info["packed_iv"]) == 256
    assert len(info["packed_index_hash"]) == 256

    # magic salah -> PubgFormatError
    bad = bytearray(base)
    struct.pack_into("<I", bad, 1, 0xDEADBEEF ^ ks[2])
    try:
        parse_footer(bytes(bad), keystream=ks)
        raise AssertionError("harusnya raise PubgFormatError")
    except PubgFormatError:
        pass

    # v<=3 paksa index_encrypted=False
    v3 = bytearray(base)
    struct.pack_into("<I", v3, 5, 3)  # version tidak diobfuscate
    i3 = parse_footer(b"\x00" * 3000 + bytes(v3), keystream=ks)
    assert i3["index_encrypted"] is False

    # SIMPLE2 decrypt: vektor known-answer (hitung manual)
    # K=0xE55B4ED1; w0=0x11111111 -> out0=K^w0=0xF44A5FC0
    # w1=0x22222222 -> out1=out0^w1=0xD6687DE2
    d = struct.pack("<4I", 0x11111111, 0x22222222, 0x33333333, 0x44444444)
    out = simple2_decrypt(d)
    w = struct.unpack("<4I", out)
    assert w[0] == 0xF44A5FC0, hex(w[0])
    assert w[1] == 0xD6687DE2, hex(w[1])
    assert w[2] == (0xD6687DE2 ^ 0x33333333) & 0xFFFFFFFF
    assert w[3] == (w[2] ^ 0x44444444) & 0xFFFFFFFF

    # derivasi kunci SM4
    k1 = derive_sm4_key("DefaultEngine", 2)
    k2 = derive_sm4_key("defaultengine", 2)
    assert len(k1) == 16 and k1 == k2
    assert len(derive_sm4_key("x", 31)) == 16
    assert len(derive_dynamic_sm4_key(0)) == 16
    try:
        derive_dynamic_sm4_key(37)
        raise AssertionError("harusnya raise ValueError")
    except ValueError:
        pass

    # LCG permutation
    p = lcg_inverse_permutation(10)
    assert sorted(p) == list(range(10))
    assert lcg_inverse_permutation(1) == [0]

    print("pubgpak self-test: LULUS")


if __name__ == "__main__":
    _self_test()
