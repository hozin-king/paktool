#!/usr/bin/env python3
"""AES-256 (decrypt) — pure Python stdlib, dipercepat T-table.

Dipakai untuk dekripsi index .pak PUBG Mobile (AES-256-CBC, key/IV dari
unwrap RSA footer). Hanya implementasi DECRYPT (cukup untuk unpack).
"""

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

_M32 = 0xFFFFFFFF


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i


def _rotr32(w, n):
    n %= 32
    return ((w >> n) | (w << (32 - n))) & _M32


# T-table decrypt: Td0[x] = (0E*S^-1[x], 09*S^-1[x], 0D*S^-1[x], 0B*S^-1[x])
_TD0 = []
for _x in range(256):
    _s = _INV_SBOX[_x]
    _TD0.append((_gmul(_s, 0x0E) << 24) | (_gmul(_s, 0x09) << 16)
                | (_gmul(_s, 0x0D) << 8) | _gmul(_s, 0x0B))
_TD1 = [_rotr32(w, 8) for w in _TD0]
_TD2 = [_rotr32(w, 16) for w in _TD0]
_TD3 = [_rotr32(w, 24) for w in _TD0]


def _expand_key(key: bytes):
    assert len(key) == 32, "key harus 32 byte (AES-256)"
    w = [int.from_bytes(key[i * 4:(i + 1) * 4], "big") for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((_SBOX[(t >> 16) & 0xFF] << 24)
                 | (_SBOX[(t >> 8) & 0xFF] << 16)
                 | (_SBOX[t & 0xFF] << 8)
                 | _SBOX[(t >> 24) & 0xFF]) ^ (rcon << 24)
            rcon = _gmul(rcon, 2)
        elif i % 8 == 4:
            t = ((_SBOX[(t >> 24) & 0xFF] << 24)
                 | (_SBOX[(t >> 16) & 0xFF] << 16)
                 | (_SBOX[(t >> 8) & 0xFF] << 8)
                 | _SBOX[t & 0xFF])
        w.append(w[i - 8] ^ t)
    return w


def _inv_mixcol_word(w):
    b0, b1, b2, b3 = (w >> 24) & 0xFF, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF
    return ((_gmul(b0, 0x0E) ^ _gmul(b1, 0x0B) ^ _gmul(b2, 0x0D) ^ _gmul(b3, 0x09)) << 24
            | (_gmul(b0, 0x09) ^ _gmul(b1, 0x0E) ^ _gmul(b2, 0x0B) ^ _gmul(b3, 0x0D)) << 16
            | (_gmul(b0, 0x0D) ^ _gmul(b1, 0x09) ^ _gmul(b2, 0x0E) ^ _gmul(b3, 0x0B)) << 8
            | (_gmul(b0, 0x0B) ^ _gmul(b1, 0x0D) ^ _gmul(b2, 0x09) ^ _gmul(b3, 0x0E)))


def _decrypt_block(block: bytes, rk) -> bytes:
    # round key tengah di-InvMixColumns (equivalent inverse cipher)
    dk = [_inv_mixcol_word(w) for w in rk[4:56]]
    s0 = int.from_bytes(block[0:4], "big") ^ rk[56]
    s1 = int.from_bytes(block[4:8], "big") ^ rk[57]
    s2 = int.from_bytes(block[8:12], "big") ^ rk[58]
    s3 = int.from_bytes(block[12:16], "big") ^ rk[59]
    for r in range(13, 0, -1):
        k = (r - 1) * 4
        t0 = (_TD0[s0 >> 24] ^ _TD1[(s3 >> 16) & 0xFF]
              ^ _TD2[(s2 >> 8) & 0xFF] ^ _TD3[s1 & 0xFF] ^ dk[k])
        t1 = (_TD0[s1 >> 24] ^ _TD1[(s0 >> 16) & 0xFF]
              ^ _TD2[(s3 >> 8) & 0xFF] ^ _TD3[s2 & 0xFF] ^ dk[k + 1])
        t2 = (_TD0[s2 >> 24] ^ _TD1[(s1 >> 16) & 0xFF]
              ^ _TD2[(s0 >> 8) & 0xFF] ^ _TD3[s3 & 0xFF] ^ dk[k + 2])
        t3 = (_TD0[s3 >> 24] ^ _TD1[(s2 >> 16) & 0xFF]
              ^ _TD2[(s1 >> 8) & 0xFF] ^ _TD3[s0 & 0xFF] ^ dk[k + 3])
        s0, s1, s2, s3 = t0, t1, t2, t3
    f0 = (((_INV_SBOX[s0 >> 24] << 24) | (_INV_SBOX[(s3 >> 16) & 0xFF] << 16)
           | (_INV_SBOX[(s2 >> 8) & 0xFF] << 8) | _INV_SBOX[s1 & 0xFF]) ^ rk[0])
    f1 = (((_INV_SBOX[s1 >> 24] << 24) | (_INV_SBOX[(s0 >> 16) & 0xFF] << 16)
           | (_INV_SBOX[(s3 >> 8) & 0xFF] << 8) | _INV_SBOX[s2 & 0xFF]) ^ rk[1])
    f2 = (((_INV_SBOX[s2 >> 24] << 24) | (_INV_SBOX[(s1 >> 16) & 0xFF] << 16)
           | (_INV_SBOX[(s0 >> 8) & 0xFF] << 8) | _INV_SBOX[s3 & 0xFF]) ^ rk[2])
    f3 = (((_INV_SBOX[s3 >> 24] << 24) | (_INV_SBOX[(s2 >> 16) & 0xFF] << 16)
           | (_INV_SBOX[(s1 >> 8) & 0xFF] << 8) | _INV_SBOX[s0 & 0xFF]) ^ rk[3])
    return (f0.to_bytes(4, "big") + f1.to_bytes(4, "big")
            + f2.to_bytes(4, "big") + f3.to_bytes(4, "big"))


def aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-CBC. data harus kelipatan 16 byte.
    Kembalikan plaintext MASIH ber-padding (pakai pkcs7_unpad untuk lepas)."""
    assert len(iv) == 16, "iv harus 16 byte"
    assert len(data) % 16 == 0 and len(data) > 0, "data harus kelipatan 16"
    rk = _expand_key(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        blk = data[off:off + 16]
        dec = _decrypt_block(blk, rk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def pkcs7_unpad(data: bytes) -> bytes:
    """Lepas padding PKCS#7. Raise ValueError bila padding tidak valid."""
    if not data:
        raise ValueError("data kosong")
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding PKCS#7 tidak valid")
    return data[:-n]


def pkcs7_pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _sub_shift_row(s0, s1, s2, s3):
    # SubBytes (forward SBOX) + ShiftRows, state sebagai 4 word kolom
    b = [[0] * 4 for _ in range(4)]
    for col, w in enumerate((s0, s1, s2, s3)):
        for row in range(4):
            b[row][col] = _SBOX[(w >> (24 - 8 * row)) & 0xFF]
    # ShiftRows: baris r digeser kiri r
    out = []
    for col in range(4):
        w = 0
        for row in range(4):
            w |= b[row][(col + row) % 4] << (24 - 8 * row)
        out.append(w)
    return out


def _mixcol_word(w):
    b0, b1, b2, b3 = (w >> 24) & 0xFF, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF
    return ((_gmul(b0, 2) ^ _gmul(b1, 3) ^ b2 ^ b3) << 24
            | (b0 ^ _gmul(b1, 2) ^ _gmul(b2, 3) ^ b3) << 16
            | (b0 ^ b1 ^ _gmul(b2, 2) ^ _gmul(b3, 3)) << 8
            | (_gmul(b0, 3) ^ b1 ^ b2 ^ _gmul(b3, 2)))


def _encrypt_block(block: bytes, rk) -> bytes:
    s = [int.from_bytes(block[i * 4:(i + 1) * 4], "big") ^ rk[i] for i in range(4)]
    for r in range(1, 15):
        s = _sub_shift_row(*s)
        if r < 14:
            s = [_mixcol_word(w) for w in s]
        k = r * 4
        s = [s[i] ^ rk[k + i] for i in range(4)]
    return b"".join(w.to_bytes(4, "big") for w in s)


def aes256_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt AES-256-CBC. data harus kelipatan 16 byte (pakai pkcs7_pad dulu)."""
    assert len(key) == 32 and len(iv) == 16 and len(data) % 16 == 0
    rk = _expand_key(key)
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _encrypt_block(blk, rk)
        out += enc
        prev = enc
    return bytes(out)


if __name__ == "__main__":
    # self-test encrypt: FIPS-197 C.3 (AES-256)
    _k = bytes(range(32))                       # 000102...1f
    _p = bytes.fromhex("00112233445566778899aabbccddeeff")
    _c = aes256_cbc_encrypt(_k, bytes(16), _p)
    assert _c.hex() == "8ea2b7ca516745bfeafc49904b496089", _c.hex()
    _msg = b"halo paktool " * 7
    _ct = aes256_cbc_encrypt(_k, bytes(range(16)), pkcs7_pad(_msg))
    assert pkcs7_unpad(aes256_cbc_decrypt(_k, bytes(range(16)), _ct)) == _msg
    print("OK pyaes-enc")
    import os

    # 1. FIPS-197 AES-256 test vector (decrypt)
    key = bytes(range(32))
    ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes256_cbc_decrypt(key, bytes(16), ct) == pt, "FIPS-197 vector gagal"

    # 2. cross-check T-table vs implementasi straightforward (50 blok acak)
    def ref_decrypt(block, rk):
        st = list(block)
        for c in range(4):
            w = rk[56 + c]
            for r in range(4):
                st[4 * c + r] ^= (w >> (24 - 8 * r)) & 0xFF
        for rnd in range(13, 0, -1):
            tmp = [0] * 16
            for r in range(4):
                for c in range(4):
                    tmp[4 * c + r] = st[4 * ((c - r) % 4) + r]
            st = [_INV_SBOX[b] for b in tmp]
            for c in range(4):
                w = rk[4 * rnd + c]
                for r in range(4):
                    st[4 * c + r] ^= (w >> (24 - 8 * r)) & 0xFF
            tmp = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = st[4 * c:4 * c + 4]
                tmp[4 * c] = (_gmul(a0, 0x0E) ^ _gmul(a1, 0x0B)
                              ^ _gmul(a2, 0x0D) ^ _gmul(a3, 0x09))
                tmp[4 * c + 1] = (_gmul(a0, 0x09) ^ _gmul(a1, 0x0E)
                                  ^ _gmul(a2, 0x0B) ^ _gmul(a3, 0x0D))
                tmp[4 * c + 2] = (_gmul(a0, 0x0D) ^ _gmul(a1, 0x09)
                                  ^ _gmul(a2, 0x0E) ^ _gmul(a3, 0x0B))
                tmp[4 * c + 3] = (_gmul(a0, 0x0B) ^ _gmul(a1, 0x0D)
                                  ^ _gmul(a2, 0x09) ^ _gmul(a3, 0x0E))
            st = tmp
        tmp = [0] * 16
        for r in range(4):
            for c in range(4):
                tmp[4 * c + r] = st[4 * ((c - r) % 4) + r]
        st = [_INV_SBOX[b] for b in tmp]
        for c in range(4):
            w = rk[c]
            for r in range(4):
                st[4 * c + r] ^= (w >> (24 - 8 * r)) & 0xFF
        return bytes(st)

    for _ in range(50):
        k = os.urandom(32)
        rk = _expand_key(k)
        blk = os.urandom(16)
        assert _decrypt_block(blk, rk) == ref_decrypt(blk, rk), "T-table != ref"

    # 3. CBC chaining: blok ke-2 harus di-XOR dengan ciphertext blok ke-1
    k = os.urandom(32)
    iv = os.urandom(16)
    rk = _expand_key(k)
    c0, c1 = os.urandom(16), os.urandom(16)
    got = aes256_cbc_decrypt(k, iv, c0 + c1)
    exp = (bytes(a ^ b for a, b in zip(_decrypt_block(c0, rk), iv))
           + bytes(a ^ b for a, b in zip(_decrypt_block(c1, rk), c0)))
    assert got == exp, "CBC chaining salah"

    # 4. pkcs7_unpad
    assert pkcs7_unpad(b"HELLO" + bytes([3]) * 3) == b"HELLO"
    assert pkcs7_unpad(bytes([16]) * 16) == b""
    for bad in (b"", b"A", b"AB" + bytes([3]) * 2, bytes([17]) + b"A" * 15):
        try:
            pkcs7_unpad(bad if bad else b"\x00")
            raise SystemExit(f"unpad seharusnya gagal: {bad!r}")
        except ValueError:
            pass

    print("OK pyaes")
