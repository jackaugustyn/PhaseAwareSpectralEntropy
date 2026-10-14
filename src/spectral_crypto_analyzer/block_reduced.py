"""Reduced-round block-cipher cores for comparative spectral studies.

All public encrypt helpers map a 128-bit block to a 128-bit block so they fit
the analyzer contract. 64-bit designs (DES, PRESENT) encrypt the two 64-bit
halves independently under the same key (parallel ECB), which preserves a
single round-count axis while keeping the output width at 128 bits.

These implementations are for *analysis only*, not production use.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# Speck128/128 (ARX, 32 rounds) — Beaulieu et al., NSA
# ---------------------------------------------------------------------------

_SPECK128_ROUNDS = 32


def _speck128_ror(x: int, r: int) -> int:
    return ((x >> r) | (x << (64 - r))) & 0xFFFFFFFFFFFFFFFF


def _speck128_rol(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & 0xFFFFFFFFFFFFFFFF


def _speck128_key_schedule(key: bytes) -> list[int]:
    """Speck128/128 key schedule: 16-byte key → 32 round keys.

    Key bytes are interpreted as two little-endian 64-bit words (K[0], K[1]),
    matching the NSA reference memory layout.
    """
    if len(key) != 16:
        raise ValueError("Speck128/128 key must be 16 bytes")
    a = int.from_bytes(key[0:8], "little")
    b = int.from_bytes(key[8:16], "little")
    round_keys: list[int] = []
    for i in range(_SPECK128_ROUNDS):
        round_keys.append(a)
        b = (_speck128_ror(b, 8) + a) & 0xFFFFFFFFFFFFFFFF
        b ^= i
        a = _speck128_rol(a, 3) ^ b
    return round_keys


def speck128_encrypt_reduced(block: bytes, key: bytes, rounds: int) -> bytes:
    """Encrypt one 128-bit Speck128/128 block with *rounds* of 32.

    Plaintext/ciphertext bytes are two little-endian words (P[0], P[1]);
    each round updates ``R(P[1], P[0], rk)`` as in the NSA reference code.
    """
    if not 1 <= rounds <= _SPECK128_ROUNDS:
        raise ValueError(f"Speck128 rounds must be 1-{_SPECK128_ROUNDS}, got {rounds}")
    if len(block) != 16:
        raise ValueError("Speck128 block must be 16 bytes")
    rk = _speck128_key_schedule(key)
    y = int.from_bytes(block[0:8], "little")
    x = int.from_bytes(block[8:16], "little")
    for i in range(rounds):
        x = (_speck128_ror(x, 8) + y) & 0xFFFFFFFFFFFFFFFF
        x ^= rk[i]
        y = _speck128_rol(y, 3) ^ x
    return y.to_bytes(8, "little") + x.to_bytes(8, "little")


# ---------------------------------------------------------------------------
# SM4 (Feistel, 32 rounds) — GB/T 32907-2016
# ---------------------------------------------------------------------------

_SM4_SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
]

_SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

_SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
]

_SM4_ROUNDS = 32


def _sm4_rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm4_tau(a: int) -> int:
    return (
        (_SM4_SBOX[(a >> 24) & 0xFF] << 24)
        | (_SM4_SBOX[(a >> 16) & 0xFF] << 16)
        | (_SM4_SBOX[(a >> 8) & 0xFF] << 8)
        | _SM4_SBOX[a & 0xFF]
    )


def _sm4_l(b: int) -> int:
    return b ^ _sm4_rol(b, 2) ^ _sm4_rol(b, 10) ^ _sm4_rol(b, 18) ^ _sm4_rol(b, 24)


def _sm4_l_prime(b: int) -> int:
    return b ^ _sm4_rol(b, 13) ^ _sm4_rol(b, 23)


def _sm4_t(x: int) -> int:
    return _sm4_l(_sm4_tau(x))


def _sm4_t_prime(x: int) -> int:
    return _sm4_l_prime(_sm4_tau(x))


def _sm4_key_schedule(key: bytes) -> list[int]:
    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes")
    mk = list(struct.unpack(">4I", key))
    k = [mk[i] ^ _SM4_FK[i] for i in range(4)]
    rk: list[int] = []
    for i in range(_SM4_ROUNDS):
        next_k = k[i] ^ _sm4_t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _SM4_CK[i])
        k.append(next_k)
        rk.append(next_k)
    return rk


def sm4_encrypt_reduced(block: bytes, key: bytes, rounds: int) -> bytes:
    """Encrypt one 128-bit SM4 block with *rounds* of 32 Feistel rounds."""
    if not 1 <= rounds <= _SM4_ROUNDS:
        raise ValueError(f"SM4 rounds must be 1-{_SM4_ROUNDS}, got {rounds}")
    if len(block) != 16:
        raise ValueError("SM4 block must be 16 bytes")
    rk = _sm4_key_schedule(key)
    x = list(struct.unpack(">4I", block))
    for i in range(rounds):
        x.append(x[i] ^ _sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
    # Standard SM4 reverse-order output of the last four words.
    out = x[rounds + 3], x[rounds + 2], x[rounds + 1], x[rounds]
    return struct.pack(">4I", *out)


# ---------------------------------------------------------------------------
# PRESENT-80 (SPN, 31 rounds, 64-bit block) — Bogdanov et al.
# Dual-half ECB maps 128-bit analyzer states.
# ---------------------------------------------------------------------------

_PRESENT_SBOX = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
]

_PRESENT_ROUNDS = 31


def _present_sbox_layer(state: int) -> int:
    out = 0
    for i in range(16):
        nibble = (state >> (4 * i)) & 0xF
        out |= _PRESENT_SBOX[nibble] << (4 * i)
    return out


def _present_p_layer_fixed(state: int) -> int:
    """PRESENT bit permutation P(i) = 16*i mod 63 for i < 63, P(63)=63."""
    out = 0
    for i in range(64):
        bit = (state >> i) & 1
        if i == 63:
            j = 63
        else:
            j = (16 * i) % 63
        out |= bit << j
    return out


def _present80_key_schedule(key: bytes) -> list[int]:
    """80-bit key → 32 round keys of 64 bits (addRoundKey uses top 64)."""
    if len(key) < 10:
        raise ValueError("PRESENT-80 key must be at least 10 bytes")
    # Store 80-bit key as integer (MSB first).
    k = int.from_bytes(key[:10], "big")
    round_keys: list[int] = []
    for i in range(1, _PRESENT_ROUNDS + 2):
        round_keys.append((k >> 16) & 0xFFFFFFFFFFFFFFFF)
        # Rotate left by 61 bits within 80-bit register.
        k = ((k << 61) | (k >> 19)) & ((1 << 80) - 1)
        # S-box on leftmost 4 bits.
        top = (k >> 76) & 0xF
        k = (k & ((1 << 76) - 1)) | (_PRESENT_SBOX[top] << 76)
        # XOR round counter into bits 19..15.
        k ^= (i & 0x1F) << 15
    return round_keys


def _present80_encrypt_64(block8: bytes, key: bytes, rounds: int) -> bytes:
    if not 1 <= rounds <= _PRESENT_ROUNDS:
        raise ValueError(f"PRESENT rounds must be 1-{_PRESENT_ROUNDS}, got {rounds}")
    if len(block8) != 8:
        raise ValueError("PRESENT block must be 8 bytes")
    rk = _present80_key_schedule(key)
    state = int.from_bytes(block8, "big")
    for i in range(rounds):
        state ^= rk[i]
        state = _present_sbox_layer(state)
        state = _present_p_layer_fixed(state)
    state ^= rk[rounds]
    return state.to_bytes(8, "big")


def present80_encrypt_reduced(block: bytes, key: bytes, rounds: int) -> bytes:
    """Encrypt 128 bits as two independent PRESENT-80 blocks (parallel ECB)."""
    if len(block) != 16:
        raise ValueError("PRESENT dual-block input must be 16 bytes")
    key10 = key[:10].ljust(10, b"\x00")
    return _present80_encrypt_64(block[:8], key10, rounds) + _present80_encrypt_64(
        block[8:], key10, rounds
    )


# ---------------------------------------------------------------------------
# DES (Feistel, 16 rounds, 64-bit block) — FIPS 46-3
# Dual-half ECB maps 128-bit analyzer states.
# ---------------------------------------------------------------------------

_DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

_DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

_DES_E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

_DES_P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

_DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

_DES_PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

_DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_DES_SBOX = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]

_DES_ROUNDS = 16


def _des_permute(value: int, table: list[int], in_bits: int) -> int:
    out = 0
    for pos in table:
        bit = (value >> (in_bits - pos)) & 1
        out = (out << 1) | bit
    return out


def _des_rol28(x: int, n: int) -> int:
    return ((x << n) | (x >> (28 - n))) & 0x0FFFFFFF


def _des_key_schedule(key8: bytes) -> list[int]:
    if len(key8) != 8:
        raise ValueError("DES key must be 8 bytes")
    key = int.from_bytes(key8, "big")
    cd = _des_permute(key, _DES_PC1, 64)
    c = (cd >> 28) & 0x0FFFFFFF
    d = cd & 0x0FFFFFFF
    subkeys: list[int] = []
    for shift in _DES_SHIFTS:
        c = _des_rol28(c, shift)
        d = _des_rol28(d, shift)
        cd = (c << 28) | d
        subkeys.append(_des_permute(cd, _DES_PC2, 56))
    return subkeys


def _des_f(r: int, subkey: int) -> int:
    expanded = _des_permute(r, _DES_E, 32)
    x = expanded ^ subkey
    s_out = 0
    for i in range(8):
        chunk = (x >> (42 - 6 * i)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 0x01)
        col = (chunk >> 1) & 0x0F
        s_out = (s_out << 4) | _DES_SBOX[i][16 * row + col]
    return _des_permute(s_out, _DES_P, 32)


def _des_encrypt_64(block8: bytes, key8: bytes, rounds: int) -> bytes:
    if not 1 <= rounds <= _DES_ROUNDS:
        raise ValueError(f"DES rounds must be 1-{_DES_ROUNDS}, got {rounds}")
    if len(block8) != 8:
        raise ValueError("DES block must be 8 bytes")
    subkeys = _des_key_schedule(key8)
    block = int.from_bytes(block8, "big")
    block = _des_permute(block, _DES_IP, 64)
    l = (block >> 32) & 0xFFFFFFFF
    r = block & 0xFFFFFFFF
    for i in range(rounds):
        l, r = r, l ^ _des_f(r, subkeys[i])
    # Final swap is omitted after the last round in the classic description:
    # after Nr Feistel steps, preoutput is R||L before FP.
    preoutput = ((r & 0xFFFFFFFF) << 32) | (l & 0xFFFFFFFF)
    out = _des_permute(preoutput, _DES_FP, 64)
    return out.to_bytes(8, "big")


def des_encrypt_reduced(block: bytes, key: bytes, rounds: int) -> bytes:
    """Encrypt 128 bits as two independent DES blocks (parallel ECB)."""
    if len(block) != 16:
        raise ValueError("DES dual-block input must be 16 bytes")
    key8 = key[:8].ljust(8, b"\x00")
    return _des_encrypt_64(block[:8], key8, rounds) + _des_encrypt_64(block[8:], key8, rounds)