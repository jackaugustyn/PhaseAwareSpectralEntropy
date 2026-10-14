"""Reference-checked stream-cipher cores for ordinary-IV/nonce studies.

Partial initialization and reduced rounds are experimental variants.
"""

from __future__ import annotations

import struct

from spectral_crypto_analyzer.primitives import _chacha20_block_reduced


MASK32 = 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & MASK32


def _rotr(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK32


def chacha20_iv_stream(key: bytes, nonce: bytes, rounds: int, nbytes: int) -> bytes:
    """IETF ChaCha20, counter zero onward, with an even number of rounds."""
    if len(key) != 32 or len(nonce) != 12 or nbytes < 0:
        raise ValueError("ChaCha20 needs a 32-byte key and 12-byte nonce")
    return b"".join(
        _chacha20_block_reduced(key, nonce, counter, rounds)
        for counter in range((nbytes + 63) // 64)
    )[:nbytes]


def _salsa20_block_reduced(key: bytes, nonce: bytes, counter: int, rounds: int) -> bytes:
    """Salsa20/rounds block with a 256-bit key and the original 64-bit nonce."""
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("Salsa20 needs a 32-byte key and 8-byte nonce")
    if rounds not in range(2, 21, 2) or not 0 <= counter < 1 << 64:
        raise ValueError("Salsa20 needs 2--20 even rounds and a 64-bit counter")
    constants = struct.unpack("<4I", b"expand 32-byte k")
    words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<2I", nonce)
    initial = [
        constants[0], *words[:4], constants[1], *nonce_words,
        counter & MASK32, counter >> 32, constants[2], *words[4:], constants[3],
    ]
    state = initial[:]

    def quarter(a: int, b: int, c: int, d: int) -> None:
        state[b] ^= _rotl((state[a] + state[d]) & MASK32, 7)
        state[c] ^= _rotl((state[b] + state[a]) & MASK32, 9)
        state[d] ^= _rotl((state[c] + state[b]) & MASK32, 13)
        state[a] ^= _rotl((state[d] + state[c]) & MASK32, 18)

    for _ in range(rounds // 2):
        for indices in ((0, 4, 8, 12), (5, 9, 13, 1),
                        (10, 14, 2, 6), (15, 3, 7, 11)):
            quarter(*indices)
        for indices in ((0, 1, 2, 3), (5, 6, 7, 4),
                        (10, 11, 8, 9), (15, 12, 13, 14)):
            quarter(*indices)
    return struct.pack("<16I", *((a + b) & MASK32 for a, b in zip(state, initial)))


def salsa20_iv_stream(key: bytes, nonce: bytes, rounds: int, nbytes: int) -> bytes:
    """Salsa20/rounds stream starting with 64-bit block counter zero."""
    if len(key) != 32 or len(nonce) != 8 or rounds not in range(2, 21, 2) or nbytes < 0:
        raise ValueError("Salsa20 needs a 32-byte key, 8-byte nonce, even 2--20 rounds, and nonnegative length")
    return b"".join(
        _salsa20_block_reduced(key, nonce, counter, rounds)
        for counter in range((nbytes + 63) // 64)
    )[:nbytes]


_RABBIT_A = (
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
    0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3,
)


def _rabbit_next(x: list[int], c: list[int], carry: int) -> int:
    """One Rabbit next-state step (eSTREAM / Crypto++ rabbit.c)."""
    old = c[:]
    c[0] = (old[0] + _RABBIT_A[0] + carry) & MASK32
    for i in range(1, 8):
        c[i] = (old[i] + _RABBIT_A[i] + int(c[i - 1] < old[i - 1])) & MASK32
    carry = int(c[7] < old[7])
    g = [(((x[i] + c[i]) & MASK32) ** 2) for i in range(8)]
    g = [((square >> 32) ^ square) & MASK32 for square in g]
    x[0] = (g[0] + _rotl(g[7], 16) + _rotl(g[6], 16)) & MASK32
    x[1] = (g[1] + _rotl(g[0], 8) + g[7]) & MASK32
    x[2] = (g[2] + _rotl(g[1], 16) + _rotl(g[0], 16)) & MASK32
    x[3] = (g[3] + _rotl(g[2], 8) + g[1]) & MASK32
    x[4] = (g[4] + _rotl(g[3], 16) + _rotl(g[2], 16)) & MASK32
    x[5] = (g[5] + _rotl(g[4], 8) + g[3]) & MASK32
    x[6] = (g[6] + _rotl(g[5], 16) + _rotl(g[4], 16)) & MASK32
    x[7] = (g[7] + _rotl(g[6], 8) + g[5]) & MASK32
    return carry


def _rabbit_key_state(key: bytes) -> tuple[list[int], list[int], int]:
    """Master key setup matching the eSTREAM rabbit.c reference."""
    if len(key) != 16:
        raise ValueError("Rabbit needs a 16-byte key")
    t = list(struct.unpack("<4I", key))
    x = [
        t[0],
        ((t[3] << 16) | (t[2] >> 16)) & MASK32,
        t[1],
        ((t[0] << 16) | (t[3] >> 16)) & MASK32,
        t[2],
        ((t[1] << 16) | (t[0] >> 16)) & MASK32,
        t[3],
        ((t[2] << 16) | (t[1] >> 16)) & MASK32,
    ]
    c = [
        _rotl(t[2], 16),
        (t[0] & 0xFFFF0000) | (t[1] & 0xFFFF),
        _rotl(t[3], 16),
        (t[1] & 0xFFFF0000) | (t[2] & 0xFFFF),
        _rotl(t[0], 16),
        (t[2] & 0xFFFF0000) | (t[3] & 0xFFFF),
        _rotl(t[1], 16),
        (t[3] & 0xFFFF0000) | (t[0] & 0xFFFF),
    ]
    carry = 0
    for _ in range(4):
        carry = _rabbit_next(x, c, carry)
    for i in range(8):
        c[i] ^= x[(i + 4) % 8]
    return x, c, carry


def _rabbit_output(x: list[int]) -> bytes:
    words = (
        x[0] ^ (x[5] >> 16) ^ ((x[3] << 16) & MASK32),
        x[2] ^ (x[7] >> 16) ^ ((x[5] << 16) & MASK32),
        x[4] ^ (x[1] >> 16) ^ ((x[7] << 16) & MASK32),
        x[6] ^ (x[3] >> 16) ^ ((x[1] << 16) & MASK32),
    )
    return struct.pack("<4I", *(word & MASK32 for word in words))


def rabbit_iv_stream(key: bytes, iv: bytes, setup_iterations: int, nbytes: int) -> bytes:
    """Rabbit with a truncated final IV setup; four iterations are standard."""
    if len(iv) != 8 or setup_iterations not in range(5) or nbytes < 0:
        raise ValueError("Rabbit needs an 8-byte IV and 0--4 IV iterations")
    master_x, master_c, master_carry = _rabbit_key_state(key)
    x = master_x[:]
    c = master_c[:]
    carry = master_carry
    v0, v1 = struct.unpack("<2I", iv)
    subv = (
        v0,
        ((v0 >> 16) | (v1 & 0xFFFF0000)) & MASK32,
        v1,
        (((v1 << 16) & MASK32) | (v0 & 0xFFFF)) & MASK32,
    )
    for i in range(8):
        c[i] ^= subv[i % 4]
    for _ in range(setup_iterations):
        carry = _rabbit_next(x, c, carry)
    result = bytearray()
    for _ in range((nbytes + 15) // 16):
        carry = _rabbit_next(x, c, carry)
        result += _rabbit_output(x)
    return bytes(result[:nbytes])


def rabbit_key_only_stream(key: bytes, nbytes: int) -> bytes:
    """The no-IV Rabbit mode, used only for a published regression vector."""
    x, c, carry = _rabbit_key_state(key)
    result = bytearray()
    for _ in range((nbytes + 15) // 16):
        carry = _rabbit_next(x, c, carry)
        result += _rabbit_output(x)
    return bytes(result[:nbytes])


def _hc_f1(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _hc_f2(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def _hc_g1(x: int, y: int, z: int) -> int:
    return ((_rotr(x, 10) ^ _rotr(z, 23)) + _rotr(y, 8)) & MASK32


def _hc_g2(x: int, y: int, z: int) -> int:
    return ((_rotl(x, 10) ^ _rotl(z, 23)) + _rotl(y, 8)) & MASK32


def _hc_h1(q: list[int], x: int) -> int:
    return (q[x & 255] + q[256 + ((x >> 16) & 255)]) & MASK32


def _hc_h2(p: list[int], x: int) -> int:
    return (p[x & 255] + p[256 + ((x >> 16) & 255)]) & MASK32


def hc128_iv_stream(key: bytes, iv: bytes, init_steps: int, nbytes: int) -> bytes:
    """HC-128 with 0--1024 final initialization updates (1024 standard)."""
    if len(key) != 16 or len(iv) != 16 or init_steps not in range(1025) or nbytes < 0:
        raise ValueError("HC-128 needs 16-byte key/IV and 0--1024 init steps")
    kw = list(struct.unpack("<4I", key))
    iw = list(struct.unpack("<4I", iv))
    w = kw + kw + iw + iw
    for i in range(16, 1280):
        w.append((_hc_f2(w[i - 2]) + w[i - 7] + _hc_f1(w[i - 15]) + w[i - 16] + i) & MASK32)
    p = w[256:768]
    q = w[768:1280]
    for i in range(init_steps):
        j = i & 511
        if i < 512:
            p[j] = (p[j] + _hc_g1(p[(j - 3) & 511], p[(j - 10) & 511], p[(j - 511) & 511])) & MASK32
            p[j] ^= _hc_h1(q, p[(j - 12) & 511])
        else:
            q[j] = (q[j] + _hc_g2(q[(j - 3) & 511], q[(j - 10) & 511], q[(j - 511) & 511])) & MASK32
            q[j] ^= _hc_h2(p, q[(j - 12) & 511])
    result = bytearray()
    for i in range((nbytes + 3) // 4):
        j = i & 511
        if (i & 1023) < 512:
            p[j] = (p[j] + _hc_g1(p[(j - 3) & 511], p[(j - 10) & 511], p[(j - 511) & 511])) & MASK32
            word = p[j] ^ _hc_h1(q, p[(j - 12) & 511])
        else:
            q[j] = (q[j] + _hc_g2(q[(j - 3) & 511], q[(j - 10) & 511], q[(j - 511) & 511])) & MASK32
            word = q[j] ^ _hc_h2(p, q[(j - 12) & 511])
        result += struct.pack("<I", word)
    return bytes(result[:nbytes])


# MICKEY 2.0 (80-bit key, IV length 0--80 bits). Spec: Babbage & Dodd,
# "The MICKEY stream ciphers", LNCS 4986; tables from Appendix A.
_MICKEY_N = 100
_MICKEY_RTAPS = frozenset(
    {
        0, 1, 3, 4, 5, 6, 9, 12, 13, 16, 19, 20, 21, 22, 25, 28, 37, 38,
        41, 42, 45, 46, 50, 52, 54, 56, 58, 60, 61, 63, 64, 65, 66, 67,
        71, 72, 79, 80, 81, 82, 87, 88, 89, 90, 91, 92, 94, 95, 96, 97,
    }
)
# COMP0/COMP1 are indexed 1..98; slot 0 unused.
_MICKEY_COMP0 = [0] + [
    0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1,
    1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1,
]
_MICKEY_COMP1 = [0] + [
    1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0,
    0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0,
    1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0,
    0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0,
]
_MICKEY_FB0 = [
    1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1,
    1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1,
    0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0,
    0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0,
]
_MICKEY_FB1 = [
    1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1,
    0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1,
    0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1,
    1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
]


def _mickey_bits_msb(data: bytes, nbits: int) -> list[int]:
    bits = []
    for index in range(nbits):
        bits.append((data[index // 8] >> (7 - (index % 8))) & 1)
    return bits


def _mickey_clock_r(r: list[int], input_bit: int, control_bit: int) -> None:
    feedback = r[99] ^ input_bit
    nxt = [0] + r[:99]
    for i in _MICKEY_RTAPS:
        nxt[i] ^= feedback
    if control_bit:
        for i in range(_MICKEY_N):
            nxt[i] ^= r[i]
    r[:] = nxt


def _mickey_clock_s(s: list[int], input_bit: int, control_bit: int) -> None:
    feedback = s[99] ^ input_bit
    hat = [0] * _MICKEY_N
    hat[0] = 0
    for i in range(1, 99):
        hat[i] = s[i - 1] ^ ((s[i] ^ _MICKEY_COMP0[i]) & (s[i + 1] ^ _MICKEY_COMP1[i]))
    hat[99] = s[98]
    fb = _MICKEY_FB1 if control_bit else _MICKEY_FB0
    s[:] = [hat[i] ^ (fb[i] & feedback) for i in range(_MICKEY_N)]


def _mickey_clock_kg(r: list[int], s: list[int], mixing: bool, input_bit: int) -> None:
    control_r = s[34] ^ r[67]
    control_s = s[67] ^ r[33]
    input_r = (input_bit ^ s[50]) if mixing else input_bit
    _mickey_clock_r(r, input_r, control_r)
    _mickey_clock_s(s, input_bit, control_s)


def mickey20_iv_stream(
    key: bytes, iv: bytes, preclock: int, nbytes: int, *, iv_bits: int | None = None
) -> bytes:
    """MICKEY 2.0 keystream; ``preclock=100`` is the standard blank init."""
    if len(key) != 10 or nbytes < 0 or preclock < 0:
        raise ValueError("MICKEY 2.0 needs a 10-byte key and non-negative sizes")
    if iv_bits is None:
        iv_bits = len(iv) * 8
    if iv_bits < 0 or iv_bits > 80 or (iv_bits + 7) // 8 > len(iv):
        raise ValueError("MICKEY 2.0 IV length must be 0--80 bits")
    r = [0] * _MICKEY_N
    s = [0] * _MICKEY_N
    for bit in _mickey_bits_msb(iv, iv_bits):
        _mickey_clock_kg(r, s, True, bit)
    for bit in _mickey_bits_msb(key, 80):
        _mickey_clock_kg(r, s, True, bit)
    for _ in range(preclock):
        _mickey_clock_kg(r, s, True, 0)
    out = bytearray(nbytes)
    for index in range(nbytes * 8):
        out[index // 8] |= (r[0] ^ s[0]) << (7 - (index % 8))
        _mickey_clock_kg(r, s, False, 0)
    return bytes(out)
