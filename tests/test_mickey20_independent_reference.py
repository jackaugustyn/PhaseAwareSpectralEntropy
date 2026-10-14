"""Cross-check MICKEY 2.0 against a separate literal Appendix A translation."""

from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))

from extension_stream_cores import mickey20_iv_stream  # noqa: E402

N = 100
RTAPS = {
    0, 1, 3, 4, 5, 6, 9, 12, 13, 16, 19, 20, 21, 22, 25, 28, 37, 38,
    41, 42, 45, 46, 50, 52, 54, 56, 58, 60, 61, 63, 64, 65, 66, 67,
    71, 72, 79, 80, 81, 82, 87, 88, 89, 90, 91, 92, 94, 95, 96, 97,
}
COMP0 = [0] + [
    0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1,
    1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1,
]
COMP1 = [0] + [
    1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0,
    0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0,
    1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0,
    0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0,
]
FB0 = [
    1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1,
    1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1,
    0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0,
    0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0,
]
FB1 = [
    1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1,
    0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1,
    0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1,
    1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
]


def _msb_bits(data: bytes, nbits: int) -> list[int]:
    return [(data[i // 8] >> (7 - (i % 8))) & 1 for i in range(nbits)]


def _reference_mickey20(key: bytes, iv: bytes, preclock: int, nbytes: int) -> bytes:
    r = [0] * N
    s = [0] * N

    def clock_r(input_bit: int, control_bit: int) -> None:
        feedback = r[99] ^ input_bit
        nxt = [0] + r[:99]
        for tap in RTAPS:
            nxt[tap] ^= feedback
        if control_bit:
            for i in range(N):
                nxt[i] ^= r[i]
        r[:] = nxt

    def clock_s(input_bit: int, control_bit: int) -> None:
        feedback = s[99] ^ input_bit
        hat = [0] * N
        for i in range(1, 99):
            hat[i] = s[i - 1] ^ ((s[i] ^ COMP0[i]) & (s[i + 1] ^ COMP1[i]))
        hat[99] = s[98]
        fb = FB1 if control_bit else FB0
        s[:] = [hat[i] ^ (fb[i] & feedback) for i in range(N)]

    def clock_kg(mixing: bool, input_bit: int) -> None:
        control_r = s[34] ^ r[67]
        control_s = s[67] ^ r[33]
        input_r = (input_bit ^ s[50]) if mixing else input_bit
        clock_r(input_r, control_r)
        clock_s(input_bit, control_s)

    for bit in _msb_bits(iv, len(iv) * 8):
        clock_kg(True, bit)
    for bit in _msb_bits(key, 80):
        clock_kg(True, bit)
    for _ in range(preclock):
        clock_kg(True, 0)

    out = bytearray(nbytes)
    for index in range(nbytes * 8):
        out[index // 8] |= (r[0] ^ s[0]) << (7 - (index % 8))
        clock_kg(False, 0)
    return bytes(out)


def test_mickey20_matches_independent_appendix_a_reference() -> None:
    rng = random.Random(20260721)
    cases = [
        (bytes(10), b""),
        (bytes.fromhex("123456789abcdef01234"), bytes.fromhex("21436587")),
        (bytes.fromhex("123456789abcdef01234"), bytes.fromhex("2143658788")),
    ]
    cases.extend((rng.randbytes(10), rng.randbytes(rng.choice([0, 4, 8, 10]))) for _ in range(3))
    for key, iv in cases:
        for preclock in (0, 1, 25, 100):
            assert mickey20_iv_stream(key, iv, preclock, 16) == _reference_mickey20(
                key, iv, preclock, 16
            )
