"""Independent standard Salsa20 vectors and reduced-round core cross-check."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))

from extension_stream_cores import _salsa20_block_reduced, salsa20_iv_stream  # noqa: E402


def test_salsa20_libsodium_standard_vectors() -> None:
    catalog = ROOT / "tests" / "vectors" / "extension" / "salsa20_libsodium.json"
    vectors = json.loads(catalog.read_text())
    for case in vectors["cases"]:
        key, nonce, expected = (bytes.fromhex(case[name]) for name in ("key", "nonce", "stream"))
        assert salsa20_iv_stream(key, nonce, 20, len(expected)) == expected


def _reference_block(key: bytes, nonce: bytes, counter: int, rounds: int) -> bytes:
    """Literal pure-function columnround/rowround translation of Salsa20."""
    mask = 0xFFFFFFFF

    def rotl(value: int, n: int) -> int:
        return ((value << n) | (value >> (32 - n))) & mask

    def qr(x: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
        a, b, c, d = x
        b ^= rotl((a + d) & mask, 7)
        c ^= rotl((b + a) & mask, 9)
        d ^= rotl((c + b) & mask, 13)
        a ^= rotl((d + c) & mask, 18)
        return a, b, c, d

    def transform(state: tuple[int, ...], groups: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
        result = list(state)
        for group in groups:
            for index, value in zip(group, qr(tuple(state[index] for index in group))):
                result[index] = value
        return tuple(result)

    constants = struct.unpack("<4I", b"expand 32-byte k")
    words = struct.unpack("<8I", key)
    iv = struct.unpack("<2I", nonce)
    initial = (constants[0], *words[:4], constants[1], *iv,
               counter & mask, counter >> 32, constants[2], *words[4:], constants[3])
    state = initial
    columns = ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11))
    rows = ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14))
    for _ in range(rounds // 2):
        state = transform(transform(state, columns), rows)
    return struct.pack("<16I", *((a + b) & mask for a, b in zip(state, initial)))


def test_salsa20_reduced_rounds_against_literal_reference() -> None:
    for key, nonce, counter in ((bytes(32), bytes(8), 0),
                                (bytes(range(32)), bytes(range(8)), 7),
                                (bytes.fromhex("80" + "00" * 31), bytes.fromhex("0011223344556677"), 1)):
        for rounds in (2, 4, 6, 8, 12, 20):
            assert _salsa20_block_reduced(key, nonce, counter, rounds) == \
                   _reference_block(key, nonce, counter, rounds)
