"""Cross-check Grain-128 against the independent ECRYPT reference equations.

The implementation below is deliberately separate from the production helper
and follows Martin Hell's ECRYPT reference code register update literally.
"""

from __future__ import annotations

import random

from spectral_crypto_analyzer.primitives import _grain128_keystream_128


def _bits_lsb(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(8)]


def _reference_grain128(key: bytes, iv: bytes, warmup: int) -> bytes:
    nfsr = _bits_lsb(key)
    lfsr = _bits_lsb(iv) + [1] * 32

    def clock(initializing: bool) -> int:
        output = (
            nfsr[2]
            ^ nfsr[15]
            ^ nfsr[36]
            ^ nfsr[45]
            ^ nfsr[64]
            ^ nfsr[73]
            ^ nfsr[89]
            ^ lfsr[93]
            ^ (nfsr[12] & lfsr[8])
            ^ (lfsr[13] & lfsr[20])
            ^ (nfsr[95] & lfsr[42])
            ^ (lfsr[60] & lfsr[79])
            ^ (nfsr[12] & nfsr[95] & lfsr[95])
        )
        nbit = (
            lfsr[0]
            ^ nfsr[0]
            ^ nfsr[26]
            ^ nfsr[56]
            ^ nfsr[91]
            ^ nfsr[96]
            ^ (nfsr[3] & nfsr[67])
            ^ (nfsr[11] & nfsr[13])
            ^ (nfsr[17] & nfsr[18])
            ^ (nfsr[27] & nfsr[59])
            ^ (nfsr[40] & nfsr[48])
            ^ (nfsr[61] & nfsr[65])
            ^ (nfsr[68] & nfsr[84])
        )
        lbit = lfsr[0] ^ lfsr[7] ^ lfsr[38] ^ lfsr[70] ^ lfsr[81] ^ lfsr[96]
        if initializing:
            nbit ^= output
            lbit ^= output
        nfsr[:] = nfsr[1:] + [nbit]
        lfsr[:] = lfsr[1:] + [lbit]
        return output

    for _ in range(warmup):
        clock(initializing=True)
    output = bytearray(16)
    for index in range(128):
        output[index // 8] |= clock(initializing=False) << (index % 8)
    return bytes(output)


def test_grain128_matches_independent_ecrypt_reference() -> None:
    rng = random.Random(20260721)
    cases = [(bytes(16), bytes(12))]
    cases.extend((rng.randbytes(16), rng.randbytes(12)) for _ in range(4))
    for key, iv in cases:
        for warmup in (0, 1, 32, 256, 512):
            assert _grain128_keystream_128(key, iv, warmup) == _reference_grain128(
                key, iv, warmup
            )
