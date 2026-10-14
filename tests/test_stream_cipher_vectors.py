"""Published regression vectors for stream-cipher cores used in the study."""

from spectral_crypto_analyzer.primitives import (
    _a5_1_keystream_128,
    _grain128_keystream_128,
    _rc4_keystream_128,
    _trivium_keystream_128,
)


def test_trivium_zero_vector() -> None:
    """eSTREAM Set 2, vector 0: zero 80-bit key and IV."""
    actual = _trivium_keystream_128(bytes(10), bytes(10), 1152)
    assert actual.hex() == "fbe0bf265859051b517a2e4e239fc97f"


def test_rc4_key_vector() -> None:
    """RC4's canonical ``Key`` vector, before dropping output bytes."""
    actual = _rc4_keystream_128(b"Key", 0)
    assert actual.hex() == "eb9f7781b734ca72a7194a2867b64295"


def test_grain128_zero_regression_vector() -> None:
    """Original Grain-128 equations, zero key/IV, after 256 clocks."""
    actual = _grain128_keystream_128(bytes(16), bytes(12), 256)
    assert actual.hex() == "f09b7bf7d7f6b5c2de2ffc73ac21397f"


def test_a51_published_vector_prefix() -> None:
    """First 114 bits of the published A5/1 key/frame test vector."""
    actual = _a5_1_keystream_128(
        bytes.fromhex("1223456789abcdef"), frame22=0x134, warmup_rounds=100
    )
    expected_114 = bytes.fromhex("534eaa582fe8151ab6e1855a728c00")
    assert actual[:14] == expected_114[:14]
    assert actual[14] & 0xC0 == expected_114[14] & 0xC0
