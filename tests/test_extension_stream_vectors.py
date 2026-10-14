"""Published regression vectors for MICKEY 2.0, HC-128 and Rabbit."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))

from extension_stream_cores import (  # noqa: E402
    chacha20_iv_stream,
    hc128_iv_stream,
    mickey20_iv_stream,
    rabbit_iv_stream,
    rabbit_key_only_stream,
)


def test_chacha20_rfc8439_block_vector() -> None:
    """RFC 8439 Section 2.3.2, block counter one."""
    from spectral_crypto_analyzer.primitives import _chacha20_block_reduced

    expected = (
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4"
        "ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    assert _chacha20_block_reduced(key, nonce, 1, 20).hex() == expected
    assert chacha20_iv_stream(key, nonce, 20, 128)[64:] == bytes.fromhex(expected)


def test_rabbit_estream_key_only_vectors() -> None:
    """Crypto++ / eSTREAM rabbit.c key-only Tests 1--3."""
    cases = [
        (bytes(16), "02f74a1c26456bf5ecd6a536f05457b1a78ac689476c697b390c9cc515d8e888"),
        (
            bytes.fromhex("c21fcf3881cd5ee8628accb0a9890df8"),
            "3d02e0c730559112b473b790dee018dfcd6d730ce54e19f0c35ec4790eb6c74a",
        ),
        (
            bytes.fromhex("1d272c6a2d8e3dfcac14056b78d633a0"),
            "a3a97abb80393820b7e50c4abb53823dc4423799c2efc9ffb3a4125f1f4c99a8",
        ),
    ]
    for key, expected in cases:
        assert rabbit_key_only_stream(key, 32).hex() == expected


def test_rabbit_estream_iv_vectors() -> None:
    """Crypto++ RabbitWithIV Tests 4--6 (eSTREAM rabbit.c with IV)."""
    cases = [
        (bytes(16), bytes(8), "edb70567375dcd7cd89554f85e27a7c68d4adc7032298f7bd4eff504aca6295f"),
        (
            bytes(16),
            bytes.fromhex("597e26c175f573c3"),
            "6d7d012292ccdce0e2120058b94ecd1f2e6f93edff99247b012521d1104e5fa7",
        ),
        (
            bytes(16),
            bytes.fromhex("2717f4d21a56eba6"),
            "4d1051a123afb670bf8d8505c8d85a44035bc3acc667aeae5b2cf44779f2c896",
        ),
    ]
    for key, iv, expected in cases:
        assert rabbit_iv_stream(key, iv, 4, 32).hex() == expected


def test_hc128_wu_estream_vectors() -> None:
    """Wu HC-128 / eSTREAM first-block vectors (also in Crypto++ hc128.txt)."""
    cases = [
        (bytes(16), bytes(16), "82001573a003fd3b7fd72ffb0eaf63aa"),
        (
            bytes.fromhex("80000000000000000000000000000000"),
            bytes(16),
            "378602b98f32a74847515654ae0de7ed",
        ),
        (
            bytes(16),
            bytes.fromhex("80000000000000000000000000000000"),
            "337f8611c6ed615fc2e7d28c6daaaf1b",
        ),
    ]
    for key, iv, expected in cases:
        assert hc128_iv_stream(key, iv, 1024, 16).hex() == expected


def test_mickey20_published_example_vectors() -> None:
    """asecuritysite MICKEY V2 examples (eSTREAM ECRYPT API)."""
    key = bytes.fromhex("123456789abcdef01234")
    assert (
        mickey20_iv_stream(key, bytes.fromhex("21436587"), 100, 16).hex()
        == "9821e10c5ed28d32bbc3d1fb15e93a15"
    )
    assert (
        mickey20_iv_stream(key, bytes.fromhex("2143658788"), 100, 16, iv_bits=40).hex()
        == "f4eb021dab78c9da2d633161d848226b"
    )


def test_extension_vector_catalog_files_present() -> None:
    catalog = ROOT / "tests" / "vectors" / "extension"
    assert (catalog / "rabbit_estream_cryptopp.txt").is_file()
    assert (catalog / "hc128_wu_estream.txt").is_file()
    assert (catalog / "mickey20_asecuritysite.txt").is_file()
