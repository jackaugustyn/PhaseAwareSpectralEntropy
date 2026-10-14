"""Independent ChaCha nonce-layout and within-block intervention checks."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))

from extension_stream_cores import chacha20_iv_stream  # noqa: E402
from matched_nonce_phase_study import _rotated, _spectral  # noqa: E402


def test_mapped_ietf_chacha_matches_independent_original_layout() -> None:
    cases = (
        (bytes(32), bytes(8)),
        (bytes(range(32)), bytes(range(8))),
        (bytes.fromhex("80" + "00" * 31), bytes.fromhex("0011223344556677")),
    )
    for key, nonce64 in cases:
        independent = Cipher(algorithms.ChaCha20(key, bytes(8) + nonce64), mode=None)
        reference = independent.encryptor().update(bytes(512))
        mapped = chacha20_iv_stream(key, bytes(4) + nonce64, 20, 512)
        assert mapped == reference


def test_cyclic_rotation_preserves_each_trajectory_and_dc_share() -> None:
    rng = np.random.default_rng(20261025)
    values = rng.integers(0, 129, size=(16, 32), dtype=np.uint8)
    shifts = rng.integers(0, 4, size=(128, 16, 8), dtype=np.uint8)
    rotated = _rotated(values, shifts)
    assert np.array_equal(np.sort(rotated, axis=-1),
                          np.broadcast_to(np.sort(values, axis=-1), rotated.shape))
    original_p0 = _spectral(values)[1]
    rotated_p0 = _spectral(rotated)[1]
    assert np.allclose(rotated_p0, original_p0, rtol=0, atol=1e-12)
