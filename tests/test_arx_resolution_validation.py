"""Validation-cohort checks independent of any unpublished cohort observations."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))

from arx_resolution_validation import (aggregate_words, flip_nonce, holm, measure,
                                      sign_flip_pvalues, word_hw)


def test_aggregation_matches_direct_bits_in_both_window_halves() -> None:
    rng = np.random.default_rng(1029)
    left = rng.integers(0, 256, 1024, dtype=np.uint8).tobytes()
    right = rng.integers(0, 256, 1024, dtype=np.uint8).tobytes()
    words = word_hw(left, right)
    difference = np.unpackbits(np.bitwise_xor(np.frombuffer(left, dtype=np.uint8),
                                              np.frombuffer(right, dtype=np.uint8)))
    for width in (32, 64, 128):
        for start, stop in ((0, 16), (0, 8), (8, 16)):
            direct = difference[start*512:stop*512].reshape(-1, width).sum(axis=1)
            np.testing.assert_array_equal(aggregate_words(words, width, start, stop), direct)
        joined = np.concatenate((aggregate_words(words, width, 0, 8),
                                 aggregate_words(words, width, 8, 16)))
        np.testing.assert_array_equal(joined, aggregate_words(words, width, 0, 16))
    assert np.all(aggregate_words(np.full((16, 16), 32, dtype=np.uint8), 128, 0, 16) == 128)


def test_known_harmonic_and_fundamental_curves_for_six_windows() -> None:
    for width in (32, 64, 128):
        period = 512 // width
        for blocks in (8, 16):
            time = np.arange(period*blocks)
            for cycles, expected_fundamental in ((1, 1.0), (2, 0.0)):
                x = width/2 + width/4 * np.cos(2*np.pi*cycles*time/period)
                result = measure(np.tile(x, (4, 1)), width)
                assert result["block_harmonic_share"] == pytest.approx(1)
                assert result["block_fundamental_share"] == pytest.approx(expected_fundamental, abs=1e-25)


def test_sign_flips_use_plus_one_and_shared_whole_key_signs() -> None:
    values = np.array([[1., 0., -1.], [2., 0., -2.], [3., 0., -3.]])
    replicates, seed = 79, 77
    signs = 2*np.random.default_rng(seed).integers(0, 2, (replicates, 3), dtype=np.int8)-1
    expected_counts = np.array([sum(abs(sum(row[k]*values[k, column] for k in range(3)))
                                   >= abs(sum(values[:, column])) for row in signs)
                                for column in range(3)])
    p, counts = sign_flip_pvalues(values, replicates, seed)
    np.testing.assert_array_equal(counts, expected_counts)
    np.testing.assert_allclose(p, (expected_counts+1)/(replicates+1), rtol=0, atol=0)
    assert p[1] == 1 and p[0] == p[2] and np.all(p > 0)


def test_holm_known_cases_ties_and_original_order() -> None:
    np.testing.assert_allclose(holm(np.array([0.04, 0.01, 0.03])), [0.06, 0.03, 0.06])
    np.testing.assert_allclose(holm(np.full(5, 1/100001)), np.full(5, 5/100001))
    np.testing.assert_array_equal(holm(np.ones(5)), np.ones(5))


def test_nonce_mask56_is_second_little_endian_word_bit31() -> None:
    delta = flip_nonce(bytes(8), 56)
    assert int.from_bytes(delta[:4], "little") == 0
    assert int.from_bytes(delta[4:], "little") == 1 << 31
