"""Checks of resolution changes and the 512-bit block harmonic diagnostic."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))

from analyze_arx_resolution import aggregate_words, measure  # noqa: E402
from analyze_literature_mask_followup import _spectral  # noqa: E402


def test_aggregation_preserves_hw_and_legacy_128bit_order() -> None:
    rng = np.random.default_rng(6029)
    words = rng.integers(0, 33, (2, 3, 4, 8, 16), dtype=np.uint8)
    for width in (32, 64, 128):
        full = aggregate_words(words, width, 0, 8)
        first = aggregate_words(words, width, 0, 4)
        last = aggregate_words(words, width, 4, 8)
        assert np.array_equal(full.sum(axis=-1), words.sum(axis=(-2, -1)))
        assert np.array_equal(full, np.concatenate((first, last), axis=-1))
    legacy = words.reshape(2, 3, 4, 8, 4, 4).sum(axis=-1, dtype=np.uint8).reshape(2, 3, 4, 32)
    assert np.array_equal(aggregate_words(words, 128, 0, 8), legacy)
    maximum = np.full((4, 8, 16), 32, dtype=np.uint8)
    assert np.all(aggregate_words(maximum, 128, 0, 8) == 128)


def test_128bit_full_metrics_reproduce_legacy_estimator() -> None:
    rng = np.random.default_rng(6029)
    words = rng.integers(0, 33, (2, 3, 4, 8, 16), dtype=np.uint8)
    trajectories = aggregate_words(words, 128, 0, 8)
    old = _spectral(trajectories)
    new = measure(trajectories, 128)
    for name in ("hmp", "hnodc", "p0"):
        np.testing.assert_allclose(new[name], old[name], rtol=0, atol=2e-15)


def test_block_harmonics_track_512bits_at_each_resolution() -> None:
    # A within-block pattern repeated across all blocks has only block harmonics.
    word_profile = np.arange(16, dtype=np.uint8)
    words = np.tile(word_profile, (4, 8, 1))
    for width in (32, 64, 128):
        for stop in (4, 8):
            result = measure(aggregate_words(words, width, 0, stop), width)
            assert float(result["block_harmonic_share"]) == pytest.approx(1.0)
            assert float(result["phase_range_fraction"]) > 0
    # A variation between blocks that is constant inside each block has no
    # non-DC power at the block harmonics, despite substantial AC power.
    changing_blocks = np.broadcast_to(np.arange(8, dtype=np.uint8)[None, :, None], (4, 8, 16))
    for width in (32, 64, 128):
        result = measure(aggregate_words(changing_blocks, width, 0, 8), width)
        assert float(result["block_harmonic_share"]) == pytest.approx(0.0, abs=1e-30)
        assert float(result["phase_range_fraction"]) == 0


def test_constant_and_zero_trajectories_have_finite_defined_metrics() -> None:
    for value in (0, 64):
        result = measure(np.full((4, 32), value), 128)
        assert all(np.isfinite(x) for x in result.values())
        assert result["hmp"] == result["hnodc"] == result["block_harmonic_share"] == 0
        assert result["p0"] == int(value > 0)


def test_fundamental_distinguishes_block_period_from_shorter_subperiod() -> None:
    for width in (32, 64, 128):
        period = 512 // width
        positions = np.arange(8 * period)
        for cycles, expected in ((1, 1.0), (2, 0.0)):
            trajectory = 0.5 * width + 0.25 * width * np.cos(2 * np.pi * cycles * positions / period)
            result = measure(np.tile(trajectory, (4, 1)), width)
            assert result["block_harmonic_share"] == pytest.approx(1.0)
            assert result["block_fundamental_share"] == pytest.approx(expected, abs=1e-25)
