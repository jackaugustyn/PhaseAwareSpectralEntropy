"""Model-law checks without fitting or observing the new evaluation cohort."""
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/stream_rounds_study"))
from arx_spectral_prediction import (INDICES, SMOKE_INDICES, bootstrap_weights,
                                    empirical_fit, expected_power, measured,
                                    normalize_power, sample_model)


def test_expected_power_matches_exact_enumeration_of_independent_residuals() -> None:
    # One Bernoulli word in each of sixteen blocks: enumerate all 2**16
    # outcomes, each with equal probability, before comparing every DFT bin.
    mean = np.zeros(16)
    variance = np.zeros(16)
    mean[0], variance[0] = 0.5, 0.25
    exact = np.zeros(64)
    for start in range(0, 1 << 16, 256):
        bits = ((np.arange(start, start+256)[:, None] >> np.arange(16)) & 1)
        trajectories = np.zeros((256, 64))
        trajectories[:, ::4] = bits
        exact += (abs(np.fft.fft(trajectories, axis=-1)) ** 2).sum(axis=0)
    exact /= 1 << 16
    np.testing.assert_allclose(expected_power(mean, variance, 128), exact, rtol=0, atol=5e-12)


def test_layer_average_is_not_power_of_the_pooled_mean() -> None:
    means = np.zeros((2, 16))
    means[1, 0] = 8
    conditional = expected_power(means, np.zeros_like(means), 32).mean(axis=0)
    pooled = expected_power(means.mean(axis=0), np.zeros(16), 32)
    assert conditional[0] == 8192 and pooled[0] == 4096


def test_finite_entropy_differs_from_entropy_of_expected_power() -> None:
    trajectories = np.array([[1., 0.], [1., 1.]])
    powers = abs(np.fft.fft(trajectories, axis=-1)) ** 2
    p, _ = normalize_power(powers)
    individual = -(p*np.log2(np.where(p > 0, p, 1))).sum(axis=-1).mean()
    expected_p, _ = normalize_power(powers.mean(axis=0))
    expected_entropy = -(expected_p*np.log2(expected_p)).sum()
    assert individual == 0.5
    assert abs(expected_entropy-individual) > 0.1


def test_q_power_pooling_precedes_normalization_and_preserves_fundamental() -> None:
    words = np.ones((1, 2, 4, 16, 16), dtype=np.uint8)
    words[:, :, 1] = 0
    words[:, :, 1, :, 0] = 32
    words[:, :, 2] = 2
    words[:, :, 3] = 3
    result, _, q = measured(words, 128)
    trajectories = words.reshape(1, 2, 4, 16, 4, 4).sum(axis=-1).reshape(1, 2, 4, 64)
    power = abs(np.fft.fft(trajectories, axis=-1)) ** 2
    p, _ = normalize_power(power.mean(axis=-2))
    expected_hmp = -(p*np.log2(np.where(p > 0, p, 1))).sum(axis=-1)
    np.testing.assert_allclose(result["hmp"], expected_hmp, rtol=0, atol=1e-14)
    np.testing.assert_allclose(result["F512"].mean(axis=-1), q[..., 16]+q[..., -16], rtol=0, atol=1e-14)


def test_sampling_preserves_marginal_support_and_conditional_base_profiles() -> None:
    training = np.zeros((2, 2, 64, 4, 16, 16), dtype=np.uint8)
    for key in range(2):
        for base in range(4):
            training[key, :, :, base] = key*10 + base
    training[:, 1, 56, :, :, 7] = 0
    keys = np.array([0, 1, 0], dtype=np.int16)
    fit = empirical_fit(training)
    assert np.all(fit["m0_counts"].sum(axis=-1) == 128)
    assert not fit["m1_variance"].any()
    for model in (0, 1):
        sample = sample_model(training, model, 1, keys, np.random.default_rng(9))
        assert not sample[:, 56, :, :, 7].any()
        assert set(np.unique(sample)) <= {0, 1, 2, 3, 10, 11, 12, 13}
        if model == 1:
            for row, key in enumerate(keys):
                for base in range(4):
                    assert np.all(sample[row, 0, base] == key*10+base)


def test_bootstrap_weights_equal_whole_key_resampling() -> None:
    draws = np.array([[0, 1, 1], [2, 2, 0]])
    values = np.array([[1., 4.], [3., 2.], [9., 7.]])
    np.testing.assert_allclose(bootstrap_weights(draws, 3) @ values, values[draws].mean(axis=1), rtol=0, atol=1e-15)
    assert not set(INDICES) & set(range(840, 920))
    assert not set(INDICES) & set(SMOKE_INDICES)
