#!/usr/bin/env python3
"""Independent audit of empirical ARX spectral predictions.

The audit does not import prediction-model, generation, or measurement
functions. Mathematical helpers use independent moment calculations,
frequency-line embedding, and mirrored real-FFT powers.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import itertools
import json
from pathlib import Path
import platform
import struct

import numpy as np

from audit_arx_feedforward import reference_initial, reference_working

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "doc_stream_ciphers/data/arx_spectral_prediction"
TRAIN = ROOT / "doc_stream_ciphers/data/arx_resolution_validation"
PROTOCOL = ROOT / "doc_stream_ciphers/ARX_SPECTRAL_PREDICTION_PROTOCOL.txt"
PROTOCOL_HASH = "358fad464030014909e176064436f2bd4c1a3c2d3af72fd5e4d86f827921b186"
FAMILIES = ("ChaCha20", "Salsa20")
WIDTHS = (32, 64, 128)
PER_MASK = ("hmp", "p0", "hnodc", "F512", "harmonic", "mean_hw_fraction")
SCALARS = tuple(f"{metric}_{kind}" for metric in PER_MASK for kind in ("observed", "reference", "delta")) + ("G",)
KINDS = ("p_observed", "p_reference", "q_observed", "q_reference")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def arrays(path: Path) -> dict[str, np.ndarray]:
    with np.load(path) as data:
        return {name: data[name] for name in data.files}


def maximum_error(actual, expected, *, atol: float = 2e-11, rtol: float = 0) -> float:
    actual, expected = np.asarray(actual), np.asarray(expected)
    np.testing.assert_allclose(actual, expected, atol=atol, rtol=rtol)
    return float(np.max(np.abs(actual - expected)))


def empirical_moments(training: np.ndarray) -> dict[str, np.ndarray]:
    """Input axes: key, family, mask, base, block, word (two rounds only)."""
    values = training.astype(np.float64)
    squared = values * values
    mean0 = values.mean(axis=(0, 3, 4))
    variance0 = squared.mean(axis=(0, 3, 4)) - mean0 * mean0
    mean1 = values.mean(axis=4)
    variance1 = squared.mean(axis=4) - mean1 * mean1
    return {"m0_mean": mean0, "m0_variance": variance0,
            "m1_mean": mean1, "m1_variance": variance1}


def expected_layer_power(means: np.ndarray, variances: np.ndarray,
                         segment_bits: int, blocks: int = 16) -> np.ndarray:
    """Embed the DFT of one mean block at harmonics; add flat noise power."""
    words_per_segment = segment_bits // 32
    locations = np.arange(0, 16, words_per_segment)
    profile = np.add.reduceat(means, locations, axis=-1)
    length = blocks * profile.shape[-1]
    background = blocks * variances.sum(axis=-1)
    power = np.broadcast_to(background[..., None], (*background.shape, length)).copy()
    power[..., ::blocks] += blocks ** 2 * np.abs(np.fft.fft(profile, axis=-1)) ** 2
    return power


def expected_model_power(moments: dict[str, np.ndarray], model: int,
                         segment_bits: int) -> np.ndarray:
    if model == 0:
        return expected_layer_power(moments["m0_mean"], moments["m0_variance"], segment_bits)
    conditional = expected_layer_power(moments["m1_mean"], moments["m1_variance"], segment_bits)
    # Average key and base layers *after* squaring their separate mean DFTs.
    return conditional.mean(axis=(0, 3))


def spectral_measurement(words: np.ndarray, segment_bits: int) -> dict[str, np.ndarray]:
    """Per-key/per-mask metrics and normalized full/AC spectra, Q=4 first."""
    values = words.astype(np.float64).reshape(*words.shape[:-2], -1)
    step = segment_bits // 32
    trajectory = np.add.reduceat(values, np.arange(0, values.shape[-1], step), axis=-1)
    length = trajectory.shape[-1]
    half_power = np.mean(np.abs(np.fft.rfft(trajectory, axis=-1)) ** 2, axis=-2)
    weights = np.full(half_power.shape[-1], 2.0)
    weights[[0, -1]] = 1.0
    denominator = np.sum(half_power * weights, axis=-1, keepdims=True)
    half_probability = half_power / denominator
    full = np.concatenate((half_probability, half_probability[..., -2:0:-1]), axis=-1)
    ac_denominator = np.sum(half_power[..., 1:] * weights[1:], axis=-1, keepdims=True)
    assert np.all(ac_denominator > 0)
    half_ac = half_power[..., 1:] / ac_denominator
    ac = np.concatenate((half_ac, half_ac[..., -2::-1]), axis=-1)
    hmp = -np.sum(full * np.log2(np.where(full > 0, full, 1)), axis=-1)
    hnodc = -np.sum(ac * np.log2(np.where(ac > 0, ac, 1)), axis=-1) / np.log2(length - 1)
    return {"hmp": hmp, "p0": full[..., 0], "hnodc": hnodc,
            "F512": ac[..., 15] + ac[..., length - 17],
            "harmonic": np.sum(ac[..., 15::16], axis=-1),
            "mean_hw_fraction": trajectory.mean(axis=(-2, -1)) / segment_bits,
            "full_spectrum": full, "ac_spectrum": ac}


def scalar_measurement(actual: dict, reference: dict) -> np.ndarray:
    result = []
    for name in PER_MASK:
        a, r = actual[name], reference[name]
        result.extend((a.mean(axis=1), r.mean(axis=1), (a - r).mean(axis=1)))
    difference = actual["hmp"] - reference["hmp"]
    result.append((difference[:, 32:] - difference[:, :32]).mean(axis=1))
    return np.column_stack(result)


def key_profiles(measurement: dict) -> tuple[np.ndarray, np.ndarray]:
    p = measurement["full_spectrum"].mean(axis=1)
    q = measurement["ac_spectrum"].mean(axis=1)
    q = np.concatenate((np.zeros_like(q[:, :1]), q), axis=1)
    return p, q


def mathematical_fixtures() -> dict:
    # Exact expected periodogram of two blocks, with four independent binary
    # residuals: enumeration avoids a simulation-based expectation check.
    mean = np.ones(16)
    variance = np.zeros(16)
    variance[:2] = 1
    possible = []
    for bits in itertools.product((-1, 1), repeat=4):
        sample = np.ones((2, 16))
        sample[:, :2] += np.asarray(bits).reshape(2, 2)
        possible.append(np.abs(np.fft.fft(sample.ravel())) ** 2)
    maximum_error(expected_layer_power(mean, variance, 32, blocks=2), np.mean(possible, axis=0))
    return {"exact_residual_configurations_enumerated": len(possible)}


def audit_provenance(directory: Path) -> tuple[dict, dict]:
    prediction = json.loads((directory / "prediction_manifest.json").read_text())
    generation = json.loads((directory / "evaluation_generation_manifest.json").read_text())
    analysis = json.loads((directory / "analysis_manifest.json").read_text())
    assert sha(PROTOCOL) == PROTOCOL_HASH == prediction["protocol_sha256"] == analysis["protocol_sha256"]
    assert prediction["status"] == "frozen_predictions_before_evaluation"
    assert generation["status"] == "complete"
    assert generation["prediction_manifest_sha256"] == sha(directory / "prediction_manifest.json")
    assert prediction["fingerprint"] == generation["fingerprint"] == analysis["fingerprint"]
    specification_names = ("protocol_sha256", "source_sha256", "training_raw_sha256", "training_generation_manifest_sha256",
                           "training_key_indices", "training_rounds", "evaluation_key_indices", "models", "families",
                           "segment_bits", "mc_replicates", "mc_batch_size", "seed", "mc_seed", "m1_key_seed",
                           "reference_seed", "bootstrap_seed", "bootstrap_replicates", "smoke", "python", "numpy")
    specification = {key: prediction[key] for key in specification_names}
    assert hashlib.sha256(json.dumps(specification, sort_keys=True).encode()).hexdigest() == prediction["fingerprint"]
    assert prediction["models"] == ["M0", "M1"] and prediction["families"] == list(FAMILIES)
    assert prediction["segment_bits"] == list(WIDTHS) and prediction["training_rounds"] == 2
    assert prediction["mc_batch_size"] == 32
    for name, expected in (("seed", 20261031), ("mc_seed", 2026103101), ("m1_key_seed", 2026103102),
                           ("reference_seed", 2026103103), ("bootstrap_seed", 2026103104), ("bootstrap_replicates", 5000)):
        assert prediction[name] == expected
    assert prediction["mc_replicates"] == (32 if prediction["smoke"] else 4096)
    train_indices = list(range(840, 920))
    test_indices = [1280, 1281] if prediction["smoke"] else list(range(1200, 1280))
    assert prediction["training_key_indices"] == analysis["training_key_indices"] == train_indices
    assert prediction["evaluation_key_indices"] == generation["evaluation_key_indices"] == analysis["evaluation_key_indices"] == test_indices
    assert not set(train_indices).intersection(test_indices)
    checked_hashes = 0
    for name, digest in prediction["source_sha256"].items():
        assert sha(ROOT / name) == digest, name
        checked_hashes += 1
    for collection in (prediction["output_sha256"], analysis["input_sha256"], analysis["output_sha256"]):
        for name, digest in collection.items():
            assert sha(directory / name) == digest, name
            checked_hashes += 1
    training_manifest = json.loads((TRAIN / "generation_manifest.json").read_text())
    assert sha(TRAIN / "generation_manifest.json") == prediction["training_generation_manifest_sha256"]
    assert sha(TRAIN / "arx_resolution_validation_raw.npz") == prediction["training_raw_sha256"] == training_manifest["raw_sha256"]
    assert sha(directory / "evaluation_raw.npz") == generation["raw_sha256"]
    for index in test_indices:
        path = directory / "checkpoints" / f"key_{index}.npz"
        metadata = json.loads(path.with_suffix(".json").read_text())
        assert metadata["key_index"] == index and metadata["fingerprint"] == prediction["fingerprint"]
        assert metadata["prediction_manifest_sha256"] == generation["prediction_manifest_sha256"]
        assert sha(path) == metadata["raw_sha256"] == generation["checkpoint_sha256"][path.name]
    return prediction, {"checked_source_and_artifact_hashes": checked_hashes,
                        "training_raw_sha256": prediction["training_raw_sha256"],
                        "evaluation_raw_sha256": generation["raw_sha256"],
                        "prediction_manifest_sha256": sha(directory / "prediction_manifest.json"),
                        "evaluation_manifest_sha256": sha(directory / "evaluation_generation_manifest.json"),
                        "analysis_manifest_sha256": sha(directory / "analysis_manifest.json"),
                        "training_evaluation_key_overlap": 0, "checkpoint_fingerprints_verified": len(test_indices)}


def audit_fit(directory: Path, training: np.ndarray) -> dict:
    saved = arrays(directory / "training_fit.npz")
    np.testing.assert_array_equal(saved["training_hw32"], training)
    np.testing.assert_array_equal(saved["training_key_indices"], np.arange(840, 920))
    moments = empirical_moments(training)
    errors = {name: maximum_error(saved[name], value, atol=2e-10) for name, value in moments.items()}
    counts = np.empty((2, 64, 16, 33), dtype=np.int32)
    for value in range(33):
        counts[..., value] = np.count_nonzero(training == value, axis=(0, 3, 4))
    np.testing.assert_array_equal(counts, saved["m0_counts"])
    assert np.all(counts.sum(axis=-1) == 5120)
    expected = arrays(directory / "expected_power.npz")
    analytic_rows = {(row["model"], row["family"], int(row["segment_bits"]), int(row["frequency_bin"])): row
                     for row in rows(directory / "analytic_spectrum.csv")}
    power_error = normalized_error = 0.0
    for width in WIDTHS:
        for mi in (0, 1):
            power = expected_model_power(moments, mi, width)
            power_error = max(power_error, maximum_error(expected[f"s{width}"][mi], power, atol=1e-6, rtol=1e-13))
            p = power / power.sum(axis=-1, keepdims=True)
            q = np.zeros_like(power)
            q[..., 1:] = power[..., 1:] / power[..., 1:].sum(axis=-1, keepdims=True)
            for fi, family in enumerate(FAMILIES):
                for k in range(power.shape[-1]):
                    row = analytic_rows[f"M{mi}", family, width, k]
                    power_error = max(power_error, maximum_error(float(row["expected_power_mean_over_masks"]), power[fi, :, k].mean(), atol=1e-6))
                    for name, target in (("normalized_expected_power", p), ("normalized_expected_ac_power", q)):
                        normalized_error = max(normalized_error, maximum_error(float(row[name]), target[fi, :, k].mean()))
    return {"moment_max_absolute_errors": errors, "m0_histogram_cells_checked": int(counts.size),
            "expected_power_max_absolute_error": power_error,
            "normalized_expected_power_max_absolute_error": normalized_error,
            "expected_power_method": "DFT of one mean block embedded at k=16*l, plus flat variance power; conditional M1 powers averaged before normalization."}


def sample_reference(training: np.ndarray, model: int, family: int,
                     chosen: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    shape = (len(chosen), 64, 4, 16, 16)
    mask = np.arange(64)[None, :, None, None, None]
    word = np.arange(16)[None, None, None, None, :]
    draw = rng.integers(0, 5120 if model == 0 else 16, size=shape, dtype=np.int16)
    if model == 0:
        # Decode a flat marginal index back into its source coordinates,
        # independently of the generator's transposed marginal-pool array.
        key = draw // 64
        base = (draw // 16) % 4
        block = draw % 16
    else:
        key = chosen[:, None, None, None, None]
        base = np.arange(4)[None, None, :, None, None]
        block = draw
    return training[key, family, mask, base, block, word]


def audit_monte_carlo_cell(training: np.ndarray, model: int, family: int, count: int,
                           saved_values: np.ndarray, saved_spectra: dict, chosen: np.ndarray) -> dict:
    sampling = np.random.default_rng(np.random.SeedSequence([2026103101, model, family]))
    reference_rng = np.random.default_rng(np.random.SeedSequence([2026103103, family]))
    recalculated = np.empty((count, 3, len(SCALARS)))
    spectra = {f"{kind}_s{width}": np.empty((count, 8192 // width)) for width in WIDTHS for kind in KINDS}
    for start in range(0, count, 32):
        stop = min(start + 32, count)
        actual = sample_reference(training, model, family, chosen[start:stop], sampling)
        reference = reference_rng.binomial(32, 0.5, size=actual.shape).astype(np.uint8)
        for wi, width in enumerate(WIDTHS):
            a = spectral_measurement(actual, width)
            r = spectral_measurement(reference, width)
            recalculated[start:stop, wi] = scalar_measurement(a, r)
            pa, qa = key_profiles(a)
            pr, qr = key_profiles(r)
            for kind, value in zip(KINDS, (pa, pr, qa, qr)):
                spectra[f"{kind}_s{width}"][start:stop] = value
        if stop % 1024 == 0 or stop == count:
            print(f"MC audit M{model}/{FAMILIES[family]}: {stop}/{count}", flush=True)
    scalar_error = maximum_error(recalculated, saved_values[model, :, family])
    spectrum_error = mcse_error = 0.0
    for name, value in spectra.items():
        spectrum_error = max(spectrum_error, maximum_error(value.mean(axis=0), saved_spectra[name + "_mean"][model, family]))
        # Two-pass standard deviation avoids subtraction of accumulated moments.
        mcse = value.std(axis=0, ddof=1) / np.sqrt(count)
        mcse_error = max(mcse_error, maximum_error(mcse, saved_spectra[name + "_mcse"][model, family], atol=2e-10))
    return {"model": f"M{model}", "family": FAMILIES[family], "pseudo_keys": count,
            "scalar_max_absolute_error": scalar_error, "spectrum_mean_max_absolute_error": spectrum_error,
            "spectrum_mcse_max_absolute_error": mcse_error,
            "sampling": "int16 PCG64 draws in batches of 32, independent coordinate decoding; one shared M1 key-index array."}


def independent_emitted_words(key: bytes, nonce: bytes, family: str) -> np.ndarray:
    result = []
    for counter in range(16):
        initial = reference_initial(key, nonce, family, counter)
        working = reference_working(initial, family, 2)
        result.append([(a + b) & 0xFFFFFFFF for a, b in zip(initial, working)])
    return np.asarray(result, dtype=np.uint32)


def numeric_evaluation_audit(actual: np.ndarray, reference: np.ndarray, indices: np.ndarray) -> dict:
    pair_checks = streams = 0
    selected = sorted(set((0, len(indices) - 1)))
    for pos in selected:
        master = hashlib.blake2b(f"stream-publication-v1:20261031:{int(indices[pos])}".encode(), digest_size=32).digest()
        material = hashlib.shake_256(b"spectral-prediction-nonces-v1:" + master).digest(32)
        bases = [material[i:i + 8] for i in range(0, 32, 8)]

        def flip(base: bytes, bit: int) -> bytes:
            return (int.from_bytes(base, "big") ^ (1 << (63 - bit))).to_bytes(8, "big")

        vertices = set(bases)
        vertices.update(flip(base, bit) for base in bases for bit in range(64))
        assert len(vertices) == 260
        for fi, family in enumerate(FAMILIES):
            label = family.encode() + b":" + master
            key = hashlib.blake2b(b"spectral-prediction-key-v1:" + label, digest_size=32).digest()
            secret = hashlib.blake2b(b"spectral-prediction-secret-v1:" + label, digest_size=32).digest()
            cipher_words = {v: independent_emitted_words(key, v, family) for v in vertices}
            domain = b"spectral-prediction-oracle-v1:" + family.encode() + b":" + secret + b"\0\2"
            oracle_words = {v: np.asarray(struct.unpack("<256I", hashlib.shake_256(domain + v).digest(1024)), dtype=np.uint32).reshape(16, 16)
                            for v in vertices}
            streams += len(vertices)
            for bi, base in enumerate(bases):
                for mask in range(64):
                    other = flip(base, mask)
                    for collection, stored in ((cipher_words, actual), (oracle_words, reference)):
                        difference = collection[base] ^ collection[other]
                        octets = np.ascontiguousarray(difference, dtype="<u4").view(np.uint8).reshape(16, 16, 4)
                        hw = np.unpackbits(octets, axis=-1).sum(axis=-1, dtype=np.uint8)
                        np.testing.assert_array_equal(hw, stored[pos, fi, mask, bi])
                        pair_checks += 1
    return {"regenerated_key_indices": [int(indices[pos]) for pos in selected],
            "cipher_streams": streams, "cipher_blocks": streams * 16,
            "reference_streams": streams, "cipher_reference_pair_trajectories": pair_checks}


def audit_evaluation(directory: Path, actual: np.ndarray, reference: np.ndarray,
                     indices: np.ndarray, mc: np.ndarray, mc_spectra: dict) -> dict:
    n = len(indices)
    saved = arrays(directory / "evaluation_metrics.npz")
    saved_profiles = arrays(directory / "evaluation_spectra.npz")
    np.testing.assert_array_equal(saved["key_indices"], indices)
    assert saved["scalar_names"].tolist() == list(SCALARS)
    values = np.empty((n, 2, 3, len(SCALARS)))
    profiles = {f"{kind}_s{width}": np.empty((n, 2, 8192 // width)) for kind in KINDS for width in WIDTHS}
    scalar_error = spectrum_error = 0.0
    for fi in range(2):
        for wi, width in enumerate(WIDTHS):
            a, r = (spectral_measurement(words[:, fi], width) for words in (actual, reference))
            values[:, fi, wi] = scalar_measurement(a, r)
            pa, qa = key_profiles(a)
            pr, qr = key_profiles(r)
            for kind, value in zip(KINDS, (pa, pr, qa, qr)):
                profiles[f"{kind}_s{width}"][:, fi] = value
    scalar_error = maximum_error(values, saved["values"])
    for name, value in profiles.items():
        spectrum_error = max(spectrum_error, maximum_error(value, saved_profiles[name]))

    draws = np.random.default_rng(2026103104).integers(0, n, (5000, n), dtype=np.int16)
    multiplicities = np.zeros((5000, n), dtype=np.int16)
    np.add.at(multiplicities, (np.repeat(np.arange(5000), n), draws.ravel()), 1)
    weights = multiplicities.astype(float) / n
    scalars = {(r["model"], r["family"], int(r["segment_bits"]), r["metric"]): r for r in rows(directory / "scalar_summary.csv")}
    compact = {(r["model"], r["family"], int(r["segment_bits"]), r["metric"]): r for r in rows(directory / "compact_summary.csv")}
    spectral = {(r["model"], r["family"], int(r["segment_bits"]), int(r["frequency_bin"])): r for r in rows(directory / "spectral_summary.csv")}
    distances = {(r["model"], r["family"], int(r["segment_bits"])): r for r in rows(directory / "spectral_errors.csv")}
    per_key = {(int(r["key_index"]), r["family"], int(r["segment_bits"])): r for r in rows(directory / "evaluation_per_key.csv")}
    assert len(scalars) == 2 * 2 * 3 * 19 and len(compact) == 24 and len(distances) == 12
    assert len(spectral) == 4 * sum(8192 // width for width in WIDTHS) and len(per_key) == n * 6
    summary_error = ci_error = mcse_error = l1_error = 0.0
    compact_findings = []
    for fi, family in enumerate(FAMILIES):
        for wi, width in enumerate(WIDTHS):
            local = values[:, fi, wi]
            average = local.mean(axis=0)
            limits = np.quantile(weights @ local, (0.025, 0.975), axis=0)
            for ki, key in enumerate(indices):
                row = per_key[int(key), family, width]
                scalar_error = max(scalar_error, maximum_error([float(row[name]) for name in SCALARS], local[ki]))
            profile_intervals = {kind: np.quantile(weights @ profiles[f"{kind}_s{width}"][:, fi], (0.025, 0.975), axis=0) for kind in KINDS}
            for mi in range(2):
                prediction = mc[mi, :, fi, wi].mean(axis=0)
                prediction_se = mc[mi, :, fi, wi].std(axis=0, ddof=1) / np.sqrt(len(mc[mi]))
                for ci, name in enumerate(SCALARS):
                    row = scalars[f"M{mi}", family, width, name]
                    expected = {"prediction": prediction[ci], "prediction_mcse": prediction_se[ci],
                                "observed": average[ci], "observed_ci95_low": limits[0, ci], "observed_ci95_high": limits[1, ci],
                                "error": average[ci] - prediction[ci], "error_ci95_low": limits[0, ci] - prediction[ci],
                                "error_ci95_high": limits[1, ci] - prediction[ci]}
                    for column, value in expected.items():
                        discrepancy = maximum_error(float(row[column]), value)
                        if "ci95" in column:
                            ci_error = max(ci_error, discrepancy)
                        elif "mcse" in column:
                            mcse_error = max(mcse_error, discrepancy)
                        else:
                            summary_error = max(summary_error, discrepancy)
                    if name in ("G", "F512_delta"):
                        record = compact[f"M{mi}", family, width, "F512" if name == "F512_delta" else name]
                        for column, value in expected.items():
                            summary_error = max(summary_error, maximum_error(float(record[column]), value))
                        compact_findings.append({"model": f"M{mi}", "family": family, "segment_bits": width,
                                                 "metric": name, "observed": float(average[ci]),
                                                 "prediction": float(prediction[ci]), "error": float(average[ci] - prediction[ci])})
                for frequency in range(8192 // width):
                    row = spectral[f"M{mi}", family, width, frequency]
                    for kind in KINDS:
                        for suffix, expected in (("prediction", mc_spectra[f"{kind}_s{width}_mean"][mi, fi, frequency]),
                                                 ("prediction_mcse", mc_spectra[f"{kind}_s{width}_mcse"][mi, fi, frequency]),
                                                 ("evaluation", profiles[f"{kind}_s{width}"][:, fi, frequency].mean()),
                                                 ("ci95_low", profile_intervals[kind][0, frequency]),
                                                 ("ci95_high", profile_intervals[kind][1, frequency])):
                            ci_error = max(ci_error, maximum_error(float(row[f"{kind}_{suffix}"]), expected))
                q_actual = profiles[f"q_observed_s{width}"][:, fi]
                q_prediction = mc_spectra[f"q_observed_s{width}_mean"][mi, fi]
                l1 = np.abs(q_actual.mean(axis=0) - q_prediction).sum()
                l1_limits = np.quantile(np.abs(weights @ q_actual - q_prediction).sum(axis=1), (0.025, 0.975))
                row = distances[f"M{mi}", family, width]
                for column, value in (("ac_profile_l1_error", l1), ("ci95_low", l1_limits[0]), ("ci95_high", l1_limits[1])):
                    l1_error = max(l1_error, maximum_error(float(row[column]), value))
    return {"six_evaluation_cells_and_two_models_checked": True,
            "per_key_scalar_max_absolute_error": scalar_error, "per_key_spectrum_max_absolute_error": spectrum_error,
            "summary_max_absolute_error": summary_error, "ci_max_absolute_error": ci_error,
            "scalar_mcse_max_absolute_error": mcse_error, "spectral_l1_max_absolute_error": l1_error,
            "conditional_interval_scope": "5000 whole-evaluation-key draws, fixed training fit and fixed MC estimate; training/MC uncertainty is not included in these intervals. MCSE is checked separately.",
            "hypothesis_tests": "None; L1 distances and their intervals are descriptive.",
            "compact_findings": compact_findings}


def audit(directory: Path, workers: int = 2) -> dict:
    prediction, provenance = audit_provenance(directory)
    with np.load(TRAIN / "arx_resolution_validation_raw.npz") as data:
        np.testing.assert_array_equal(data["key_indices"], np.arange(840, 920))
        training = data["observed"][:, :, 0]
    assert training.shape == (80, 2, 64, 4, 16, 16)
    raw = arrays(directory / "evaluation_raw.npz")
    actual, reference, indices = raw["observed"], raw["oracle"], raw["key_indices"]
    np.testing.assert_array_equal(indices, prediction["evaluation_key_indices"])
    assert actual.shape == reference.shape == (len(indices), 2, 64, 4, 16, 16)
    assert actual.dtype == reference.dtype == np.uint8 and max(actual.max(), reference.max()) <= 32
    count = prediction["mc_replicates"]
    mc = arrays(directory / "monte_carlo_metrics.npz")
    assert mc["values"].shape == (2, count, 2, 3, len(SCALARS))
    assert mc["scalar_names"].tolist() == list(SCALARS)
    chosen = np.random.default_rng(2026103102).integers(0, 80, size=count, dtype=np.int16)
    np.testing.assert_array_equal(chosen, mc["m1_training_key_positions"])
    mc_spectra = arrays(directory / "monte_carlo_spectra.npz")
    result = {"status": "passed", "auditor_source_sha256": sha(Path(__file__)),
              "independent_core_source_sha256": sha(Path(__file__).with_name("audit_arx_feedforward.py")),
              "provenance": provenance, "fixtures": mathematical_fixtures(),
              "fit_and_expected_power": audit_fit(directory, training),
              "mode": "read_only unless --write requests this new audit report",
              "audit_runtime": {"python": platform.python_version(), "numpy": np.__version__}}
    print("Prediction provenance, fit, and analytic spectrum audit passed", flush=True)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        jobs = [pool.submit(audit_monte_carlo_cell, training, mi, fi, count, mc["values"], mc_spectra, chosen)
                for mi in range(2) for fi in range(2)]
        result["evaluation_regeneration"] = numeric_evaluation_audit(actual, reference, indices)
        print("Independent first/last evaluation-key core audit passed", flush=True)
        result["evaluation_statistics"] = audit_evaluation(directory, actual, reference, indices, mc["values"], mc_spectra)
        print("Evaluation metrics, conditional CI, and spectral L1 audit passed", flush=True)
        result["monte_carlo_regeneration"] = [job.result() for job in jobs]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--write", action="store_true", help="Write independent_audit.json in this new experiment directory")
    args = parser.parse_args()
    if args.workers not in range(1, 5):
        parser.error("--workers must be 1--4")
    report = audit(args.directory, args.workers)
    if args.write:
        (args.directory / "independent_audit.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
