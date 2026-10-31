#!/usr/bin/env python3
"""Frozen M0/M1 empirical spectrum predictions and independent ARX evaluation."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from arx_resolution_validation import aggregate_words
from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream
from publication_study import _key_material

PROTOCOL = ROOT / "doc_stream_ciphers/ARX_SPECTRAL_PREDICTION_PROTOCOL.txt"
PROTOCOL_SHA256 = "358fad464030014909e176064436f2bd4c1a3c2d3af72fd5e4d86f827921b186"
TRAIN = ROOT / "doc_stream_ciphers/data/arx_resolution_validation"
OUT = ROOT / "doc_stream_ciphers/data/arx_spectral_prediction"
FAMILIES = ("ChaCha20", "Salsa20")
MODELS = ("M0", "M1")
WIDTHS = (32, 64, 128)
INDICES = tuple(range(1200, 1280))
SMOKE_INDICES = (1280, 1281)
SEED = 20261031
MC_SEED, KEY_SEED, REFERENCE_SEED, BOOT_SEED = 2026103101, 2026103102, 2026103103, 2026103104
MC_REPLICATES, SMOKE_REPLICATES, BATCH_SIZE, BOOTSTRAPS = 4096, 32, 32, 5000
PER_MASK = ("hmp", "p0", "hnodc", "F512", "harmonic", "mean_hw_fraction")
SCALARS = tuple(f"{name}_{kind}" for name in PER_MASK for kind in ("observed", "reference", "delta")) + ("G",)
POPCOUNT = np.array([x.bit_count() for x in range(256)], dtype=np.uint8)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def save_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def save_npz(path: Path, **arrays: np.ndarray) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        np.savez_compressed(stream, **arrays)
    temporary.replace(path)


def save_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def specification(smoke: bool) -> dict:
    if sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise AssertionError("The fixed prediction protocol changed")
    names = ("arx_spectral_prediction.py", "arx_resolution_validation.py", "analyze_arx_resolution.py",
             "extension_stream_cores.py", "publication_study.py")
    paths = [Path(__file__).with_name(name) for name in names]
    paths.append(ROOT / "src/spectral_crypto_analyzer/primitives.py")
    training_manifest = json.loads((TRAIN / "generation_manifest.json").read_text())
    raw_hash = sha256(TRAIN / "arx_resolution_validation_raw.npz")
    if raw_hash != training_manifest["raw_sha256"]:
        raise AssertionError("Training raw hash differs from its archived manifest")
    return {"protocol_sha256": PROTOCOL_SHA256,
            "source_sha256": {str(path.relative_to(ROOT)): sha256(path) for path in paths},
            "training_raw_sha256": raw_hash, "training_generation_manifest_sha256": sha256(TRAIN / "generation_manifest.json"),
            "training_key_indices": list(range(840, 920)), "training_rounds": 2,
            "evaluation_key_indices": list(SMOKE_INDICES if smoke else INDICES),
            "models": MODELS, "families": FAMILIES, "segment_bits": WIDTHS,
            "mc_replicates": SMOKE_REPLICATES if smoke else MC_REPLICATES,
            "mc_batch_size": BATCH_SIZE, "seed": SEED, "mc_seed": MC_SEED,
            "m1_key_seed": KEY_SEED, "reference_seed": REFERENCE_SEED,
            "bootstrap_seed": BOOT_SEED, "bootstrap_replicates": BOOTSTRAPS,
            "smoke": smoke, "python": platform.python_version(), "numpy": np.__version__}


def fingerprint(spec: dict) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()


def empirical_fit(training: np.ndarray) -> dict[str, np.ndarray]:
    """Input: key,cipher,mask,base,block,word; all counts have equal key weight."""
    if training.ndim != 6 or training.shape[1:] != (2, 64, 4, 16, 16):
        raise ValueError("Expected key x 2 x 64 x 4 x 16 x 16 training HW32")
    counts = np.empty((2, 64, 16, 33), dtype=np.int32)
    for fi in range(2):
        for mask in range(64):
            for word in range(16):
                counts[fi, mask, word] = np.bincount(training[:, fi, mask, :, :, word].ravel(), minlength=33)
    return {"training_hw32": training, "m0_counts": counts,
            "m0_mean": training.mean(axis=(0, 3, 4)), "m0_variance": training.var(axis=(0, 3, 4)),
            "m1_mean": training.mean(axis=4), "m1_variance": training.var(axis=4)}


def expected_power(mean: np.ndarray, variance: np.ndarray, width: int) -> np.ndarray:
    """Conditional expected periodogram under independent word residuals."""
    group = width // 32
    positions = 512 // width
    mu = mean.reshape(*mean.shape[:-1], positions, group).sum(axis=-1)
    var = variance.reshape(*variance.shape[:-1], positions, group).sum(axis=-1)
    # Computing the full repeated-mean FFT makes the scaling by B explicit.
    repeated = np.tile(mu, 16)
    return np.abs(np.fft.fft(repeated, axis=-1)) ** 2 + 16 * var.sum(axis=-1, keepdims=True)


def normalize_power(power: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    total = power.sum(axis=-1, keepdims=True)
    p = np.divide(power, total, out=np.zeros_like(power), where=total > 0)
    ac_total = power[..., 1:].sum(axis=-1, keepdims=True)
    q = np.zeros_like(power)
    np.divide(power[..., 1:], ac_total, out=q[..., 1:], where=ac_total > 0)
    return p, q


def measured(words: np.ndarray, width: int) -> tuple[dict[str, np.ndarray], np.ndarray, np.ndarray]:
    trajectories = aggregate_words(words, width, 0, 16).astype(float)
    power = (np.abs(np.fft.fft(trajectories, axis=-1)) ** 2).mean(axis=-2)
    p, q = normalize_power(power)
    n = power.shape[-1]
    hmp = -(p * np.log2(np.where(p > 0, p, 1))).sum(axis=-1)
    hnodc = -(q * np.log2(np.where(q > 0, q, 1))).sum(axis=-1) / np.log2(n - 1)
    metrics = {"hmp": hmp, "p0": p[..., 0], "hnodc": hnodc,
               "F512": q[..., 16] + q[..., -16], "harmonic": q[..., 16::16].sum(axis=-1),
               "mean_hw_fraction": trajectories.mean(axis=(-2, -1)) / width}
    return metrics, p.mean(axis=-2), q.mean(axis=-2)


def scalar_values(actual: dict[str, np.ndarray], reference: dict[str, np.ndarray]) -> np.ndarray:
    entries = []
    for name in PER_MASK:
        a, r = actual[name], reference[name]
        entries.extend((a.mean(axis=-1), r.mean(axis=-1), (a-r).mean(axis=-1)))
    gap = actual["hmp"] - reference["hmp"]
    entries.append((gap[..., 32:] - gap[..., :32]).mean(axis=-1))
    return np.stack(entries, axis=-1)


def sample_model(training: np.ndarray, model: int, family: int, keys: np.ndarray,
                 rng: np.random.Generator) -> np.ndarray:
    shape = (len(keys), 64, 4, 16, 16)
    mask = np.arange(64)[None, :, None, None, None]
    word = np.arange(16)[None, None, None, None, :]
    if model == 0:
        pool = training[:, family].transpose(1, 4, 0, 2, 3).reshape(64, 16, -1)
        sample = rng.integers(0, pool.shape[-1], size=shape, dtype=np.int16)
        return pool[mask, word, sample]
    sample = rng.integers(0, 16, size=shape, dtype=np.int16)
    base = np.arange(4)[None, None, :, None, None]
    return training[keys[:, None, None, None, None], family, mask, base, sample, word]


def freeze_predictions(directory: Path, smoke: bool) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    spec = specification(smoke)
    token = fingerprint(spec)
    manifest_path = directory / "prediction_manifest.json"
    if manifest_path.exists():
        saved = json.loads(manifest_path.read_text())
        if saved["fingerprint"] != token:
            raise AssertionError("Existing predictions have a different fingerprint")
        for name, expected in saved["output_sha256"].items():
            if sha256(directory / name) != expected:
                raise AssertionError(f"Frozen prediction changed: {name}")
        return saved
    with np.load(TRAIN / "arx_resolution_validation_raw.npz") as raw:
        np.testing.assert_array_equal(raw["key_indices"], np.arange(840, 920))
        training = raw["observed"][:, :, 0]
    fit = empirical_fit(training)
    save_npz(directory / "training_fit.npz", **fit, training_key_indices=np.arange(840, 920))
    analytic = {}
    analytic_rows = []
    for wi, width in enumerate(WIDTHS):
        m0 = expected_power(fit["m0_mean"], fit["m0_variance"], width)
        # Average conditional powers, not the complex amplitudes or pooled means.
        m1 = expected_power(fit["m1_mean"], fit["m1_variance"], width).mean(axis=(0, 3))
        analytic[f"s{width}"] = np.stack((m0, m1))
        for mi, model in enumerate(MODELS):
            p, q = normalize_power(analytic[f"s{width}"][mi])
            for fi, family in enumerate(FAMILIES):
                for frequency in range(p.shape[-1]):
                    analytic_rows.append({"model": model, "family": family, "segment_bits": width,
                                          "frequency_bin": frequency,
                                          "expected_power_mean_over_masks": float(analytic[f"s{width}"][mi, fi, :, frequency].mean()),
                                          "normalized_expected_power": float(p[fi, :, frequency].mean()),
                                          "normalized_expected_ac_power": float(q[fi, :, frequency].mean())})
    save_npz(directory / "expected_power.npz", **analytic)
    save_csv(directory / "analytic_spectrum.csv", analytic_rows)
    count = spec["mc_replicates"]
    chosen_keys = np.random.default_rng(KEY_SEED).integers(0, 80, size=count, dtype=np.int16)
    values = np.empty((2, count, 2, 3, len(SCALARS)))
    profiles = {}
    for width in WIDTHS:
        n = 8192 // width
        for kind in ("p_observed", "p_reference", "q_observed", "q_reference"):
            profiles[f"{kind}_s{width}_sum"] = np.zeros((2, 2, n))
            profiles[f"{kind}_s{width}_sumsq"] = np.zeros((2, 2, n))
    started = perf_counter()
    for mi, model in enumerate(MODELS):
        for fi, family in enumerate(FAMILIES):
            rng = np.random.default_rng(np.random.SeedSequence([MC_SEED, mi, fi]))
            reference_rng = np.random.default_rng(np.random.SeedSequence([REFERENCE_SEED, fi]))
            for start in range(0, count, BATCH_SIZE):
                stop = min(start + BATCH_SIZE, count)
                words = sample_model(training, mi, fi, chosen_keys[start:stop], rng)
                reference = reference_rng.binomial(32, 0.5, size=words.shape).astype(np.uint8)
                for wi, width in enumerate(WIDTHS):
                    a, pa, qa = measured(words, width)
                    r, pr, qr = measured(reference, width)
                    values[mi, start:stop, fi, wi] = scalar_values(a, r)
                    for kind, x in (("p_observed", pa), ("p_reference", pr), ("q_observed", qa), ("q_reference", qr)):
                        profiles[f"{kind}_s{width}_sum"][mi, fi] += x.sum(axis=0)
                        profiles[f"{kind}_s{width}_sumsq"][mi, fi] += (x*x).sum(axis=0)
                if stop % 1024 == 0 or stop == count:
                    print(f"Prediction {model}/{family}: {stop}/{count} MC keys, {perf_counter()-started:.1f}s", flush=True)
    profile_output = {}
    for name in list(profiles):
        if name.endswith("_sumsq"):
            continue
        prefix = name[:-4]
        sums, squares = profiles[name], profiles[prefix + "_sumsq"]
        profile_output[prefix + "_mean"] = sums / count
        profile_output[prefix + "_mcse"] = np.sqrt(np.maximum(0, squares - sums*sums/count) / (count - 1) / count)
    save_npz(directory / "monte_carlo_metrics.npz", values=values, m1_training_key_positions=chosen_keys,
             scalar_names=np.asarray(SCALARS), models=np.asarray(MODELS), families=np.asarray(FAMILIES), widths=np.asarray(WIDTHS))
    save_npz(directory / "monte_carlo_spectra.npz", **profile_output)
    names = ("training_fit.npz", "expected_power.npz", "analytic_spectrum.csv", "monte_carlo_metrics.npz", "monte_carlo_spectra.npz")
    if fingerprint(specification(smoke)) != token:
        raise AssertionError("Sources changed while fitting predictions")
    manifest = {**spec, "fingerprint": token, "status": "frozen_predictions_before_evaluation",
                "metric_axes": ["model", "pseudo_key", "family", "segment_width", "scalar"],
                "scalar_names": SCALARS,
                "training_hw32_axes": ["training_key", "family", "mask", "base", "block", "word"],
                "sampling_dtype": "int16 for M0 marginal index, M1 block index and M1 key position",
                "m0_pool_order": "key,base,block within each family,mask,word marginal",
                "monte_carlo_seconds": perf_counter()-started,
                "output_sha256": {name: sha256(directory / name) for name in names}}
    save_json(manifest_path, manifest)
    return manifest


def flip_nonce(base: bytes, bit: int) -> bytes:
    result = bytearray(base)
    result[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(result)


def word_hw(left: bytes, right: bytes) -> np.ndarray:
    difference = np.frombuffer(left, dtype=np.uint8) ^ np.frombuffer(right, dtype=np.uint8)
    return POPCOUNT[difference].reshape(16, 16, 4).sum(axis=-1, dtype=np.uint8)


def evaluation_key(index: int) -> tuple[np.ndarray, np.ndarray]:
    if index not in INDICES + SMOKE_INDICES:
        raise ValueError("Evaluation index is outside the fixed cohorts")
    master, _ = _key_material(SEED, index)
    material = hashlib.shake_256(b"spectral-prediction-nonces-v1:" + master).digest(32)
    bases = tuple(material[8*i:8*(i+1)] for i in range(4))
    vertices = set(bases)
    vertices.update(flip_nonce(base, bit) for base in bases for bit in range(64))
    if len(vertices) != 260:
        raise AssertionError("The evaluation nonce stars are not disjoint")
    observed = np.empty((2, 64, 4, 16, 16), dtype=np.uint8)
    oracle = np.empty_like(observed)
    for fi, family in enumerate(FAMILIES):
        label = family.encode() + b":"
        key = hashlib.blake2b(b"spectral-prediction-key-v1:" + label + master, digest_size=32).digest()
        secret = hashlib.blake2b(b"spectral-prediction-secret-v1:" + label + master, digest_size=32).digest()
        domain = b"spectral-prediction-oracle-v1:" + label
        cipher = chacha20_iv_stream if fi == 0 else salsa20_iv_stream
        actual = {v: cipher(key, bytes(4)+v if fi == 0 else v, 2, 1024) for v in vertices}
        reference = {v: hashlib.shake_256(domain + secret + (2).to_bytes(2, "big") + v).digest(1024) for v in vertices}
        for bi, base in enumerate(bases):
            for mask in range(64):
                other = flip_nonce(base, mask)
                observed[fi, mask, bi] = word_hw(actual[base], actual[other])
                oracle[fi, mask, bi] = word_hw(reference[base], reference[other])
    return observed, oracle


def generate_evaluation(directory: Path, smoke: bool) -> dict:
    predictions_path = directory / "prediction_manifest.json"
    if not predictions_path.is_file():
        raise AssertionError("Evaluation requires predictions frozen before generation")
    predictions = freeze_predictions(directory, smoke)  # Only verifies existing files here.
    token = predictions["fingerprint"]
    prediction_hash = sha256(predictions_path)
    path = directory / "evaluation_generation_manifest.json"
    if path.exists():
        old = json.loads(path.read_text())
        if old["fingerprint"] != token or old["prediction_manifest_sha256"] != prediction_hash:
            raise AssertionError("Evaluation cannot mix prediction/source versions")
    indices = SMOKE_INDICES if smoke else INDICES
    checkpoint = directory / "checkpoints"
    checkpoint.mkdir(exist_ok=True)
    manifest = {"status": "generating", "fingerprint": token, "prediction_manifest_sha256": prediction_hash,
                "evaluation_key_indices": list(indices), "raw_axes": ["key", "family", "mask", "base", "block", "word"],
                "rounds": 2, "smoke": smoke}
    save_json(path, manifest)
    actual, controls, hashes = [], [], {}
    started = perf_counter()
    for completed, index in enumerate(indices, 1):
        raw_path = checkpoint / f"key_{index}.npz"
        metadata = checkpoint / f"key_{index}.json"
        if metadata.exists():
            saved = json.loads(metadata.read_text())
            if (saved["fingerprint"] != token or saved["key_index"] != index
                    or saved["prediction_manifest_sha256"] != prediction_hash or sha256(raw_path) != saved["raw_sha256"]):
                raise AssertionError("Invalid evaluation checkpoint")
            with np.load(raw_path) as raw:
                a, r = raw["observed"], raw["oracle"]
        else:
            a, r = evaluation_key(index)
            save_npz(raw_path, observed=a, oracle=r)
            save_json(metadata, {"fingerprint": token, "key_index": index,
                                 "prediction_manifest_sha256": prediction_hash, "raw_sha256": sha256(raw_path)})
        if a.shape != (2, 64, 4, 16, 16) or r.shape != a.shape or a.max() > 32 or r.max() > 32:
            raise AssertionError("Invalid evaluation HW32 axes or range")
        actual.append(a)
        controls.append(r)
        hashes[raw_path.name] = sha256(raw_path)
        if completed % 10 == 0 or completed == len(indices):
            print(f"Evaluation generation {completed}/{len(indices)} keys, {perf_counter()-started:.1f}s", flush=True)
    if fingerprint(specification(smoke)) != token:
        raise AssertionError("Source/training inputs changed during evaluation")
    output = directory / "evaluation_raw.npz"
    save_npz(output, observed=np.stack(actual), oracle=np.stack(controls), key_indices=np.asarray(indices, dtype=np.int32))
    manifest.update(status="complete", raw_sha256=sha256(output), checkpoint_sha256=hashes,
                    elapsed_seconds=perf_counter()-started)
    save_json(path, manifest)
    return manifest


def bootstrap_weights(indices: np.ndarray, n: int) -> np.ndarray:
    weights = np.zeros((len(indices), n))
    for row, sampled in enumerate(indices):
        weights[row] = np.bincount(sampled, minlength=n) / n
    return weights


def analyze(directory: Path, smoke: bool) -> dict:
    predictions = freeze_predictions(directory, smoke)
    generation_path = directory / "evaluation_generation_manifest.json"
    generation = json.loads(generation_path.read_text())
    if (generation["status"] != "complete" or generation["fingerprint"] != predictions["fingerprint"]
            or generation["prediction_manifest_sha256"] != sha256(directory / "prediction_manifest.json")
            or generation["raw_sha256"] != sha256(directory / "evaluation_raw.npz")):
        raise AssertionError("Evaluation/prediction provenance mismatch")
    with np.load(directory / "evaluation_raw.npz") as raw:
        actual, reference, keys = raw["observed"], raw["oracle"], raw["key_indices"]
    np.testing.assert_array_equal(keys, SMOKE_INDICES if smoke else INDICES)
    with np.load(directory / "monte_carlo_metrics.npz") as raw:
        mc = raw["values"]
    with np.load(directory / "monte_carlo_spectra.npz") as raw:
        mc_spectra = {name: raw[name] for name in raw.files}
    n = len(keys)
    scalars = np.empty((n, 2, 3, len(SCALARS)))
    profiles = {}
    for wi, width in enumerate(WIDTHS):
        t = 8192 // width
        for kind in ("p_observed", "p_reference", "q_observed", "q_reference"):
            profiles[f"{kind}_s{width}"] = np.empty((n, 2, t))
        for fi in range(2):
            a, pa, qa = measured(actual[:, fi], width)
            r, pr, qr = measured(reference[:, fi], width)
            scalars[:, fi, wi] = scalar_values(a, r)
            for kind, x in (("p_observed", pa), ("p_reference", pr), ("q_observed", qa), ("q_reference", qr)):
                profiles[f"{kind}_s{width}"][:, fi] = x
    save_npz(directory / "evaluation_metrics.npz", values=scalars, key_indices=keys, scalar_names=np.asarray(SCALARS))
    save_npz(directory / "evaluation_spectra.npz", **profiles)
    draws = np.random.default_rng(BOOT_SEED).integers(0, n, (BOOTSTRAPS, n), dtype=np.int16)
    weights = bootstrap_weights(draws, n)
    rows, compact, spectral_rows, distance_rows, per_key = [], [], [], [], []
    for fi, family in enumerate(FAMILIES):
        for wi, width in enumerate(WIDTHS):
            value = scalars[:, fi, wi]
            observed = value.mean(axis=0)
            low, high = np.quantile(value[draws].mean(axis=1), (0.025, 0.975), axis=0)
            for ki, key in enumerate(keys):
                per_key.append({"key_index": int(key), "family": family, "segment_bits": width,
                                **{name: float(value[ki, ci]) for ci, name in enumerate(SCALARS)}})
            for mi, model in enumerate(MODELS):
                predicted = mc[mi, :, fi, wi].mean(axis=0)
                mcse = mc[mi, :, fi, wi].std(axis=0, ddof=1) / np.sqrt(len(mc[mi]))
                for ci, name in enumerate(SCALARS):
                    row = {"model": model, "family": family, "segment_bits": width, "metric": name,
                           "prediction": float(predicted[ci]), "prediction_mcse": float(mcse[ci]),
                           "observed": float(observed[ci]), "observed_ci95_low": float(low[ci]),
                           "observed_ci95_high": float(high[ci]), "error": float(observed[ci]-predicted[ci]),
                           "error_ci95_low": float(low[ci]-predicted[ci]), "error_ci95_high": float(high[ci]-predicted[ci])}
                    rows.append(row)
                    if name in ("G", "F512_delta"):
                        compact.append({**row, "metric": "F512" if name == "F512_delta" else name})
                q_pred = mc_spectra[f"q_observed_s{width}_mean"][mi, fi]
                q_actual = profiles[f"q_observed_s{width}"][:, fi]
                distances = np.abs(weights @ q_actual - q_pred).sum(axis=1)
                lo, hi = np.quantile(distances, (0.025, 0.975))
                distance_rows.append({"model": model, "family": family, "segment_bits": width,
                                      "ac_profile_l1_error": float(abs(q_actual.mean(axis=0)-q_pred).sum()),
                                      "ci95_low": float(lo), "ci95_high": float(hi)})
                for frequency in range(8192 // width):
                    row = {"model": model, "family": family, "segment_bits": width, "frequency_bin": frequency}
                    for kind in ("p_observed", "p_reference", "q_observed", "q_reference"):
                        x = profiles[f"{kind}_s{width}"][:, fi, frequency]
                        interval = np.quantile(x[draws].mean(axis=1), (0.025, 0.975))
                        row.update({f"{kind}_prediction": float(mc_spectra[f"{kind}_s{width}_mean"][mi, fi, frequency]),
                                    f"{kind}_prediction_mcse": float(mc_spectra[f"{kind}_s{width}_mcse"][mi, fi, frequency]),
                                    f"{kind}_evaluation": float(x.mean()), f"{kind}_ci95_low": float(interval[0]),
                                    f"{kind}_ci95_high": float(interval[1])})
                    spectral_rows.append(row)
    for name, records in (("scalar_summary.csv", rows), ("compact_summary.csv", compact),
                          ("spectral_summary.csv", spectral_rows), ("spectral_errors.csv", distance_rows),
                          ("evaluation_per_key.csv", per_key)):
        save_csv(directory / name, records)
    inputs = ("prediction_manifest.json", "evaluation_generation_manifest.json", "evaluation_raw.npz")
    outputs = ("evaluation_metrics.npz", "evaluation_spectra.npz", "scalar_summary.csv", "compact_summary.csv",
               "spectral_summary.csv", "spectral_errors.csv", "evaluation_per_key.csv")
    result = {"status": "smoke_complete" if smoke else "completed_fixed_prediction_evaluation",
              "fingerprint": predictions["fingerprint"], "protocol_sha256": PROTOCOL_SHA256,
              "models": MODELS, "families": FAMILIES, "segment_bits": WIDTHS, "rounds": 2,
              "training_key_indices": list(range(840, 920)), "evaluation_key_indices": keys.tolist(),
              "mc_replicates": predictions["mc_replicates"], "bootstrap_seed": BOOT_SEED,
              "bootstrap_replicates": BOOTSTRAPS,
              "compact_F512": "observed-minus-reference 512-bit fundamental fraction (DeltaF512)",
              "error_order": "evaluation mean minus fixed finite-MC prediction",
              "interval_scope": "pointwise whole-evaluation-key percentile intervals conditional on fixed training fit and MC estimate; MCSE reported separately",
              "spectral_error": "L1 distance between observed and predicted mean AC-normalized cipher spectra; normalize per mask before averaging",
              "hypothesis_tests": "none; no success threshold or model selection",
              "input_sha256": {name: sha256(directory / name) for name in inputs},
              "output_sha256": {name: sha256(directory / name) for name in outputs}}
    save_json(directory / "analysis_manifest.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fit-only", action="store_true")
    parser.add_argument("--analyze-only", action="store_true")
    args = parser.parse_args()
    directory = args.output or (Path("/tmp/arx_spectral_prediction_smoke") if args.smoke else OUT)
    if args.smoke and not directory.resolve().is_relative_to(Path("/tmp")):
        parser.error("Smoke output must be under /tmp")
    if args.analyze_only:
        result = analyze(directory, args.smoke)
    else:
        result = freeze_predictions(directory, args.smoke)
        if not args.fit_only:
            generate_evaluation(directory, args.smoke)
            result = analyze(directory, args.smoke)
    print(json.dumps({"status": result["status"], "directory": str(directory)}, indent=2))


if __name__ == "__main__":
    main()
