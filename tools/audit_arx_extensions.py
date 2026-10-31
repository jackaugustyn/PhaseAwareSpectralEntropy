#!/usr/bin/env python3
"""Audit new ARX datasets and independently reproduce fresh validation metrics.

Reads existing data only. Neither the generator's aggregation nor its
measurement/statistical functions are imported. The JSON report records
what can be verified from archived HW arrays versus generation metadata.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "doc_stream_ciphers" / "data" / "arx_resolution_validation"
FAMILIES = ("ChaCha20", "Salsa20")
ROUNDS = (2, 4)
WINDOWS = {"full8192": (0, 16), "first4096": (0, 8), "last4096": (8, 16)}
METRICS = ("hmp", "hnodc", "block_harmonic_share", "block_fundamental_share")


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def archived_hash_checks() -> dict[str, object]:
    data = ROOT / "doc_stream_ciphers" / "data"
    mechanism_dir = data / "arx_mechanism_results"
    mechanism_manifest = mechanism_dir / "manifest.json"
    mechanism = json.loads(mechanism_manifest.read_text())
    count = 0
    for path, expected in mechanism["source_sha256"].items():
        assert _hash(ROOT / path) == expected, path
        count += 1
    for path, expected in mechanism["output_sha256"].items():
        assert _hash(mechanism_dir / path) == expected, path
        count += 1
    resolution_dir = data / "arx_resolution_results"
    resolution_manifest = resolution_dir / "arx_resolution_manifest.json"
    resolution = json.loads(resolution_manifest.read_text())
    assert _hash(ROOT / resolution["source_script"]) == resolution["source_script_sha256"]
    count += 1
    for path, expected in resolution["input_sha256"].items():
        assert _hash(ROOT / path) == expected, path
        count += 1
    for path, expected in resolution["output_sha256"].items():
        assert _hash(resolution_dir / path) == expected, path
        count += 1
    return {"verified_archived_source_input_output_hashes": count,
            "mechanism_manifest_sha256": _hash(mechanism_manifest),
            "resolution_manifest_sha256": _hash(resolution_manifest)}


def reference(words: np.ndarray, segment: int, start: int, stop: int) -> dict[str, np.ndarray]:
    # Flatten only the output-block and word axes, then add strided words
    # into contiguous segments; this differs from the generator's reshape.
    x = words[..., start:stop, :].astype(float).reshape(*words.shape[:-2], -1)
    width = segment // 32
    x = sum(x[..., shift::width] for shift in range(width))
    n = x.shape[-1]
    blocks = stop - start
    power = np.mean(np.abs(np.fft.rfft(x, axis=-1)) ** 2, axis=-2)
    weights = np.full(n // 2 + 1, 2.0)
    weights[0] = weights[-1] = 1.0
    total = np.sum(power * weights, axis=-1, keepdims=True)
    probability = power / total
    hmp = -np.sum(weights * probability * np.log2(np.where(probability > 0, probability, 1)), axis=-1)
    ac_total = np.sum(power[..., 1:] * weights[1:], axis=-1, keepdims=True)
    ac = power[..., 1:] / ac_total
    hnodc = -np.sum(weights[1:] * ac * np.log2(np.where(ac > 0, ac, 1)), axis=-1) / np.log2(n - 1)
    harmonic = np.sum(power[..., blocks::blocks] * weights[blocks::blocks], axis=-1) / ac_total[..., 0]
    fundamental = 2 * power[..., blocks] / ac_total[..., 0]
    return {"hmp": hmp, "hnodc": hnodc,
            "block_harmonic_share": harmonic, "block_fundamental_share": fundamental}


def audit(directory: Path, report: Path | None = None) -> dict[str, object]:
    archived_checks = archived_hash_checks()
    manifest_path = directory / "arx_resolution_validation_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    generation_path = directory / "generation_manifest.json"
    generation = json.loads(generation_path.read_text())
    assert _hash(generation_path) == manifest["generation_manifest_sha256"]
    raw_path = directory / "arx_resolution_validation_raw.npz"
    assert _hash(raw_path) == manifest["raw_sha256"] == generation["raw_sha256"]
    for path, digest in manifest["source_sha256"].items():
        assert _hash(ROOT / path) == digest
    assert _hash(ROOT / "doc_stream_ciphers" / "ARX_RESOLUTION_VALIDATION_PROTOCOL.txt") == manifest["protocol_sha256"]
    for name, digest in manifest["output_sha256"].items():
        assert _hash(directory / name) == digest
    with np.load(raw_path) as data:
        actual, control, keys = data["observed"], data["oracle"], data["key_indices"]
    assert actual.shape == control.shape == (80, 2, 2, 64, 4, 16, 16)
    np.testing.assert_array_equal(keys, np.arange(840, 920))
    assert actual.min() >= 0 and control.min() >= 0 and max(actual.max(), control.max()) <= 32

    def coordinates(row: dict[str, str]) -> tuple[str, int, int, str]:
        return row["family"], int(row["rounds"]), int(row["segment_bits"]), row["window"]

    recorded = {(coordinates(row), int(row["key_index"])): row
                for row in _rows(directory / "arx_resolution_validation_per_key.csv")}
    summary = {coordinates(row): row for row in _rows(directory / "arx_resolution_validation_summary.csv")}
    assert len(recorded) == 80 * 36 and len(summary) == 36
    draws = np.random.default_rng(2026102902).integers(0, 80, (5000, 80), dtype=np.int16)
    errors = {"per_key": 0.0, "mean": 0.0, "ci": 0.0}
    planned_values: dict[tuple[str, int], np.ndarray] = {}
    for fi, family in enumerate(FAMILIES):
        for ri, rounds in enumerate(ROUNDS):
            for width in (32, 64, 128):
                for window, (start, stop) in WINDOWS.items():
                    identity = family, rounds, width, window
                    a, c = (reference(x[:, fi, ri], width, start, stop) for x in (actual, control))
                    endpoint = {}
                    for metric in METRICS:
                        delta = a[metric] - c[metric]
                        endpoint[f"actual_{metric}"] = a[metric].mean(axis=1)
                        endpoint[f"control_{metric}"] = c[metric].mean(axis=1)
                        endpoint[f"delta_{metric}"] = delta.mean(axis=1)
                        endpoint[f"word_gap_delta_{metric}"] = np.mean(delta[:, 32:] - delta[:, :32], axis=1)
                    if rounds == 2 and window == "full8192":
                        planned_values[family, width] = endpoint["word_gap_delta_hmp"]
                    for name, values in endpoint.items():
                        old = np.array([float(recorded[identity, int(key)][name]) for key in keys])
                        errors["per_key"] = max(errors["per_key"], float(np.max(np.abs(values - old))))
                        errors["mean"] = max(errors["mean"], abs(float(values.mean()) - float(summary[identity][f"{name}_mean"])))
                        quantiles = np.quantile(values[draws].mean(axis=1), (0.025, 0.975))
                        for quantile, suffix in zip(quantiles, ("low", "high")):
                            errors["ci"] = max(errors["ci"], abs(float(quantile) - float(summary[identity][f"{name}_ci95_{suffix}"])))
    if max(errors.values()) > 2e-12:
        raise AssertionError(f"Independent rFFT endpoint reproduction failed: {errors}")

    planned = _rows(directory / "arx_resolution_validation_planned_tests.csv")
    expected = [("Salsa20", 32), ("Salsa20", 64), ("Salsa20", 128), ("ChaCha20", 32), ("ChaCha20", 64)]
    assert [(row["family"], int(row["segment_bits"])) for row in planned] == expected
    values = np.column_stack([planned_values[item] for item in expected])
    observed = np.abs(values.mean(axis=0))
    counts = np.zeros(5, dtype=np.int64)
    rng = np.random.default_rng(2026102901)
    for start in range(0, 100000, 2000):
        signs = rng.integers(0, 2, (min(2000, 100000 - start), 80), dtype=np.int8) * 2 - 1
        simulated = abs(np.einsum("rk,kc->rc", signs, values) / 80)
        counts += np.sum(simulated >= observed - 1e-12 * np.maximum(1, observed), axis=0)
    p = (counts + 1) / 100001
    adjusted = np.empty(5)
    running = 0.0
    for rank, column in enumerate(sorted(range(5), key=lambda i: p[i])):
        running = max(running, min(1.0, (5 - rank) * p[column]))
        adjusted[column] = running
    for column, row in enumerate(planned):
        assert int(row["sign_flip_extremes"]) == counts[column]
        assert float(row["p_two_sided_plus_one"]) == p[column]
        assert float(row["p_holm_five"]) == adjusted[column]
        assert abs(float(row["mean"]) - values[:, column].mean()) < 2e-12

    salsa = actual[:, 1, 0]
    zero_checks = [int(np.count_nonzero(salsa[:, :32, :, :, 1])),
                   sum(int(np.count_nonzero(salsa[:, 32:, :, :, word])) for word in (0, 1, 2, 3, 6)),
                   int(np.count_nonzero(salsa[:, 56, :, :, 7]))]
    counter_checks = sum(int(np.count_nonzero(salsa[..., word][..., 1:] != salsa[..., word][..., :1]))
                         for word in (4, 5, 6, 7, 11))
    assert not any(zero_checks) and counter_checks == 0
    result = {"status": "passed", "auditor_source_sha256": _hash(Path(__file__)),
              "archived_hash_checks": archived_checks,
              "audited_manifest_sha256": _hash(manifest_path),
              "independent_estimator": "weighted real FFT with mirrored-bin weights; separate strided-word aggregation",
              "verified_per_key_endpoints": [f"{prefix}_{metric}" for metric in METRICS
                                             for prefix in ("actual", "control", "delta", "word_gap_delta")],
              "configurations": 36, "keys": 80, "max_absolute_errors": errors,
              "inference": "5000 whole-key bootstrap draws, all five 100000-replicate two-sided sign-flip counts, plus-one p and five-test Holm reproduced",
              "raw_structural_violations": {"zero_output_word_checks": zero_checks,
                                            "counter_independent_difference_hw": counter_checks},
              "direct_emitted_word_check_limit": "raw archives retain HW only; direct emitted-word equality counts are checked in generation metadata, not reconstructed here"}
    for check in manifest["structural_checks"].values():
        assert check["violations"] == 0 and check["comparisons"] > 0
    if report is not None:
        report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(audit(arguments.directory, arguments.report), indent=2))
