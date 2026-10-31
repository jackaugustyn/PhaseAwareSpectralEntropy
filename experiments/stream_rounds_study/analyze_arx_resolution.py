#!/usr/bin/env python3
"""Descriptive resolution/window reanalysis of archived ARX word-HW data.

No streams or keys are generated. For each mask the four base-nonce power
spectra are averaged before normalization (Q=4), as in the original scan.
The original 128-bit/full-window nonce-word gaps are independently checked.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "doc_stream_ciphers" / "data" / "literature_mask_followup"
OUTPUT = ROOT / "doc_stream_ciphers" / "data" / "arx_resolution_results"
FAMILIES = ("ChaCha20", "Salsa20")
ROUNDS = (2, 4, 6, 8, 20)
SEGMENTS = (32, 64, 128)
WINDOWS = {"full4096": (0, 8), "first2048": (0, 4), "last2048": (4, 8)}
BOOTSTRAPS = 5000
BOOTSTRAP_SEED = 20261029
METRICS = ("hmp", "hnodc", "p0", "mean_hw_fraction",
           "block_harmonic_share", "block_fundamental_share", "phase_range_fraction")


def aggregate_words(words: np.ndarray, segment_bits: int,
                    block_start: int, block_stop: int) -> np.ndarray:
    """Sum contiguous 32-bit HWs, preserving trajectory and block order."""
    x = np.asarray(words)
    if x.shape[-2:] != (8, 16) or segment_bits not in SEGMENTS:
        raise ValueError("Expected eight 16-word blocks and 32/64/128-bit segments")
    if not 0 <= block_start < block_stop <= 8:
        raise ValueError("Window must contain complete output blocks")
    width = segment_bits // 32
    selected = x[..., block_start:block_stop, :]
    shape = (*x.shape[:-2], block_stop - block_start, 16 // width, width)
    return selected.reshape(shape).sum(axis=-1, dtype=np.uint16).reshape(
        *x.shape[:-2], -1)


def measure(trajectories: np.ndarray, segment_bits: int) -> dict[str, np.ndarray]:
    """Return one measurement per key and mask, averaging Q spectra first.

    If L=512/segment_bits and N=B*L, the block harmonic share is
    sum(P[j*B], j=1,...,L-1) / sum(P[1:]). It measures the fraction of AC
    power at frequencies compatible with a repeating 512-bit-block profile.
    Its matched-control subtraction adjusts for differing N and L.
    """
    x = np.asarray(trajectories, dtype=np.float64)
    n = x.shape[-1]
    period = 512 // segment_bits
    if x.ndim < 2 or segment_bits not in SEGMENTS or n % period:
        raise ValueError("Trajectories must cover an integer number of output blocks")
    blocks = n // period
    power = np.mean(np.abs(np.fft.fft(x, axis=-1)) ** 2, axis=-2)
    total = power.sum(axis=-1, keepdims=True)
    p = np.divide(power, total, out=np.zeros_like(power), where=total > 0)
    hmp = -np.sum(p * np.log2(np.where(p > 0, p, 1)), axis=-1)
    ac_power = power[..., 1:].sum(axis=-1, keepdims=True)
    ac = np.divide(power[..., 1:], ac_power,
                   out=np.zeros_like(power[..., 1:]), where=ac_power > 0)
    hnodc = -np.sum(ac * np.log2(np.where(ac > 0, ac, 1)), axis=-1) / np.log2(n - 1)
    harmonic_power = power[..., blocks::blocks].sum(axis=-1)
    share = np.divide(harmonic_power, ac_power[..., 0],
                      out=np.zeros_like(harmonic_power), where=ac_power[..., 0] > 0)
    fundamental_power = power[..., blocks] + power[..., -blocks]
    fundamental_share = np.divide(
        fundamental_power, ac_power[..., 0], out=np.zeros_like(fundamental_power),
        where=ac_power[..., 0] > 0)
    phase = x.reshape(*x.shape[:-1], blocks, period).mean(axis=(-3, -2))
    return {
        "hmp": hmp,
        "hnodc": hnodc,
        "p0": p[..., 0],
        "mean_hw_fraction": x.mean(axis=(-2, -1)) / segment_bits,
        "block_harmonic_share": share,
        "block_fundamental_share": fundamental_share,
        "phase_range_fraction": np.ptp(phase, axis=-1) / segment_bits,
    }


def _csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ci(values: np.ndarray, indices: np.ndarray) -> tuple[float, float, float]:
    means = values[indices].mean(axis=1)
    lo, hi = np.quantile(means, (0.025, 0.975))
    return float(values.mean()), float(lo), float(hi)


def analyze(output: Path = OUTPUT) -> dict[str, object]:
    source_manifest = json.loads((SOURCE / "manifest.json").read_text())
    raw_path = SOURCE / "arx_raw.npz"
    raw_hash = _sha256(raw_path)
    if raw_hash != source_manifest["raw_sha256"]["arx"]:
        raise AssertionError("Archived raw data hash does not match its original manifest")
    with np.load(raw_path) as raw:
        actual = raw["observed"]
        control = raw["oracle"]
        key_indices = raw["key_indices"]
    if actual.shape != (80, 2, 5, 64, 4, 8, 16) or control.shape != actual.shape:
        raise AssertionError("Unexpected raw ARX data axes")
    if not np.array_equal(key_indices, np.arange(520, 600)):
        raise AssertionError("Expected the original 80-key cohort")
    if actual.max() > 32 or control.max() > 32:
        raise AssertionError("Input values must be 32-bit Hamming weights")

    samples = np.random.default_rng(BOOTSTRAP_SEED).integers(
        0, len(key_indices), size=(BOOTSTRAPS, len(key_indices)), dtype=np.int16)
    per_key: list[dict[str, object]] = []
    summary: list[dict[str, object]] = []
    compact: list[dict[str, object]] = []
    reproduced: dict[tuple[str, int], dict[str, float]] = {}
    for fi, family in enumerate(FAMILIES):
        for ri, rounds in enumerate(ROUNDS):
            for segment in SEGMENTS:
                for window, (start, stop) in WINDOWS.items():
                    measured = [measure(aggregate_words(arr[:, fi, ri], segment, start, stop), segment)
                                for arr in (actual, control)]
                    endpoints: dict[str, np.ndarray] = {}
                    for name in METRICS:
                        observed, oracle = measured[0][name], measured[1][name]
                        delta = observed - oracle
                        endpoints[f"actual_{name}"] = observed.mean(axis=-1)
                        endpoints[f"control_{name}"] = oracle.mean(axis=-1)
                        endpoints[f"delta_{name}"] = delta.mean(axis=-1)
                        endpoints[f"word_gap_delta_{name}"] = (
                            delta[:, 32:].mean(axis=-1) - delta[:, :32].mean(axis=-1))
                    axes: dict[str, object] = {
                        "family": family, "rounds": rounds, "segment_bits": segment,
                        "window": window, "block_start": start, "block_stop_exclusive": stop,
                        "n_samples": (stop - start) * 512 // segment,
                        "samples_per_512bit_block": 512 // segment,
                    }
                    for ki, key in enumerate(key_indices):
                        per_key.append({**axes, "key_index": int(key),
                                        **{name: float(x[ki]) for name, x in endpoints.items()}})
                    row: dict[str, object] = {**axes, "n_keys": len(key_indices)}
                    for name, values in endpoints.items():
                        mean, lo, hi = _ci(values, samples)
                        row[f"{name}_mean"] = mean
                        row[f"{name}_ci95_low"] = lo
                        row[f"{name}_ci95_high"] = hi
                    summary.append(row)
                    if segment == 128 and window == "full4096":
                        reproduced[family, rounds] = {
                            name: float(endpoints[f"word_gap_delta_{name}"].mean())
                            for name in ("hmp", "hnodc", "p0")}
                    compact.append({name: row[name] for name in (
                        "family", "rounds", "segment_bits", "window", "n_samples",
                        "samples_per_512bit_block", "n_keys",
                        "word_gap_delta_hmp_mean", "word_gap_delta_hmp_ci95_low",
                        "word_gap_delta_hmp_ci95_high", "delta_hnodc_mean",
                        "delta_hnodc_ci95_low", "delta_hnodc_ci95_high",
                        "actual_block_harmonic_share_mean", "control_block_harmonic_share_mean",
                        "delta_block_harmonic_share_mean", "delta_block_harmonic_share_ci95_low",
                        "delta_block_harmonic_share_ci95_high",
                        "delta_block_fundamental_share_mean", "delta_block_fundamental_share_ci95_low",
                        "delta_block_fundamental_share_ci95_high", "delta_phase_range_fraction_mean",
                        "delta_phase_range_fraction_ci95_low", "delta_phase_range_fraction_ci95_high")})
            print(f"Analyzed {family}/{rounds}: all resolutions and windows", flush=True)

    with (SOURCE / "arx_word_gap_by_round.csv").open(newline="") as stream:
        old_rows = list(csv.DictReader(stream))
    discrepancies = [abs(reproduced[row["family"], int(row["rounds"])][name]
                         - float(row[f"word_gap_delta_{name}"]))
                     for row in old_rows for name in ("hmp", "hnodc", "p0")]
    max_error = max(discrepancies)
    if max_error > 5e-13:
        raise AssertionError(f"128-bit/full-window reproduction failed: {max_error}")

    output.mkdir(parents=True, exist_ok=True)
    _csv(output / "arx_resolution_per_key.csv", per_key)
    _csv(output / "arx_resolution_summary.csv", summary)
    _csv(output / "arx_resolution_compact.csv", compact)
    manifest: dict[str, object] = {
        "analysis": "ARX segment-resolution and output-window robustness",
        "status": "completed descriptive secondary analysis of previously examined cohort",
        "new_keys_generated": 0,
        "source_script": str(Path(__file__).relative_to(ROOT)),
        "source_script_sha256": _sha256(Path(__file__)),
        "input_sha256": {
            str(path.relative_to(ROOT)): _sha256(path)
            for path in (raw_path, SOURCE / "manifest.json", SOURCE / "arx_word_gap_by_round.csv")
        },
        "raw_axes": ["key", "cipher", "rounds", "nonce_mask_msb_first", "base_nonce",
                     "output_block512", "word_hw32"],
        "raw_shape": list(actual.shape),
        "families": list(FAMILIES), "rounds": list(ROUNDS),
        "key_indices_inclusive": [520, 599], "masks": "all 64 single-bit nonce changes",
        "base_nonces_per_key": 4, "power_averaging": "Q=4 within each mask before normalization",
        "segment_bits": list(SEGMENTS),
        "windows_blocks_start_stop_exclusive": WINDOWS,
        "segmentation_origin_bits": 0,
        "normalization": {"hnodc": "AC Shannon entropy divided by log2(N-1)",
                          "phase_range_fraction": "range of base/block-averaged phase HW divided by segment_bits",
                          "mean_hw_fraction": "mean HW divided by segment_bits"},
        "block_harmonic_share": "sum P[j*B], j=1..L-1, divided by sum P[1:]; L=512/segment_bits; B=window_bits/512; N=B*L",
        "block_fundamental_share": "(P[B]+P[N-B])/sum(P[1:]); isolates the frequency 1/512 bits and excludes its higher harmonics",
        "constant_trajectory_convention": "entropy and block harmonic share are zero when their total power is zero",
        "aggregation": "average mask-level metrics within each key; deltas are observed minus matched control; word gap is mean delta for masks32:64 minus masks0:32",
        "ci": {"method": "percentile whole-key bootstrap; pointwise descriptive 95% intervals",
               "replicates": BOOTSTRAPS, "seed": BOOTSTRAP_SEED,
               "paired_resampling": "same key-index draws across both ciphers, all settings and metrics",
               "multiplicity": "no simultaneous coverage claimed; no new hypothesis tests"},
        "old_128bit_full4096_max_abs_reproduction_error": max_error,
        "reproduction_endpoints": "word_gap_delta_hmp, word_gap_delta_hnodc, word_gap_delta_p0; both ciphers and all five rounds",
        "output_rows": {"per_key": len(per_key), "summary": len(summary)},
        "limitations": ["same 80-key cohort; these are not independent replications",
                        "only block-aligned segmentation and complete-block windows",
                        "no measurements below 32-bit resolution can be reconstructed from word-HW data"],
        "numpy_version": np.__version__,
        "output_sha256": {path.name: _sha256(path) for path in sorted(output.glob("arx_resolution_*.csv"))},
    }
    (output / "arx_resolution_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    result = analyze(args.output)
    print(json.dumps({"status": result["status"], "rows": result["output_rows"],
                      "reproduction_error": result["old_128bit_full4096_max_abs_reproduction_error"]}, indent=2))
