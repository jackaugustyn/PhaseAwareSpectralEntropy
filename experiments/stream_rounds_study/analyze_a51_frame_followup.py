#!/usr/bin/env python3
"""Analyze the locked A5/1 frame-difference cohort from archived XOR bits."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "doc_stream_ciphers" / "data" / "a51_frame_followup"
RAW = OUT / "a51_frame_raw.npz"
SEED = 20261014


def _metrics(packed: np.ndarray) -> dict[str, np.ndarray]:
    """Measure first-114-bit flip rates and the 19-sample frame spectrum.

    Each 114-bit XOR is divided into 19 six-bit HW samples. Fourier powers
    are averaged over the four base frames before entropy normalization.
    """
    if np.any(packed[..., -1] & 0x3F):
        raise AssertionError("Unused six bits must be zero")
    bits = np.unpackbits(packed, axis=-1, bitorder="big")[..., :114]
    fraction = bits.mean(axis=(-1, -2))
    first16 = bits[..., :16].mean(axis=(-1, -2))
    last16 = bits[..., -16:].mean(axis=(-1, -2))
    hw = bits.reshape(*bits.shape[:-1], 19, 6).sum(axis=-1)
    power = (np.abs(np.fft.fft(hw, axis=-1)) ** 2).mean(axis=-2)
    total = power.sum(axis=-1)
    p = np.divide(power, total[..., None], out=np.zeros_like(power), where=total[..., None] > 0)
    with np.errstate(divide="ignore", invalid="ignore"):
        hmp = -np.where(p > 0, p * np.log2(p), 0).sum(axis=-1)
    dc = p[..., 0]
    ac_total = 1 - dc
    ac = np.divide(p[..., 1:], ac_total[..., None], out=np.zeros_like(p[..., 1:]),
                   where=ac_total[..., None] > 0)
    with np.errstate(divide="ignore", invalid="ignore"):
        hn = -np.where(ac > 0, ac * np.log2(ac), 0).sum(axis=-1)
    return {"flip": fraction, "first16": first16, "last16": last16,
            "hmp": hmp, "dc": dc, "hnodc": hn}


def _ci(values: np.ndarray, rng: np.random.Generator, reps: int = 10000) -> tuple[float, float]:
    """Return a pointwise interval from whole-key bootstrap resamples."""
    n = len(values)
    sampled = rng.integers(0, n, size=(reps, n))
    means = values[sampled].mean(axis=1)
    return tuple(float(x) for x in np.quantile(means, [0.025, 0.975]))


def _sign_p(values: np.ndarray, rng: np.random.Generator, reps: int = 100000) -> float:
    """Estimate a two-sided sign-flip p-value for one key-level contrast."""
    observed = abs(float(values.mean()))
    n = len(values)
    exceed = 0
    for start in range(0, reps, 2000):
        batch = min(2000, reps - start)
        signs = rng.integers(0, 2, size=(batch, n), dtype=np.int8) * 2 - 1
        estimates = (signs.astype(float) @ values) / n
        exceed += int(np.count_nonzero(np.abs(estimates) >= observed - 1e-15))
    return (exceed + 1) / (reps + 1)


def _t_abs(means: np.ndarray, sumsq: np.ndarray, n: int) -> np.ndarray:
    variance = np.maximum((sumsq - n * means * means) / (n - 1), 0)
    stderr = np.sqrt(variance / n)
    return np.divide(np.abs(means), stderr, out=np.zeros_like(means), where=stderr > 0)


def _max_t(matrix: np.ndarray, rng: np.random.Generator, reps: int = 50000) -> np.ndarray:
    """Correct the 44-cell standard-depth search with a maximum-|t| test."""
    n, cells = matrix.shape
    observed = _t_abs(matrix.mean(axis=0), (matrix * matrix).sum(axis=0), n)
    exceed = np.zeros(cells, dtype=np.int64)
    sumsq = (matrix * matrix).sum(axis=0)
    for start in range(0, reps, 1000):
        batch = min(1000, reps - start)
        signs = rng.integers(0, 2, size=(batch, n), dtype=np.int8) * 2 - 1
        means = (signs.astype(float) @ matrix) / n
        max_t = _t_abs(means, sumsq, n).max(axis=1)
        exceed += (max_t[:, None] >= observed[None, :] - 1e-12).sum(axis=0)
    return (exceed + 1) / (reps + 1)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    """Verify raw hashes and regenerate A5/1 frame statistics and tables."""
    manifest = json.loads((OUT / "manifest.json").read_text())
    if hashlib.sha256(RAW.read_bytes()).hexdigest() != manifest["raw_sha256"]:
        raise AssertionError("Raw-array hash mismatch")
    protocol = ROOT / manifest["protocol"]
    if hashlib.sha256(protocol.read_bytes()).hexdigest() != manifest["protocol_sha256"]:
        raise AssertionError("Protocol hash mismatch")
    with np.load(RAW) as raw:
        indices = raw["key_indices"].copy()
        depths = raw["depths"].copy()
        masks = raw["masks"].copy()
        bases = raw["bases"].copy()
        observed = raw["observed"].copy()
        control = raw["control"].copy()
    if observed.shape != (80, 6, 22, 4, 15) or control.shape != observed.shape:
        raise AssertionError("Unexpected archived shape")
    if not np.array_equal(indices, np.arange(680, 760)) or not np.array_equal(
        depths, [0, 20, 40, 60, 80, 100]
    ) or not np.array_equal(masks, 1 << np.arange(22)):
        raise AssertionError("Unexpected cohort or schedule")
    for row in bases:
        stars = [{int(base)} | {int(base) ^ int(mask) for mask in masks} for base in row]
        if len(set.union(*stars)) != 4 * 23:
            raise AssertionError("Non-disjoint frame stars")

    obs = _metrics(observed)
    ctrl = _metrics(control)
    delta = {name: obs[name] - ctrl[name] for name in obs}
    rng = np.random.default_rng(SEED)
    per_key = []
    for i, index in enumerate(indices):
        for d, depth in enumerate(depths):
            for m, mask in enumerate(masks):
                per_key.append({"key_index": int(index), "warmup_clocks": int(depth),
                                "frame_bit_lsb": int(m), "frame_mask": int(mask),
                                **{f"delta_{name}": float(delta[name][i, d, m]) for name in delta}})
    _write_csv(OUT / "a51_per_key.csv", list(per_key[0]), per_key)

    summary = []
    for d, depth in enumerate(depths):
        item: dict = {"warmup_clocks": int(depth), "n_keys": len(indices)}
        for name in delta:
            key_values = delta[name][:, d].mean(axis=1)
            low, high = _ci(key_values, rng)
            item.update({f"delta_{name}_mean": float(key_values.mean()),
                         f"delta_{name}_ci_low": low, f"delta_{name}_ci_high": high})
        item["observed_flip_mean"] = float(obs["flip"][:, d].mean())
        item["control_flip_mean"] = float(ctrl["flip"][:, d].mean())
        summary.append(item)
    _write_csv(OUT / "a51_summary.csv", list(summary[0]), summary)

    d20 = int(np.flatnonzero(depths == 20)[0])
    primary_values = delta["flip"][:, d20].mean(axis=1)
    primary_p = _sign_p(primary_values, rng)
    primary_low, primary_high = _ci(primary_values, rng)
    planned = [{"endpoint": "20-clock all-mask mean XOR flip fraction, observed minus control",
                "mean": float(primary_values.mean()), "ci_low": primary_low,
                "ci_high": primary_high, "sign_flip_p_two_sided": primary_p,
                "reps": 100000, "n_keys": len(indices)}]
    _write_csv(OUT / "a51_planned_test.csv", list(planned[0]), planned)

    d100 = int(np.flatnonzero(depths == 100)[0])
    matrix = np.concatenate([delta["flip"][:, d100], delta["hmp"][:, d100]], axis=1)
    adjusted = _max_t(matrix, rng)
    scan = []
    for j, (name, m) in enumerate((name, m) for name in ("flip", "hmp") for m in range(22)):
        values = matrix[:, j]
        low, high = _ci(values, rng)
        scan.append({"metric": name, "frame_bit_lsb": m, "mean": float(values.mean()),
                     "ci_low": low, "ci_high": high, "maxT_p_adjusted": float(adjusted[j]),
                     "n_keys": len(indices), "maxT_reps": 50000})
    _write_csv(OUT / "a51_standard_mask_scan.csv", list(scan[0]), scan)

    result = {"primary": planned[0], "standard_min_adjusted_p": float(adjusted.min()),
              "standard_significant_cells": sum(row["maxT_p_adjusted"] <= 0.05 for row in scan),
              "standard_best_cell": min(scan, key=lambda row: row["maxT_p_adjusted"]),
              "summary": summary}
    (OUT / "analysis_summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in OUT.glob("*")
              if path.is_file() and path.name != "analysis_manifest.json"}
    (OUT / "analysis_manifest.json").write_text(json.dumps({"inputs": ["manifest.json", RAW.name],
                                                              "seed": SEED, "file_sha256": hashes}, indent=2) + "\n")
    print(json.dumps({"primary": result["primary"],
                      "standard_min_adjusted_p": result["standard_min_adjusted_p"],
                      "standard_significant_cells": result["standard_significant_cells"],
                      "standard_best_cell": result["standard_best_cell"],
                      "summary": [{"warmup_clocks": row["warmup_clocks"],
                                   "delta_flip_mean": row["delta_flip_mean"],
                                   "delta_hmp_mean": row["delta_hmp_mean"]} for row in summary]}, indent=2))


if __name__ == "__main__":
    main()
