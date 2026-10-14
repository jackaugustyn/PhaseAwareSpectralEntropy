#!/usr/bin/env python3
"""Analyze locked fresh-key nonce masks, Trivium subcubes and Grain IV probes."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from literature_mask_followup import (ARX_FAMILIES, ARX_INDICES, ARX_ROUNDS, GRAIN_BITS,
                                      GRAIN_CLOCKS, OUT, POPCOUNT, SECONDARY_INDICES,
                                      TRIVIUM_CLOCKS, TRIVIUM_DEGREES)


BOOT = 10_000
SIGN_FLIPS = 100_000
RNG_SEED = 20261030


def _csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _boot_indices(n: int, salt: int = 0) -> np.ndarray:
    return np.random.default_rng(RNG_SEED + salt).integers(0, n, (BOOT, n), dtype=np.int16)


def _ci(values: np.ndarray, samples: np.ndarray) -> tuple[float, float, float]:
    """Return a mean and pointwise 95% interval from whole-key resamples."""
    x = np.asarray(values, dtype=np.float64)
    if x.ndim != 1 or x.size != samples.shape[1]:
        raise AssertionError("Bootstrap unit is the whole key")
    means = x[samples].mean(axis=1)
    return float(x.mean()), float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))


def _sign_p(values: np.ndarray, seed: int) -> float:
    """Estimate a two-sided whole-key sign-flip p-value for one endpoint."""
    x = np.asarray(values, dtype=np.float64)
    rng = np.random.default_rng(seed)
    observed = abs(x.mean())
    hits = 0
    for start in range(0, SIGN_FLIPS, 2000):
        count = min(2000, SIGN_FLIPS - start)
        signs = rng.integers(0, 2, (count, x.size), dtype=np.int8) * 2 - 1
        hits += int(np.count_nonzero(np.abs(signs @ x / x.size) >= observed - 1e-15))
    return (hits + 1) / (SIGN_FLIPS + 1)


def _spectral(values: np.ndarray) -> dict[str, np.ndarray]:
    """Last axes: four paired-IV trajectories, each with 32 HW blocks."""
    x = np.asarray(values, dtype=np.float64)
    power = np.mean(np.abs(np.fft.fft(x, axis=-1)) ** 2, axis=-2)
    p = power / power.sum(axis=-1, keepdims=True)
    safe = np.where(p > 0, p, 1)
    hmp = -np.sum(p * np.log2(safe), axis=-1)
    ac = power[..., 1:] / power[..., 1:].sum(axis=-1, keepdims=True)
    safe_ac = np.where(ac > 0, ac, 1)
    hnodc = -np.sum(ac * np.log2(safe_ac), axis=-1) / np.log2(31)
    return {"hmp": hmp, "hnodc": hnodc, "p0": p[..., 0],
            "mean_hw": x.mean(axis=(-2, -1))}


def _arx() -> dict[str, object]:
    """Analyze all nonce-bit positions and output words in the ARX raw cohort.

    The two prespecified word-gap contrasts receive one two-test Holm
    correction; individual masks and output-word profiles remain descriptive.
    """
    with np.load(OUT / "arx_raw.npz") as raw:
        observed = raw["observed"]
        oracle = raw["oracle"]
        indices = raw["key_indices"]
    if observed.shape != (80, 2, 5, 64, 4, 8, 16) or oracle.shape != observed.shape:
        raise AssertionError("Unexpected ARX raw shape")
    if tuple(indices) != ARX_INDICES:
        raise AssertionError("Unexpected ARX key indices")
    metrics = {name: np.empty((80, 2, 5, 64), dtype=np.float64)
               for name in ("hmp", "hnodc", "p0", "mean_hw")}
    for fi in range(2):
        for ri in range(5):
            for sign, arr in ((1, observed), (-1, oracle)):
                trajectories = arr[:, fi, ri].reshape(80, 64, 4, 8, 4, 4).sum(
                    axis=-1, dtype=np.uint8).reshape(80, 64, 4, 32)
                measured = _spectral(trajectories)
                for name in metrics:
                    if sign == 1:
                        metrics[name][:, fi, ri] = measured[name]
                    else:
                        metrics[name][:, fi, ri] -= measured[name]
    samples = _boot_indices(80)
    gaps = {name: metrics[name][..., 32:].mean(axis=-1) - metrics[name][..., :32].mean(axis=-1)
            for name in metrics}
    primary = [gaps["hmp"][:, 1, 0], gaps["hmp"][:, 1, 0] - gaps["hmp"][:, 0, 0]]
    pvals = [_sign_p(primary[0], RNG_SEED + 100), _sign_p(primary[1], RNG_SEED + 101)]
    order = np.argsort(pvals)
    adjusted = [0.0, 0.0]
    running = 0.0
    for rank, index in enumerate(order):
        running = max(running, min(1.0, (2 - rank) * pvals[index]))
        adjusted[index] = running
    planned_rows = []
    for name, values, p, adj in zip(
        ("Salsa20/2: second minus first nonce word",
         "Salsa20/2 minus ChaCha20/2: matched word gaps"), primary, pvals, adjusted
    ):
        mean, lo, hi = _ci(values, samples)
        planned_rows.append({"endpoint": name, "n_keys": 80, "estimate_bits": mean,
                             "ci95_low": lo, "ci95_high": hi, "p_sign_flip": p,
                             "p_holm": adj, "replicates": SIGN_FLIPS})
    _csv(OUT / "arx_planned_tests.csv", planned_rows)

    gap_rows = []
    for fi, family in enumerate(ARX_FAMILIES):
        for ri, rounds in enumerate(ARX_ROUNDS):
            record: dict[str, object] = {"family": family, "rounds": rounds, "n_keys": 80}
            for name in metrics:
                mean, lo, hi = _ci(gaps[name][:, fi, ri], samples)
                record[f"word_gap_delta_{name}"] = mean
                record[f"word_gap_delta_{name}_ci95_low"] = lo
                record[f"word_gap_delta_{name}_ci95_high"] = hi
            gap_rows.append(record)
    _csv(OUT / "arx_word_gap_by_round.csv", gap_rows)

    mask_rows = []
    for fi, family in enumerate(ARX_FAMILIES):
        for ri, rounds in enumerate(ARX_ROUNDS):
            for bit in range(64):
                record = {"family": family, "rounds": rounds, "nonce_bit_msb_first": bit,
                          "nonce_word": 1 if bit < 32 else 2, "within_word_msb_position": bit % 32,
                          "n_keys": 80}
                for name in metrics:
                    x = metrics[name][:, fi, ri, bit]
                    record[f"delta_{name}"] = float(x.mean())
                    record[f"delta_{name}_sd_keys"] = float(x.std(ddof=1))
                mask_rows.append(record)
    _csv(OUT / "arx_all_64_masks.csv", mask_rows)

    literature = (("ChaCha20", 1, "x_14[6]", "x_3[0]", 3.5),
                  ("ChaCha20", 33, "x_15[6]", "x_0[0]", 3.5),
                  ("Salsa20", 39, "x_7[0]", "x_1[13]", 4.0))
    literature_rows = []
    for family, bit, input_id, internal_output_id, source_round in literature:
        fi = ARX_FAMILIES.index(family)
        for ri, rounds in enumerate(ARX_ROUNDS):
            record = {"family": family, "input_state_bit": input_id,
                      "published_internal_output_bit": internal_output_id,
                      "published_internal_round": source_round,
                      "our_nonce_bit_msb_first": bit, "our_keystream_rounds": rounds,
                      "observable": "emitted keystream HW; not published internal-state bias"}
            for name in metrics:
                record[f"delta_{name}"] = float(metrics[name][:, fi, ri, bit].mean())
            literature_rows.append(record)
    _csv(OUT / "arx_literature_input_positions.csv", literature_rows)

    word_hw_delta = (observed.astype(np.float64) - oracle.astype(np.float64))
    profile_rows = []
    output_gap_rows = []
    profile_magnitude_rows = []
    for fi, family in enumerate(ARX_FAMILIES):
        for ri, rounds in enumerate(ARX_ROUNDS):
            per_key_input_words = []
            for input_word in range(2):
                view = word_hw_delta[:, fi, ri, 32 * input_word:32 * (input_word + 1)]
                per_key = view.mean(axis=(1, 2, 3))
                per_key_input_words.append(per_key)
                for output_word in range(16):
                    mean, lo, hi = _ci(per_key[:, output_word], samples)
                    profile_rows.append({"family": family, "rounds": rounds,
                                         "input_nonce_word": input_word + 1,
                                         "output_word": output_word,
                                         "delta_word_hw": mean, "ci95_low": lo,
                                         "ci95_high": hi})
            paired_gap = per_key_input_words[1] - per_key_input_words[0]
            l1_mean, l1_lo, l1_hi = _ci(np.abs(paired_gap).sum(axis=1), samples)
            profile_magnitude_rows.append({"family": family, "rounds": rounds,
                                           "per_key_output_word_gap_l1": l1_mean,
                                           "ci95_low": l1_lo, "ci95_high": l1_hi,
                                           "status": "post hoc descriptive"})
            for output_word in range(16):
                mean, lo, hi = _ci(paired_gap[:, output_word], samples)
                output_gap_rows.append({"family": family, "rounds": rounds,
                                        "output_word": output_word,
                                        "second_minus_first_delta_word_hw": mean,
                                        "ci95_low": lo, "ci95_high": hi})
    _csv(OUT / "arx_output_word_profiles.csv", profile_rows)
    _csv(OUT / "arx_output_word_gap.csv", output_gap_rows)
    _csv(OUT / "arx_output_profile_magnitude.csv", profile_magnitude_rows)
    return {"planned": planned_rows, "word_gaps": gap_rows,
            "max_abs_mask_by_round": [
                {"family": family, "rounds": rounds, "bit": int(np.argmax(np.abs(metrics["hmp"][:, fi, ri].mean(axis=0)))),
                 "max_abs_delta_hmp": float(np.max(np.abs(metrics["hmp"][:, fi, ri].mean(axis=0))))}
                for fi, family in enumerate(ARX_FAMILIES) for ri, rounds in enumerate(ARX_ROUNDS)
            ]}


def _max_t_p(values: np.ndarray, replicates: int, seed: int) -> np.ndarray:
    """Whole-key sign flip; one family-wise max-|t| across all columns."""
    x = np.asarray(values, dtype=np.float64)
    n, m = x.shape
    means = x.mean(axis=0)
    sumsquares = np.sum(x * x, axis=0)
    observed_sd = x.std(axis=0, ddof=1)
    observed_t = np.abs(means) / np.maximum(observed_sd / np.sqrt(n), 1e-15)
    hits = np.zeros(m, dtype=np.int64)
    rng = np.random.default_rng(seed)
    for start in range(0, replicates, 1000):
        batch = min(1000, replicates - start)
        signs = rng.integers(0, 2, (batch, n), dtype=np.int8) * 2 - 1
        sim_mean = signs @ x / n
        sim_var = np.maximum((sumsquares[None, :] - n * sim_mean**2) / (n - 1), 1e-30)
        max_t = np.max(np.abs(sim_mean) / np.sqrt(sim_var / n), axis=1)
        hits += np.count_nonzero(max_t[:, None] >= observed_t[None, :] - 1e-12, axis=0)
    return (hits + 1) / (replicates + 1)


def _trivium() -> dict[str, object]:
    """Analyze the Trivium subcube pilot with its planned max-|t| family."""
    with np.load(OUT / "trivium_raw.npz") as raw:
        observed = raw["observed"]
        oracle = raw["oracle"]
        indices = raw["key_indices"]
    if observed.shape != (80, 4, 3, 4, 64) or oracle.shape != observed.shape:
        raise AssertionError("Unexpected Trivium raw shape")
    if tuple(indices) != SECONDARY_INDICES:
        raise AssertionError("Unexpected Trivium key indices")
    actual_fraction = POPCOUNT[observed].sum(axis=-1).mean(axis=-1) / 512
    control_fraction = POPCOUNT[oracle].sum(axis=-1).mean(axis=-1) / 512
    difference = actual_fraction - control_fraction
    first_actual = (observed[..., 0] & 1).mean(axis=-1)
    first_control = (oracle[..., 0] & 1).mean(axis=-1)
    p_adj = _max_t_p(difference.reshape(80, 12), 50_000, RNG_SEED + 300).reshape(4, 3)
    samples = _boot_indices(80, 1)
    rows = []
    for ci, clocks in enumerate(TRIVIUM_CLOCKS):
        for di, degree in enumerate(TRIVIUM_DEGREES):
            mean, lo, hi = _ci(difference[:, ci, di], samples)
            unpacked = np.unpackbits(observed[:, ci, di], axis=-1, bitorder="little").reshape(320, 512)
            first_one = np.where(unpacked.any(axis=1), unpacked.argmax(axis=1), 512)
            common_zero_prefix = int(np.argmax(unpacked.any(axis=0))) if unpacked.any() else 512
            rows.append({"clocks": clocks, "cube_degree": degree, "n_keys": 80,
                         "n_base_ivs_per_key": 4, "output_bits": 512,
                         "observed_one_fraction": float(actual_fraction[:, ci, di].mean()),
                         "control_one_fraction": float(control_fraction[:, ci, di].mean()),
                         "delta_one_fraction": mean, "ci95_low": lo, "ci95_high": hi,
                         "p_max_t_12_cells": float(p_adj[ci, di]),
                         "observed_first_bit_fraction": float(first_actual[:, ci, di].mean()),
                         "control_first_bit_fraction": float(first_control[:, ci, di].mean()),
                         "exploratory_common_zero_prefix_bits": common_zero_prefix,
                         "exploratory_median_first_one_position": float(np.median(first_one))})
    _csv(OUT / "trivium_subcube_summary.csv", rows)
    return {"subcubes": rows}


def _grain() -> dict[str, object]:
    """Analyze the fresh-key Grain IV-position validation endpoint."""
    with np.load(OUT / "grain_raw.npz") as raw:
        observed = raw["observed"]
        oracle = raw["oracle"]
        indices = raw["key_indices"]
    if observed.shape != (80, 4, 6, 4, 32) or oracle.shape != observed.shape:
        raise AssertionError("Unexpected Grain raw shape")
    if tuple(indices) != SECONDARY_INDICES:
        raise AssertionError("Unexpected Grain key indices")
    actual = _spectral(observed)
    control = _spectral(oracle)
    differences = {name: actual[name] - control[name] for name in actual}
    samples = _boot_indices(80, 2)
    rows = []
    for ci, clocks in enumerate(GRAIN_CLOCKS):
        for bi, bit in enumerate(GRAIN_BITS):
            record: dict[str, object] = {"clocks": clocks, "iv_bit_msb_first": bit,
                                         "n_keys": 80}
            for name in differences:
                mean, lo, hi = _ci(differences[name][:, ci, bi], samples)
                record[f"delta_{name}"] = mean
                record[f"delta_{name}_ci95_low"] = lo
                record[f"delta_{name}_ci95_high"] = hi
            rows.append(record)
    _csv(OUT / "grain_locality_masks.csv", rows)
    primary = differences["hmp"][:, 0, GRAIN_BITS.index(64)] - differences["hmp"][:, 0, GRAIN_BITS.index(0)]
    mean, lo, hi = _ci(primary, samples)
    planned = {"endpoint": "Grain-128/0: bit 64 minus bit 0", "n_keys": 80,
               "estimate_bits": mean, "ci95_low": lo, "ci95_high": hi,
               "p_sign_flip": _sign_p(primary, RNG_SEED + 400), "replicates": SIGN_FLIPS}
    _csv(OUT / "grain_planned_test.csv", [planned])
    return {"planned": planned, "masks": rows}


def main() -> None:
    """Regenerate follow-up CSV tables and analysis manifest from raw arrays."""
    OUT.mkdir(parents=True, exist_ok=True)
    result = {"arx": _arx(), "trivium": _trivium(), "grain": _grain()}
    (OUT / "analysis_summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    processed = sorted(path for path in OUT.iterdir() if path.suffix == ".csv" or
                       path.name == "analysis_summary.json")
    manifest = {
        "inputs": ["manifest.json", "arx_raw.npz", "trivium_raw.npz", "grain_raw.npz"],
        "analysis_files_sha256": {
            path.relative_to(OUT.parents[2]).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in processed
        },
    }
    (OUT / "analysis_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                                encoding="utf-8")
    print(json.dumps({"arx_planned": result["arx"]["planned"],
                      "grain_planned": result["grain"]["planned"],
                      "trivium_subcubes": result["trivium"]["subcubes"]}, indent=2))


if __name__ == "__main__":
    main()
