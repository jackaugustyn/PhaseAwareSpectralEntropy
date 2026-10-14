#!/usr/bin/env python3
"""Exploratory IV-pair validation with disjoint output blocks.

Each trajectory is the HW of the XOR of 32 consecutive, nonoverlapping
128-bit blocks from paired IVs at fixed key. The standard condition uses the
full cipher initialization; zero clocks serves as a positive control.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from analyze_spectral_added_value import _pooled_ljung_box_score
from publication_study import _key_material, _summarise_trajectories
from spectral_crypto_analyzer.primitives import (
    _grain128_keystream_128,
    _trivium_keystream_128,
)


HERE = Path(__file__).resolve().parent
OUTPUT = HERE.parents[1] / "doc_stream_ciphers" / "data" / "extension_results"
MASTER_SEED = 20260721
KEY_INDICES = tuple(range(80, 120))
BASE_IVS = 4
BLOCKS = 32
BLOCK_BITS = 128
BOOTSTRAP_REPLICATES = 5000
BOOTSTRAP_SEED = 20261013
FAMILIES = {
    "Grain-128": (12, 16, 256, b"stream:grain-rr-key", _grain128_keystream_128),
    "Trivium": (10, 10, 1152, b"stream:trivium-rr-key", _trivium_keystream_128),
}
CONDITIONS = ("zero_clock", "standard")
METRICS = (
    "entropy_mean_power", "dc_share", "entropy_no_dc_normalized",
    "mean_hamming_weight", "mean_temporal_variance", "ljung_box_q8",
)


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _mask(iv_bytes: int, positions: tuple[int, ...]) -> bytes:
    data = bytearray(iv_bytes)
    for position in positions:
        data[position // 8] ^= 1 << (7 - position % 8)
    return bytes(data)


def _mask_sets(iv_bytes: int) -> dict[str, list[bytes]]:
    """Choose four spread single-bit masks and four adjacent four-bit masks."""
    n_bits = 8 * iv_bytes
    singles = (0, n_bits // 3, 2 * n_bits // 3, n_bits - 1)
    starts = (0, (n_bits - 4) // 3, 2 * (n_bits - 4) // 3, n_bits - 4)
    return {
        "single_bit": [_mask(iv_bytes, (p,)) for p in singles],
        "localized_four_bit": [_mask(iv_bytes, tuple(range(p, p + 4))) for p in starts],
    }


def _metrics(values: np.ndarray) -> dict[str, float]:
    """Summarize 128-bit HW trajectories, including spectral and lag scores."""
    spectral = _summarise_trajectories([row.astype(float) for row in values])
    spectral["ljung_box_q8"] = _pooled_ljung_box_score(values, max_lag=8)
    spectral["ljung_box_q16"] = (
        _pooled_ljung_box_score(values, max_lag=16) if values.shape[1] > 16 else float("nan")
    )
    if abs(spectral["entropy_decomposition_residual"]) > 1e-12:
        raise AssertionError("Entropy decomposition residual exceeds tolerance")
    return spectral


def _block_hamming_weights(left: bytes, right: bytes) -> np.ndarray:
    """Return 32 HW counts from disjoint 128-bit XOR output segments."""
    if len(left) != BLOCKS * BLOCK_BITS // 8 or len(right) != len(left):
        raise AssertionError("Output stream has wrong length")
    difference = bytes(a ^ b for a, b in zip(left, right))
    return np.asarray([
        int.from_bytes(difference[16 * i:16 * (i + 1)], "big").bit_count()
        for i in range(BLOCKS)
    ], dtype=np.uint8)


def _one_key(args: tuple[str, int]) -> tuple[list[dict[str, object]], dict[str, np.ndarray]]:
    family, key_index = args
    iv_bytes, key_bytes, standard_depth, tag, cipher = FAMILIES[family]
    master_key, rng = _key_material(MASTER_SEED, key_index)
    key = hashlib.blake2b(tag + master_key, digest_size=key_bytes).digest()
    bases = [rng.bytes(iv_bytes) for _ in range(BASE_IVS)]
    rows: list[dict[str, object]] = []
    arrays: dict[str, np.ndarray] = {}
    for condition in CONDITIONS:
        warmup = 0 if condition == "zero_clock" else standard_depth
        base_streams = [cipher(key, base, warmup, BLOCKS * BLOCK_BITS) for base in bases]
        for scenario, masks in _mask_sets(iv_bytes).items():
            trajectories = np.empty((len(bases) * len(masks), BLOCKS), dtype=np.uint8)
            for b_index, base in enumerate(bases):
                base_int = int.from_bytes(base, "big")
                for m_index, mask in enumerate(masks):
                    other = (base_int ^ int.from_bytes(mask, "big")).to_bytes(iv_bytes, "big")
                    other_stream = cipher(key, other, warmup, BLOCKS * BLOCK_BITS)
                    trajectories[b_index * len(masks) + m_index] = _block_hamming_weights(
                        base_streams[b_index], other_stream
                    )
            seed_bytes = f"standard-iv-ideal:{MASTER_SEED}:{family}:{condition}:{scenario}:{key_index}".encode()
            ideal_seed = int.from_bytes(hashlib.blake2b(seed_bytes, digest_size=8).digest(), "big")
            ideal = np.random.default_rng(ideal_seed).binomial(
                128, 0.5, size=trajectories.shape
            ).astype(np.uint8)
            arrays[f"{condition}_{scenario}_observed"] = trajectories
            arrays[f"{condition}_{scenario}_ideal"] = ideal
            for window, indices in (("full32", slice(None)), ("tail16", slice(16, None))):
                actual_metrics = _metrics(trajectories[:, indices])
                ideal_metrics = _metrics(ideal[:, indices])
                row: dict[str, object] = {
                    "family": family, "scenario": scenario, "condition": condition,
                    "warmup_clocks": warmup, "window": window, "key_index": key_index,
                    "key_trajectory_count": trajectories.shape[0],
                    "trajectory_length": trajectories[:, indices].shape[1],
                }
                for metric in METRICS + ("ljung_box_q16",):
                    row[f"observed_{metric}"] = actual_metrics[metric]
                    row[f"ideal_{metric}"] = ideal_metrics[metric]
                    row[f"difference_{metric}"] = actual_metrics[metric] - ideal_metrics[metric]
                rows.append(row)
    return rows, arrays


def _summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, str, str, str], list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault(tuple(str(row[name]) for name in
                                ("family", "scenario", "condition", "window")), []).append(row)
    output: list[dict[str, object]] = []
    for i, ((family, scenario, condition, window), group) in enumerate(sorted(groups.items())):
        group.sort(key=lambda row: int(row["key_index"]))
        if len(group) != len(KEY_INDICES):
            raise AssertionError("Missing independent key")
        indices = np.random.default_rng(BOOTSTRAP_SEED + i).integers(
            0, len(group), size=(BOOTSTRAP_REPLICATES, len(group))
        )
        result: dict[str, object] = {
            "family": family, "scenario": scenario, "condition": condition,
            "warmup_clocks": group[0]["warmup_clocks"], "window": window,
            "n_keys": len(group), "trajectories_per_key": group[0]["key_trajectory_count"],
        }
        for metric in METRICS + (("ljung_box_q16",) if window == "full32" else ()):
            for prefix in ("observed", "ideal", "difference"):
                values = np.asarray([float(row[f"{prefix}_{metric}"]) for row in group])
                means = values[indices].mean(axis=1)
                result[f"{prefix}_{metric}_mean"] = float(values.mean())
                result[f"{prefix}_{metric}_ci95_low"] = float(np.quantile(means, 0.025))
                result[f"{prefix}_{metric}_ci95_high"] = float(np.quantile(means, 0.975))
        output.append(result)
    return output


def _first_block_summary(pieces: list[tuple[list[dict[str, object]], dict[str, np.ndarray]]],
                         tasks: list[tuple[str, int]]) -> list[dict[str, object]]:
    """Summarize the first output block after standard initialization."""
    output: list[dict[str, object]] = []
    for group_index, family in enumerate(FAMILIES):
        for scenario_index, scenario in enumerate(_mask_sets(FAMILIES[family][0])):
            actual = np.stack([arrays[f"standard_{scenario}_observed"][:, 0]
                               for (_rows, arrays), task in zip(pieces, tasks)
                               if task[0] == family]).astype(float)
            ideal = np.stack([arrays[f"standard_{scenario}_ideal"][:, 0]
                              for (_rows, arrays), task in zip(pieces, tasks)
                              if task[0] == family]).astype(float)
            if actual.shape != (len(KEY_INDICES), BASE_IVS * 4):
                raise AssertionError("Unexpected terminal sample shape")
            rng = np.random.default_rng(BOOTSTRAP_SEED + 100 + 10 * group_index + scenario_index)
            indices = rng.integers(0, len(KEY_INDICES),
                                   size=(BOOTSTRAP_REPLICATES, len(KEY_INDICES)))
            record: dict[str, object] = {
                "family": family, "scenario": scenario,
                "warmup_clocks": FAMILIES[family][2], "n_keys": len(KEY_INDICES),
                "comparisons_per_key": actual.shape[1],
            }
            for metric, observed_values, ideal_values in (
                ("mean_hamming_weight", actual.mean(axis=1), ideal.mean(axis=1)),
                ("mean_squared_deviation_from_64", ((actual - 64) ** 2).mean(axis=1),
                 ((ideal - 64) ** 2).mean(axis=1)),
            ):
                diff = observed_values - ideal_values
                for label, values in (("observed", observed_values), ("ideal", ideal_values),
                                      ("difference", diff)):
                    means = values[indices].mean(axis=1)
                    record[f"{label}_{metric}_mean"] = float(values.mean())
                    record[f"{label}_{metric}_ci95_low"] = float(np.quantile(means, 0.025))
                    record[f"{label}_{metric}_ci95_high"] = float(np.quantile(means, 0.975))
            output.append(record)
    return output


def main() -> None:
    tasks = [(family, index) for family in FAMILIES for index in KEY_INDICES]
    with ProcessPoolExecutor(max_workers=4) as executor:
        pieces = list(executor.map(_one_key, tasks))
    rows = [row for group, _arrays in pieces for row in group]
    summary = _summary(rows)
    first_block_summary = _first_block_summary(pieces, tasks)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write_csv(OUTPUT / "standard_iv_per_key.csv", rows)
    _write_csv(OUTPUT / "standard_iv_summary.csv", summary)
    _write_csv(OUTPUT / "standard_iv_first_block_summary.csv", first_block_summary)
    for family in FAMILIES:
        for scenario in _mask_sets(FAMILIES[family][0]):
            keys = [arrays for (group, arrays), task in zip(pieces, tasks) if task[0] == family]
            for condition in CONDITIONS:
                observed = np.stack([item[f"{condition}_{scenario}_observed"] for item in keys])
                ideal = np.stack([item[f"{condition}_{scenario}_ideal"] for item in keys])
                np.savez_compressed(
                    OUTPUT / f"standard_iv_{family.lower().replace('-', '_')}_{condition}_{scenario}_raw.npz",
                    key_indices=np.asarray(KEY_INDICES), observed=observed, ideal=ideal,
                    block_indices=np.arange(BLOCKS),
                    masks=np.asarray([mask.hex() for mask in _mask_sets(FAMILIES[family][0])[scenario]]),
                )
    (OUTPUT / "standard_iv_manifest.json").write_text(json.dumps({
        "analysis": "exploratory_standard_iv_path_validation",
        "master_seed": MASTER_SEED, "key_indices": KEY_INDICES,
        "base_ivs_per_key": BASE_IVS, "nonoverlapping_blocks_per_trajectory": BLOCKS,
        "bits_per_block": BLOCK_BITS, "conditions": CONDITIONS,
        "standard_warmup_clocks": {family: config[2] for family, config in FAMILIES.items()},
        "mask_sets_hex": {family: {name: [mask.hex() for mask in masks]
                                   for name, masks in _mask_sets(config[0]).items()}
                          for family, config in FAMILIES.items()},
        "trajectory_definition": "HW of XOR of 32 consecutive disjoint 128-bit keystream blocks from fixed key and paired IVs",
        "windows": ["full32", "tail16"],
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "numpy": np.__version__,
    }, indent=2) + "\n")
    for row in summary:
        print(row["family"], row["scenario"], row["condition"], row["window"],
              "HMP diff", round(float(row["difference_entropy_mean_power_mean"]), 5),
              "AC diff", round(float(row["difference_entropy_no_dc_normalized_mean"]), 5), flush=True)
    for row in first_block_summary:
        print("standard first block", row["family"], row["scenario"],
              "HW diff", round(float(row["difference_mean_hamming_weight_mean"]), 3), flush=True)


if __name__ == "__main__":
    main()
