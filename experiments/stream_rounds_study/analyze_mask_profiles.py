#!/usr/bin/env python3
"""Reproduce descriptive mask comparisons from the exploratory per-key scan."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / "doc_stream_ciphers" / "analysis" / "mask_scan_results"
KEY_INPUT = DIRECTORY / "mask_scan_per_key.csv"
COMPARISON_OUTPUT = DIRECTORY / "mask_scan_profile_comparisons.csv"
WEAK_TEST_OUTPUT = DIRECTORY / "mask_scan_small_effect_max_t.csv"
MANIFEST_OUTPUT = DIRECTORY / "mask_scan_profile_manifest.json"
BOOTSTRAP_REPLICATES = 5000
BOOTSTRAP_SEED = 20261101
SIGN_FLIPS = 200_000
SIGN_SEED = 20261102


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _read() -> dict[tuple[str, str, int, str, int], dict[int, dict[str, str]]]:
    """Index retrospective per-mask scores and reject missing/duplicate keys."""
    cells: dict[tuple[str, str, int, str, int], dict[int, dict[str, str]]] = defaultdict(dict)
    with KEY_INPUT.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            identity = (row["cohort"], row["cipher"], int(row["configuration"]),
                        row["mask_family"], int(row["mask_number"]))
            key = int(row["key_index"])
            if key in cells[identity]:
                raise AssertionError(f"Duplicate key {key} for {identity}")
            cells[identity][key] = row
    if len(cells) != 368 or any(len(keys) != 80 for keys in cells.values()):
        raise AssertionError("Wrong per-mask cell or key count")
    return cells


def _series(cells: dict, cohort: str, cipher: str, configuration: int,
            family: str, masks: tuple[int, ...], metric: str) -> tuple[np.ndarray, np.ndarray]:
    """Average selected masks per key while retaining key pairing."""
    arms = [cells[(cohort, cipher, configuration, family, mask)] for mask in masks]
    indices = np.array(sorted(arms[0]))
    if any(sorted(arm) != list(indices) for arm in arms):
        raise AssertionError("Mask groups have different key indices")
    values = np.array([[float(arm[int(key)][f"delta_{metric}"]) for key in indices]
                       for arm in arms]).mean(axis=0)
    return indices, values


def _comparison(label: str, cohort: str, cipher: str, configuration: int,
                family: str, first_masks: tuple[int, ...], second_masks: tuple[int, ...],
                metric: str, cells: dict, seed_offset: int) -> dict[str, object]:
    first_keys, first = _series(cells, cohort, cipher, configuration, family, first_masks, metric)
    second_keys, second = _series(cells, cohort, cipher, configuration, family, second_masks, metric)
    if not np.array_equal(first_keys, second_keys):
        raise AssertionError("Paired comparison uses different keys")
    difference = second - first
    samples = np.random.default_rng(BOOTSTRAP_SEED + seed_offset).integers(
        0, len(difference), size=(BOOTSTRAP_REPLICATES, len(difference)))
    bootstrap = difference[samples].mean(axis=1)
    low, high = np.quantile(bootstrap, [0.025, 0.975])
    return {
        "label": label, "cohort": cohort, "cipher": cipher,
        "configuration": configuration, "mask_family": family,
        "first_masks": ",".join(map(str, first_masks)),
        "second_masks": ",".join(map(str, second_masks)),
        "metric": metric, "n_keys": len(difference),
        "first_mean": float(first.mean()), "second_mean": float(second.mean()),
        "second_minus_first": float(difference.mean()),
        "ci95_low": float(low), "ci95_high": float(high),
        "positive_keys": int(np.count_nonzero(difference > 0)),
        "status": "post_hoc_descriptive_pointwise_interval",
    }


def _cross_core(cells: dict, configuration: int, metric: str, seed_offset: int) -> dict[str, object]:
    indices = []
    gaps = []
    for cipher in ("ChaCha20", "Salsa20"):
        first_keys, first = _series(cells, "matched_phase", cipher, configuration,
                                    "single_bit", (1, 2), metric)
        second_keys, second = _series(cells, "matched_phase", cipher, configuration,
                                      "single_bit", (3, 4), metric)
        if not np.array_equal(first_keys, second_keys):
            raise AssertionError("Different word-group key indices")
        indices.append(first_keys)
        gaps.append(second - first)
    if not np.array_equal(indices[0], indices[1]):
        raise AssertionError("Cross-core comparison needs paired master-key indices")
    difference = gaps[1] - gaps[0]
    samples = np.random.default_rng(BOOTSTRAP_SEED + seed_offset).integers(
        0, len(difference), size=(BOOTSTRAP_REPLICATES, len(difference)))
    low, high = np.quantile(difference[samples].mean(axis=1), [0.025, 0.975])
    return {
        "label": "salsa_minus_chacha_word_gap", "cohort": "matched_phase",
        "cipher": "Salsa20 minus ChaCha20", "configuration": configuration,
        "mask_family": "single_bit", "first_masks": "1,2 vs 3,4",
        "second_masks": "1,2 vs 3,4", "metric": metric, "n_keys": 80,
        "first_mean": float(gaps[0].mean()), "second_mean": float(gaps[1].mean()),
        "second_minus_first": float(difference.mean()),
        "ci95_low": float(low), "ci95_high": float(high),
        "positive_keys": int(np.count_nonzero(difference > 0)),
        "status": "post_hoc_descriptive_pointwise_interval",
    }


def _comparisons(cells: dict) -> list[dict[str, object]]:
    plans = []
    for configuration in (0, 32, 64):
        plans.append(("grain_bit64_minus_bit0", "unified_six", "Grain-128",
                      configuration, "single_bit", (1,), (3,)))
    plans.append(("grain_window61_64_minus_0_3", "unified_six", "Grain-128",
                  0, "localized_four_bit", (1,), (3,)))
    for configuration in (0, 64, 128, 192, 384):
        plans.append(("trivium_bit0_minus_bit79", "unified_six", "Trivium",
                      configuration, "single_bit", (4,), (1,)))
    plans.append(("trivium_window0_3_minus_76_79", "unified_six", "Trivium",
                  64, "localized_four_bit", (4,), (1,)))
    for cohort, cipher, configurations in (
        ("salsa_transfer", "Salsa20", (2, 4, 20)),
        ("matched_phase", "ChaCha20", (2, 4, 20)),
        ("matched_phase", "Salsa20", (2, 4, 20)),
    ):
        for configuration in configurations:
            plans.append(("second_nonce_word_minus_first", cohort, cipher,
                          configuration, "single_bit", (1, 2), (3, 4)))
    output = []
    for plan in plans:
        for metric in ("hmp", "hnodc"):
            output.append(_comparison(*plan, metric, cells, len(output)))
    for configuration in (2, 4, 20):
        for metric in ("hmp", "hnodc"):
            output.append(_cross_core(cells, configuration, metric, len(output)))
    return output


def _small_effect_max_t(cells: dict) -> list[dict[str, object]]:
    columns = []
    labels = []
    for identity in sorted(cells):
        cohort, cipher, configuration, family, mask = identity
        if cohort != "unified_six" or cipher not in ("MICKEY 2.0", "HC-128", "Rabbit"):
            continue
        for metric in ("hmp", "hnodc"):
            indices = sorted(cells[identity])
            columns.append([float(cells[identity][key][f"delta_{metric}"]) for key in indices])
            labels.append((*identity, metric))
    matrix = np.asarray(columns, dtype=np.float64).T
    if matrix.shape != (80, 240):
        raise AssertionError(f"Unexpected small-effect test matrix {matrix.shape}")
    denominator = matrix.std(axis=0, ddof=1) / np.sqrt(80)
    observed = matrix.mean(axis=0) / denominator
    counts = np.zeros(len(labels), dtype=np.int64)
    rng = np.random.default_rng(SIGN_SEED)
    for _ in range(SIGN_FLIPS // 1000):
        signs = rng.integers(0, 2, size=(1000, 80), dtype=np.int8).astype(np.float64) * 2 - 1
        maximum = np.abs((signs @ matrix) / 80 / denominator).max(axis=1)
        counts += np.count_nonzero(maximum[:, None] >= np.abs(observed), axis=0)
    output = []
    for label, t_stat, count, values in zip(labels, observed, counts, matrix.T):
        cohort, cipher, configuration, family, mask, metric = label
        output.append({
            "cohort": cohort, "cipher": cipher, "configuration": configuration,
            "mask_family": family, "mask_number": mask, "metric": metric,
            "n_keys": 80, "delta_mean": float(values.mean()),
            "t_observed": float(t_stat),
            "p_max_t_familywise_240": float((count + 1) / (SIGN_FLIPS + 1)),
            "sign_flips": SIGN_FLIPS,
            "status": "post_hoc_exploratory_family",
        })
    return output


def main() -> None:
    """Rebuild descriptive mask-comparison tables and their hash manifest."""
    cells = _read()
    comparisons = _comparisons(cells)
    weak_tests = _small_effect_max_t(cells)
    _write_csv(COMPARISON_OUTPUT, comparisons)
    _write_csv(WEAK_TEST_OUTPUT, weak_tests)
    manifest = {
        "analysis": "retrospective_mask_profile_comparisons",
        "status": "post_hoc_descriptive_not_planned_inference",
        "input_per_key_sha256": hashlib.sha256(KEY_INPUT.read_bytes()).hexdigest(),
        "comparison_output_sha256": hashlib.sha256(COMPARISON_OUTPUT.read_bytes()).hexdigest(),
        "small_effect_output_sha256": hashlib.sha256(WEAK_TEST_OUTPUT.read_bytes()).hexdigest(),
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "small_effect_family": "MICKEY 2.0, HC-128, Rabbit; five settings times eight masks times two metrics each",
        "small_effect_max_t_endpoints": len(weak_tests),
        "sign_flips": SIGN_FLIPS,
        "sign_seed": SIGN_SEED,
    }
    MANIFEST_OUTPUT.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(comparisons)} paired descriptive comparisons")
    winner = min(weak_tests, key=lambda row: row["p_max_t_familywise_240"])
    print("Small-effect-family minimum maxT p:", winner["p_max_t_familywise_240"],
          winner["cipher"], winner["configuration"], winner["mask_family"],
          winner["mask_number"], winner["metric"])


if __name__ == "__main__":
    main()
