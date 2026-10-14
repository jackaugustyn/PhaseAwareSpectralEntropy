#!/usr/bin/env python3
"""Independently audit archived per-mask estimates against raw HW arrays."""

from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

import numpy as np

from explore_mask_spectral_entropy import DATA, INPUTS, OUTPUT
from publication_study import _summarise_trajectories


METRICS = {
    "hmp": "entropy_mean_power",
    "hnodc": "entropy_no_dc_normalized",
    "p0": "dc_share",
    "mean_hw": "mean_hamming_weight",
}


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    per_key = _rows(OUTPUT / "mask_scan_per_key.csv")
    summary = _rows(OUTPUT / "mask_scan_summary.csv")
    comparisons = _rows(OUTPUT / "mask_scan_profile_comparisons.csv")
    tests = _rows(OUTPUT / "mask_scan_standard_max_t.csv")
    small_tests = _rows(OUTPUT / "mask_scan_small_effect_max_t.csv")
    if (len(per_key), len(summary), len(comparisons), len(tests), len(small_tests)) != \
            (29440, 368, 44, 144, 240):
        raise AssertionError("Unexpected output record count")

    manifest = json.loads((OUTPUT / "mask_scan_manifest.json").read_text(encoding="utf-8"))
    profile_manifest = json.loads((OUTPUT / "mask_scan_profile_manifest.json").read_text(encoding="utf-8"))
    for relative, digest in manifest["input_raw_sha256"].items():
        if hashlib.sha256((DATA / relative).read_bytes()).hexdigest() != digest:
            raise AssertionError(f"Changed raw array: {relative}")
    for name, expected in (
        ("mask_scan_per_key.csv", profile_manifest["input_per_key_sha256"]),
        ("mask_scan_profile_comparisons.csv", profile_manifest["comparison_output_sha256"]),
        ("mask_scan_small_effect_max_t.csv", profile_manifest["small_effect_output_sha256"]),
    ):
        if hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest() != expected:
            raise AssertionError(f"Profile manifest mismatch: {name}")

    arrays = {}
    for cohort, cipher, relative in INPUTS:
        with np.load(DATA / relative) as raw:
            control_name = "control" if "control" in raw else "oracle"
            arrays[(cohort, cipher)] = {
                "actual": raw["actual"].copy(), "control": raw[control_name].copy(),
                "configurations": list(map(int, raw["configurations"])),
                "key_indices": list(map(int, raw["key_indices"])),
            }
    for row in random.Random(20261103).sample(per_key, 250):
        item = arrays[(row["cohort"], row["cipher"])]
        config = item["configurations"].index(int(row["configuration"]))
        key = item["key_indices"].index(int(row["key_index"]))
        family = ("single_bit", "localized_four_bit").index(row["mask_family"])
        mask = int(row["mask_number"]) - 1
        for arm in ("actual", "control"):
            trajectories = list(item[arm][key, config, family, mask::4, :])
            direct = _summarise_trajectories(trajectories)
            for short, source in METRICS.items():
                if abs(float(row[f"{arm}_{short}"]) - direct[source]) > 1e-12:
                    raise AssertionError(f"Direct-estimator mismatch: {row}, {arm}, {short}")

    groups = defaultdict(list)
    for row in per_key:
        identity = (row["cohort"], row["cipher"], row["configuration"],
                    row["mask_family"], row["mask_number"])
        groups[identity].append(row)
    for row in summary:
        identity = (row["cohort"], row["cipher"], row["configuration"],
                    row["mask_family"], row["mask_number"])
        values = groups[identity]
        if len(values) != 80 or len({r["key_index"] for r in values}) != 80:
            raise AssertionError(f"Wrong key count for {identity}")
        for metric in METRICS:
            for arm in ("actual", "control", "delta"):
                mean = np.mean([float(r[f"{arm}_{metric}"]) for r in values])
                if abs(mean - float(row[f"{arm}_{metric}_mean"])) > 1e-12:
                    raise AssertionError(f"Summary mismatch: {identity}, {arm}, {metric}")

    def contrast(cohort: str, cipher: str, config: str, family: str,
                 masks: tuple[str, ...], metric: str) -> np.ndarray:
        columns = []
        for mask in masks:
            identity = (cohort, cipher, config, family, mask)
            columns.append([float(row[f"delta_{metric}"]) for row in
                            sorted(groups[identity], key=lambda row: int(row["key_index"]))])
        return np.mean(columns, axis=0)

    for row in comparisons:
        config, metric = row["configuration"], row["metric"]
        if row["label"] == "salsa_minus_chacha_word_gap":
            first = contrast("matched_phase", "ChaCha20", config, "single_bit", ("3", "4"), metric) - \
                    contrast("matched_phase", "ChaCha20", config, "single_bit", ("1", "2"), metric)
            second = contrast("matched_phase", "Salsa20", config, "single_bit", ("3", "4"), metric) - \
                     contrast("matched_phase", "Salsa20", config, "single_bit", ("1", "2"), metric)
        else:
            first = contrast(row["cohort"], row["cipher"], config, row["mask_family"],
                             tuple(row["first_masks"].split(",")), metric)
            second = contrast(row["cohort"], row["cipher"], config, row["mask_family"],
                              tuple(row["second_masks"].split(",")), metric)
        gap = second - first
        for field, expected in (("first_mean", first.mean()), ("second_mean", second.mean()),
                                ("second_minus_first", gap.mean())):
            if abs(float(row[field]) - expected) > 1e-12:
                raise AssertionError(f"Comparison mismatch: {row['label']}, {field}")
        if int(row["positive_keys"]) != int(np.count_nonzero(gap > 0)):
            raise AssertionError(f"Positive-key count mismatch: {row['label']}")
    print("Audited 250 direct raw-array cells, 368 summary cells, 44 paired comparisons, hashes, and counts")


if __name__ == "__main__":
    main()
