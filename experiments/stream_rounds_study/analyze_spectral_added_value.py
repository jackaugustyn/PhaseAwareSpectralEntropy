#!/usr/bin/env python3
"""Quantify spectral redundancy and test equal-moment synthetic trajectories."""

from __future__ import annotations

import csv
import json
import math
from pathlib import Path
import sys

import numpy as np

STUDY_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(STUDY_DIR))

from publication_study import (  # noqa: E402
    FAMILY_DEPTHS,
    SCENARIO_NAMES,
    _bootstrap_mean_ci,
    _key_material,
    _summarise_trajectories,
    _write_csv,
)

RESULT_DIR = STUDY_DIR / "publication_results"
METRICS = [
    "entropy_mean_power",
    "dc_share",
    "ac_dc_ratio",
    "mean_temporal_variance",
    "entropy_no_dc_normalized",
]


def _load_per_key() -> list[dict[str, str]]:
    with (RESULT_DIR / "per_key_metrics.csv").open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _redundancy(rows: list[dict[str, str]]) -> None:
    selected = [
        row
        for row in rows
        if row["trajectory_length"] == "32" and row["family"] != "Ideal-Random-128"
    ]
    matrix = np.asarray([[float(row[metric]) for metric in METRICS] for row in selected])
    correlation = np.corrcoef(matrix, rowvar=False)
    output = [
        {
            "metric_x": METRICS[i],
            "metric_y": METRICS[j],
            "pearson_r": float(correlation[i, j]),
        }
        for i in range(len(METRICS))
        for j in range(i, len(METRICS))
    ]
    _write_csv(RESULT_DIR / "metric_correlations.csv", output)

    target = matrix[:, 0]
    mean_hw = np.asarray([float(row["mean_hamming_weight"]) for row in selected])
    variance = matrix[:, 3]
    design = np.column_stack((np.ones(len(target)), mean_hw, variance))
    coefficients, *_ = np.linalg.lstsq(design, target, rcond=None)
    fitted = design @ coefficients
    r_squared = 1.0 - float(np.sum((target - fitted) ** 2)) / float(
        np.sum((target - np.mean(target)) ** 2)
    )
    physics_predictor = np.log1p(variance / np.maximum(mean_hw**2, 1e-12))
    physics_design = np.column_stack((np.ones(len(target)), physics_predictor))
    physics_coef, *_ = np.linalg.lstsq(physics_design, target, rcond=None)
    physics_fitted = physics_design @ physics_coef
    physics_r_squared = 1.0 - float(np.sum((target - physics_fitted) ** 2)) / float(
        np.sum((target - np.mean(target)) ** 2)
    )
    _write_csv(
        RESULT_DIR / "entropy_regression.csv",
        [
            {
                "model": "linear_mean_hw_plus_variance",
                "r_squared": r_squared,
                "intercept": float(coefficients[0]),
                "coefficient_mean_hw": float(coefficients[1]),
                "coefficient_variance": float(coefficients[2]),
            },
            {
                "model": "log1p_variance_over_mean_squared",
                "r_squared": physics_r_squared,
                "intercept": float(physics_coef[0]),
                "coefficient_mean_hw": "",
                "coefficient_variance": float(physics_coef[1]),
            },
        ],
    )


def _representation_robustness(rows: list[dict[str, str]]) -> None:
    """Summarize two-sided/one-sided agreement and the shallow-cipher ordering."""
    output: list[dict[str, float | int | str]] = []
    for length in (8, 16, 32, 64):
        selected = [
            row for row in rows if int(row["trajectory_length"]) == length
        ]
        hmp = np.asarray([float(row["entropy_mean_power"]) for row in selected])
        hmp_one_sided = np.asarray(
            [float(row["entropy_mean_power_one_sided_weighted"]) for row in selected]
        )
        hnodc = np.asarray(
            [float(row["entropy_no_dc_normalized"]) for row in selected]
        )
        hnodc_one_sided = np.asarray(
            [float(row["entropy_no_dc_one_sided_normalized"]) for row in selected]
        )

        shallow_means = []
        for family, depths in FAMILY_DEPTHS.items():
            values = [
                float(row["entropy_no_dc_normalized"])
                for row in selected
                if row["family"] == family
                and int(row["depth"]) == min(depths)
                and row["scenario"] == "stratified_single_bit"
            ]
            shallow_means.append((family, float(np.mean(values))))
        shallow_means.sort(key=lambda item: item[1])
        trivium_value = next(
            value for family, value in shallow_means if family == "Trivium"
        )
        non_trivium = [item for item in shallow_means if item[0] != "Trivium"]
        next_family, next_value = min(non_trivium, key=lambda item: item[1])

        output.append(
            {
                "trajectory_length": length,
                "key_records": len(selected),
                "pearson_r_hmp_two_vs_one": float(
                    np.corrcoef(hmp, hmp_one_sided)[0, 1]
                ),
                "pearson_r_hnodc_two_vs_one": float(
                    np.corrcoef(hnodc, hnodc_one_sided)[0, 1]
                ),
                "shallow_trivium_hnodc": trivium_value,
                "next_lowest_shallow_family": next_family,
                "next_lowest_shallow_hnodc": next_value,
            }
        )
    _write_csv(RESULT_DIR / "spectral_representation_robustness.csv", output)


def _standardize(row: np.ndarray, mean: float = 64.0, variance: float = 32.0) -> np.ndarray:
    centered = row - np.mean(row)
    sd = float(np.std(centered, ddof=0))
    if sd == 0.0:
        raise ValueError("Synthetic row has zero variance")
    return mean + centered * math.sqrt(variance) / sd


def _pooled_lag1_autocorrelation(trajectories: np.ndarray) -> float:
    """Return the pooled, mean-centered lag-one sample autocorrelation."""
    return float(_pooled_autocorrelations(trajectories, max_lag=1)[0])


def _pooled_autocorrelations(
    trajectories: np.ndarray, max_lag: int = 8
) -> np.ndarray:
    """Return energy-weighted autocorrelations pooled across trajectories."""
    values = np.asarray(trajectories, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] < 2:
        raise ValueError("Expected a two-dimensional array with length >= 2")
    if max_lag < 1 or max_lag >= values.shape[1]:
        raise ValueError("max_lag must be between 1 and trajectory length - 1")
    centered = values - np.mean(values, axis=1, keepdims=True)
    denominator = float(np.sum(centered**2))
    if denominator == 0.0:
        return np.zeros(max_lag, dtype=np.float64)
    return np.asarray(
        [
            float(np.sum(centered[:, :-lag] * centered[:, lag:])) / denominator
            for lag in range(1, max_lag + 1)
        ]
    )


def _pooled_ljung_box_score(
    trajectories: np.ndarray, max_lag: int = 8
) -> float:
    """Return a descriptive pooled Ljung--Box-type multi-lag score."""
    values = np.asarray(trajectories, dtype=np.float64)
    length = values.shape[1] if values.ndim == 2 else 0
    correlations = _pooled_autocorrelations(values, max_lag=max_lag)
    lags = np.arange(1, max_lag + 1, dtype=np.float64)
    return float(
        length
        * (length + 2)
        * np.sum(correlations**2 / (length - lags))
    )


def _synthetic() -> None:
    rng = np.random.default_rng(20260721)
    q, length = 640, 32
    time = np.arange(length)
    collections: dict[str, list[np.ndarray]] = {
        "white_noise": [],
        "sinusoid_k4": [],
        "ar1_phi_0.8": [],
        "single_step": [],
        "monotonic_decay": [],
    }
    for _ in range(q):
        collections["white_noise"].append(_standardize(rng.normal(size=length)))
        phase = rng.uniform(0, 2 * np.pi)
        collections["sinusoid_k4"].append(
            _standardize(np.sin(2 * np.pi * 4 * time / length + phase))
        )
        innovations = rng.normal(size=length)
        ar = np.empty(length)
        ar[0] = innovations[0] / math.sqrt(1.0 - 0.8**2)
        for index in range(1, length):
            ar[index] = 0.8 * ar[index - 1] + innovations[index]
        collections["ar1_phi_0.8"].append(_standardize(ar))
        shift = int(rng.integers(0, length))
        collections["single_step"].append(
            _standardize(np.roll(np.r_[-np.ones(length // 2), np.ones(length // 2)], shift))
        )
        decay = np.exp(-time / 6.0)
        if rng.random() < 0.5:
            decay = decay[::-1]
        collections["monotonic_decay"].append(_standardize(decay))

    rows: list[dict[str, float | int | str]] = []
    for name, trajectories in collections.items():
        row: dict[str, float | int | str] = {"signal": name}
        row.update(_summarise_trajectories(trajectories))
        row["lag1_autocorrelation"] = _pooled_lag1_autocorrelation(
            np.asarray(trajectories)
        )
        row["ljung_box_q8"] = _pooled_ljung_box_score(np.asarray(trajectories))
        rows.append(row)
    _write_csv(RESULT_DIR / "synthetic_equal_moments.csv", rows)


def _temporal_comparison(rows: list[dict[str, str]]) -> None:
    """Compare DC-excluded entropy with a pooled lag-one autocorrelation."""
    trajectory_length = 32
    manifest = json.loads((RESULT_DIR / "manifest.json").read_text(encoding="utf-8"))
    master_seed = int(manifest["master_seed"])
    independent_keys = int(manifest["independent_keys"])
    base_states = int(manifest["base_states_per_key"])
    lookup = {
        (
            row["family"],
            int(row["depth"]),
            row["scenario"],
            int(row["trajectory_length"]),
            int(row["key_index"]),
        ): row
        for row in rows
    }
    output: list[dict[str, float | int | str]] = []

    for family, depths in FAMILY_DEPTHS.items():
        safe_family = family.lower().replace("/", "").replace("-", "_")
        for depth in depths:
            for scenario in SCENARIO_NAMES:
                path = (
                    RESULT_DIR
                    / "raw_trajectories"
                    / f"{safe_family}_d{depth}_{scenario}_t{trajectory_length}.npz"
                )
                with np.load(path) as archive:
                    raw = archive["hamming_weight_trajectories"]
                    key_indices = archive["key_indices"]
                for array_index, key_index_value in enumerate(key_indices):
                    key_index = int(key_index_value)
                    metric_row = lookup[
                        (family, depth, scenario, trajectory_length, key_index)
                    ]
                    output.append(
                        {
                            "family": family,
                            "depth": depth,
                            "scenario": scenario,
                            "trajectory_length": trajectory_length,
                            "key_index": key_index,
                            "trajectory_count": raw.shape[1],
                            "entropy_no_dc_normalized": float(
                                metric_row["entropy_no_dc_normalized"]
                            ),
                            "lag1_autocorrelation": _pooled_lag1_autocorrelation(
                                raw[array_index]
                            ),
                            "ljung_box_q8": _pooled_ljung_box_score(
                                raw[array_index]
                            ),
                        }
                    )

    for scenario in SCENARIO_NAMES:
        for key_index in range(independent_keys):
            metric_row = lookup[
                ("Ideal-Random-128", 0, scenario, trajectory_length, key_index)
            ]
            _, rng = _key_material(master_seed + 1_000_000, key_index)
            trajectory_count = base_states * int(metric_row["masks"])
            trajectories = np.asarray(
                [
                    rng.binomial(128, 0.5, size=trajectory_length)
                    for _ in range(trajectory_count)
                ]
            )
            output.append(
                {
                    "family": "Ideal-Random-128",
                    "depth": 0,
                    "scenario": scenario,
                    "trajectory_length": trajectory_length,
                    "key_index": key_index,
                    "trajectory_count": trajectory_count,
                    "entropy_no_dc_normalized": float(
                        metric_row["entropy_no_dc_normalized"]
                    ),
                    "lag1_autocorrelation": _pooled_lag1_autocorrelation(
                        trajectories
                    ),
                    "ljung_box_q8": _pooled_ljung_box_score(trajectories),
                }
            )

    output.sort(
        key=lambda row: (
            str(row["family"]),
            int(row["depth"]),
            str(row["scenario"]),
            int(row["key_index"]),
        )
    )
    _write_csv(RESULT_DIR / "temporal_comparison_per_key.csv", output)

    identity = ("family", "depth", "scenario", "trajectory_length")
    groups: dict[tuple[object, ...], list[dict[str, float | int | str]]] = {}
    for row in output:
        groups.setdefault(tuple(row[name] for name in identity), []).append(row)

    summaries: list[dict[str, float | int | str]] = []
    for group_index, (key, group) in enumerate(sorted(groups.items(), key=str)):
        summary: dict[str, float | int | str] = dict(zip(identity, key))
        summary["independent_keys"] = len(group)
        for metric_index, metric in enumerate(
            (
                "entropy_no_dc_normalized",
                "lag1_autocorrelation",
                "ljung_box_q8",
            )
        ):
            values = np.asarray([float(row[metric]) for row in group])
            low, high = _bootstrap_mean_ci(
                values,
                master_seed + 4_000_000 + group_index * 10 + metric_index,
            )
            summary[f"{metric}_mean"] = float(np.mean(values))
            summary[f"{metric}_sd_between_keys"] = float(np.std(values, ddof=1))
            summary[f"{metric}_ci_low"] = low
            summary[f"{metric}_ci_high"] = high
        summaries.append(summary)
    _write_csv(RESULT_DIR / "temporal_comparison_summary.csv", summaries)

    cipher_rows = [row for row in output if row["family"] != "Ideal-Random-128"]
    cipher_cells = [
        row for row in summaries if row["family"] != "Ideal-Random-128"
    ]
    statistics = []
    for scope, selected in (
        ("cipher_key_records", cipher_rows),
        ("cipher_cell_means", cipher_cells),
    ):
        suffix = "" if scope == "cipher_key_records" else "_mean"
        matrix = np.asarray(
            [
                [
                    float(row[f"entropy_no_dc_normalized{suffix}"]),
                    float(row[f"lag1_autocorrelation{suffix}"]),
                    float(row[f"ljung_box_q8{suffix}"]),
                ]
                for row in selected
            ]
        )
        statistics.append(
            {
                "scope": scope,
                "records": len(selected),
                "pearson_r_hnodc_vs_lag1": float(
                    np.corrcoef(matrix[:, 0], matrix[:, 1])[0, 1]
                ),
                "pearson_r_hnodc_vs_ljung_box_q8": float(
                    np.corrcoef(matrix[:, 0], matrix[:, 2])[0, 1]
                ),
            }
        )
    _write_csv(RESULT_DIR / "temporal_comparison_statistics.csv", statistics)


def _analytic_ideal() -> None:
    mean, variance = 64.0, 32.0
    rows = []
    for length in (8, 16, 32, 64):
        dc = length**2 * mean**2 + length * variance
        non_dc_bin = length * variance
        total = dc + (length - 1) * non_dc_bin
        distribution = np.asarray([dc] + [non_dc_bin] * (length - 1)) / total
        entropy = float(-np.sum(distribution * np.log2(distribution)))
        rows.append(
            {
                "trajectory_length": length,
                "expected_dc_power": dc,
                "expected_non_dc_power_per_bin": non_dc_bin,
                "expected_dc_share": dc / total,
                "expected_ac_dc_ratio": (total - dc) / dc,
                "entropy_of_expected_power": entropy,
            }
        )
    _write_csv(RESULT_DIR / "ideal_random_analytic.csv", rows)


def main() -> None:
    rows = _load_per_key()
    _redundancy(rows)
    _representation_robustness(rows)
    _synthetic()
    _temporal_comparison(rows)
    _analytic_ideal()


if __name__ == "__main__":
    main()
