#!/usr/bin/env python3
"""Reproducible retrospective per-mask spectral scan for the reviewer archive."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "doc_stream_ciphers"
DATA = PAPER / "data"
OUTPUT = PAPER / "analysis" / "mask_scan_results"
BOOTSTRAP_REPLICATES = 5000
BOOTSTRAP_SEED = 20261029
SIGN_FLIPS = 20_000
SIGN_SEED = 20261030
MASK_FAMILIES = ("single_bit", "localized_four_bit")
METRICS = ("hmp", "hnodc", "p0", "mean_hw")

INPUTS = (
    ("unified_six", "Grain-128", "unified_six_results/unified_six_grain_128_raw.npz"),
    ("unified_six", "Trivium", "unified_six_results/unified_six_trivium_raw.npz"),
    ("unified_six", "MICKEY 2.0", "unified_six_results/unified_six_mickey_2.0_raw.npz"),
    ("unified_six", "HC-128", "unified_six_results/unified_six_hc_128_raw.npz"),
    ("unified_six", "Rabbit", "unified_six_results/unified_six_rabbit_raw.npz"),
    ("unified_six", "ChaCha20", "unified_six_results/unified_six_chacha20_raw.npz"),
    ("salsa_transfer", "Salsa20", "salsa20_transfer_results/salsa20_transfer_raw.npz"),
    ("matched_phase", "ChaCha20", "matched_nonce_phase_results/matched_phase_chacha20_raw.npz"),
    ("matched_phase", "Salsa20", "matched_nonce_phase_results/matched_phase_salsa20_raw.npz"),
)


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _positions(hex_mask: str) -> str:
    data = bytes.fromhex(hex_mask)
    return ",".join(str(i * 8 + j) for i, byte in enumerate(data)
                    for j in range(8) if byte & (1 << (7 - j)))


def _spectral(values: np.ndarray) -> dict[str, np.ndarray]:
    """Average four base-IV powers per mask, then normalize; T is always 32.

    The trailing axes are mask, base IV, and 32 successive Hamming weights.
    """
    if values.ndim != 6 or values.shape[-3:] != (4, 4, 32):
        raise AssertionError(f"Wrong grouped HW shape: {values.shape}")
    power = np.mean(np.abs(np.fft.fft(values.astype(np.float64), axis=-1)) ** 2, axis=-2)
    weights = power / power.sum(axis=-1, keepdims=True)
    positive = np.where(weights > 0, weights, 1.0)
    hmp = -np.sum(weights * np.log2(positive), axis=-1)
    ac_total = power[..., 1:].sum(axis=-1, keepdims=True)
    ac = np.divide(power[..., 1:], ac_total, out=np.zeros_like(power[..., 1:]), where=ac_total > 0)
    positive_ac = np.where(ac > 0, ac, 1.0)
    hnodc = -np.sum(ac * np.log2(positive_ac), axis=-1) / np.log2(31)
    return {"hmp": hmp, "hnodc": hnodc, "p0": weights[..., 0],
            "mean_hw": values.mean(axis=(-2, -1))}


def _group_by_mask(values: np.ndarray) -> np.ndarray:
    """Convert base-major pair order into mask-major groups of four base IVs."""
    if values.shape[-2:] != (16, 32):
        raise AssertionError(f"Wrong raw HW shape: {values.shape}")
    grouped = values.reshape(*values.shape[:-2], 4, 4, 32).swapaxes(-3, -2)
    for mask in range(4):
        if not np.array_equal(grouped[..., mask, :, :], values[..., mask::4, :]):
            raise AssertionError("Mask grouping does not match direct strided selection")
    return grouped


def _whole_power_invariant(values: np.ndarray) -> None:
    """Four mask powers average back to the article's 16-pair power vector."""
    grouped = _group_by_mask(values).astype(np.float64)
    per_mask = np.mean(np.abs(np.fft.fft(grouped, axis=-1)) ** 2, axis=-2)
    direct = np.mean(np.abs(np.fft.fft(values.astype(np.float64), axis=-1)) ** 2, axis=-2)
    if not np.allclose(per_mask.mean(axis=-2), direct, atol=1e-8, rtol=1e-12):
        raise AssertionError("Per-mask powers do not reconstruct 16-pair powers")


def _scan() -> tuple[list[dict[str, object]], list[dict[str, object]],
                     dict[str, list[tuple[dict[str, object], np.ndarray]]], dict[str, str]]:
    per_key: list[dict[str, object]] = []
    summary: list[dict[str, object]] = []
    standard: dict[str, list[tuple[dict[str, object], np.ndarray]]] = {
        "unified_six": [], "salsa_transfer": [], "matched_phase": []}
    source_hashes: dict[str, str] = {}
    for cohort, cipher, relative in INPUTS:
        path = DATA / relative
        source_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        with np.load(path) as raw:
            configs = [int(x) for x in raw["configurations"]]
            indices = [int(x) for x in raw["key_indices"]]
            if len(indices) != 80 or raw["actual"].shape != (80, len(configs), 2, 16, 32):
                raise AssertionError(f"Wrong source array shape: {path}")
            reference_name = "control" if "control" in raw else "oracle"
            observed = raw["actual"]
            control = raw[reference_name]
            if control.shape != observed.shape:
                raise AssertionError("Observed and control shapes differ")
            _whole_power_invariant(observed)
            _whole_power_invariant(control)
            actual_metrics = _spectral(_group_by_mask(observed))
            control_metrics = _spectral(_group_by_mask(control))
            masks = {family: raw[f"masks_{family}"].tolist() for family in MASK_FAMILIES}
        for config_offset, config in enumerate(configs):
            is_standard = int(config == configs[-1])
            for family_offset, mask_family in enumerate(MASK_FAMILIES):
                samples = np.random.default_rng(
                    BOOTSTRAP_SEED + len(summary)).integers(0, 80, size=(BOOTSTRAP_REPLICATES, 80))
                for mask_offset, hex_mask in enumerate(masks[mask_family]):
                    metadata: dict[str, object] = {
                        "cohort": cohort, "cipher": cipher, "configuration": config,
                        "is_standard": is_standard, "mask_family": mask_family,
                        "mask_number": mask_offset + 1, "mask_hex": hex_mask,
                        "bit_positions_msb0": _positions(hex_mask),
                        "n_keys": 80, "pairs_per_key": 4, "blocks_per_pair": 32,
                    }
                    key_values: dict[str, np.ndarray] = {}
                    for metric in METRICS:
                        a = actual_metrics[metric][:, config_offset, family_offset, mask_offset]
                        c = control_metrics[metric][:, config_offset, family_offset, mask_offset]
                        key_values[metric] = a - c
                    record = dict(metadata)
                    for metric in METRICS:
                        a = actual_metrics[metric][:, config_offset, family_offset, mask_offset]
                        c = control_metrics[metric][:, config_offset, family_offset, mask_offset]
                        d = key_values[metric]
                        boot = d[samples].mean(axis=1)
                        record[f"actual_{metric}_mean"] = float(a.mean())
                        record[f"control_{metric}_mean"] = float(c.mean())
                        record[f"delta_{metric}_mean"] = float(d.mean())
                        record[f"delta_{metric}_ci95_low"] = float(np.quantile(boot, 0.025))
                        record[f"delta_{metric}_ci95_high"] = float(np.quantile(boot, 0.975))
                    summary.append(record)
                    for key_offset, key_index in enumerate(indices):
                        row = {"cohort": cohort, "cipher": cipher, "configuration": config,
                               "is_standard": is_standard, "mask_family": mask_family,
                               "mask_number": mask_offset + 1, "mask_hex": hex_mask,
                               "key_index": key_index}
                        for metric in METRICS:
                            row[f"actual_{metric}"] = float(actual_metrics[metric][
                                key_offset, config_offset, family_offset, mask_offset])
                            row[f"control_{metric}"] = float(control_metrics[metric][
                                key_offset, config_offset, family_offset, mask_offset])
                            row[f"delta_{metric}"] = float(key_values[metric][key_offset])
                        per_key.append(row)
                    if is_standard:
                        for metric in ("hmp", "hnodc"):
                            standard[cohort].append((dict(metadata, metric=metric), key_values[metric]))
    return per_key, summary, standard, source_hashes


def _max_t(standard: dict[str, list[tuple[dict[str, object], np.ndarray]]]) -> list[dict[str, object]]:
    groups = []
    meta = []
    for cohort in ("unified_six", "salsa_transfer", "matched_phase"):
        columns = standard[cohort]
        matrix = np.column_stack([values for _record, values in columns])
        if matrix.shape[0] != 80:
            raise AssertionError("Wrong key count for sign flips")
        means = matrix.mean(axis=0)
        denominator = matrix.std(axis=0, ddof=1) / np.sqrt(80)
        if np.any(denominator == 0):
            raise AssertionError("Zero variance in standard mask endpoint")
        groups.append((matrix, denominator, means / denominator))
        meta.extend(record for record, _values in columns)
    observed = np.concatenate([item[2] for item in groups])
    abs_observed = np.abs(observed)
    unadjusted = np.zeros(len(observed), dtype=np.int64)
    adjusted = np.zeros(len(observed), dtype=np.int64)
    rng = np.random.default_rng(SIGN_SEED)
    for _ in range(SIGN_FLIPS // 1000):
        null = []
        for matrix, denominator, _obs in groups:
            signs = rng.integers(0, 2, size=(1000, 80), dtype=np.int8).astype(np.float64) * 2 - 1
            null.append(np.abs((signs @ matrix) / 80 / denominator))
        deviations = np.concatenate(null, axis=1)
        maximum = deviations.max(axis=1)
        unadjusted += np.count_nonzero(deviations >= abs_observed, axis=0)
        adjusted += np.count_nonzero(maximum[:, None] >= abs_observed, axis=0)
    output = []
    for index, record in enumerate(meta):
        output.append({
            "cohort": record["cohort"], "cipher": record["cipher"],
            "configuration": record["configuration"],
            "mask_family": record["mask_family"], "mask_number": record["mask_number"],
            "mask_hex": record["mask_hex"], "metric": record["metric"],
            "n_keys": 80, "t_observed": float(observed[index]),
            "p_sign_flip_unadjusted": float((unadjusted[index] + 1) / (SIGN_FLIPS + 1)),
            "p_max_t_familywise_144": float((adjusted[index] + 1) / (SIGN_FLIPS + 1)),
        })
    return output


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    per_key, summary, standard, source_hashes = _scan()
    tests = _max_t(standard)
    _write_csv(OUTPUT / "mask_scan_per_key.csv", per_key)
    _write_csv(OUTPUT / "mask_scan_summary.csv", summary)
    _write_csv(OUTPUT / "mask_scan_standard_max_t.csv", tests)
    manifest = {
        "analysis": "exploratory_per_mask_spectral_entropy_scan",
        "status": "post_hoc_descriptive_results_in_manuscript",
        "input_raw_sha256": source_hashes,
        "cohorts": ["unified_six", "salsa_transfer", "matched_phase"],
        "mask_families": MASK_FAMILIES, "masks_per_family": 4,
        "pairs_per_key_per_mask": 4, "blocks_per_pair": 32,
        "spectral_estimator": "average four complete two-sided 32-point DFT power vectors before entropy normalization",
        "bootstrap_replicates": BOOTSTRAP_REPLICATES, "bootstrap_seed": BOOTSTRAP_SEED,
        "standard_max_t_endpoints": len(tests), "sign_flips": SIGN_FLIPS,
        "sign_seed": SIGN_SEED,
        "multiple_testing": "maximum absolute studentized whole-key sign flip across 144 standard mask HMP/HnoDC endpoints; independent signs for disjoint cohorts, shared signs within cohort",
    }
    (OUTPUT / "mask_scan_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Scanned {len(per_key)} key-mask records and {len(summary)} mask/configuration cells")
    for mode, rows in (("standard", [r for r in summary if r["is_standard"]]),
                       ("reduced", [r for r in summary if not r["is_standard"]])):
        for metric in ("hmp", "hnodc"):
            best = max(rows, key=lambda row: abs(float(row[f"delta_{metric}_mean"])))
            print(mode, metric, "max absolute mean", best["cohort"], best["cipher"],
                  best["configuration"], best["mask_family"], best["mask_number"],
                  f"{best[f'delta_{metric}_mean']:+.6f}")
    winner = min(tests, key=lambda row: row["p_max_t_familywise_144"])
    print("Minimum standard-mask familywise p:", winner["p_max_t_familywise_144"],
          winner["cipher"], winner["metric"])


if __name__ == "__main__":
    main()
