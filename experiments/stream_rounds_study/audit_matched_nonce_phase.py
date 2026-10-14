#!/usr/bin/env python3
"""Independently recompute matched-nonce phase results from archived arrays."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "doc_stream_ciphers" / "data" / "matched_nonce_phase_results"
PROTOCOL = ROOT / "doc_stream_ciphers" / "MATCHED_NONCE_PHASE_PROTOCOL.txt"
FAMILIES = ("ChaCha20", "Salsa20")
CONFIGS = (2, 4, 20)
SCENARIOS = ("single_bit", "localized_four_bit")
KEY_INDICES = tuple(range(440, 520))


def _rows(name: str) -> list[dict[str, str]]:
    with (DATA / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _spectral(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x = np.asarray(values, dtype=np.float64)
    transformed = np.fft.fft(x, axis=-1)
    power = np.einsum("...qt,...qt->...t", transformed.real, transformed.real) + \
            np.einsum("...qt,...qt->...t", transformed.imag, transformed.imag)
    power = power / x.shape[-2]
    probabilities = power / power.sum(axis=-1, keepdims=True)
    entropy = -np.sum(np.where(probabilities > 0,
                               probabilities * np.log2(np.maximum(probabilities, 1e-300)), 0), axis=-1)
    ac = power[..., 1:] / power[..., 1:].sum(axis=-1, keepdims=True)
    hnodc = -np.sum(np.where(ac > 0, ac * np.log2(np.maximum(ac, 1e-300)), 0), axis=-1) / \
            np.log2(x.shape[-1] - 1)
    return entropy, probabilities[..., 0], hnodc


def _rotate(values: np.ndarray, shifts: np.ndarray) -> np.ndarray:
    x = values.reshape(16, 8, 4)
    options = np.stack([np.roll(x, -offset, axis=-1) for offset in range(4)])
    return options[shifts, np.arange(16)[None, :, None], np.arange(8)[None, None, :], :].reshape(128, 16, 32)


def _phase(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    means = values.reshape(*values.shape[:-2], 16, 8, 4).mean(axis=(-3, -2))
    return means, means.max(axis=-1) - means.min(axis=-1)


def _check(row: dict[str, str], field: str, computed: float) -> None:
    if abs(float(row[field]) - computed) > 1e-10:
        raise AssertionError((row["family"], row["key_index"], row["configuration"], row["scenario"], field,
                              row[field], computed))


def main() -> None:
    manifest = json.loads((DATA / "matched_nonce_phase_manifest.json").read_text())
    assert hashlib.sha256(PROTOCOL.read_bytes()).hexdigest() == manifest["protocol_sha256"]
    assert manifest["master_key_indices"] == list(KEY_INDICES)
    assert manifest["rotation_replicates"] == 128
    records = _rows("matched_nonce_phase_per_key.csv")
    by_cell = {(row["family"], int(row["key_index"]), int(row["configuration"]), row["scenario"]): row
               for row in records}
    assert len(by_cell) == len(records) == 2 * 80 * 3 * 2
    for family in FAMILIES:
        with np.load(DATA / f"matched_phase_{family.lower()}_raw.npz") as raw:
            actual, control, rotations = raw["actual"], raw["control"], raw["rotations"]
            assert actual.shape == control.shape == (80, 3, 2, 16, 32)
            assert rotations.shape == (80, 3, 2, 128, 16, 8)
            assert raw["key_indices"].tolist() == list(KEY_INDICES)
            assert raw["configurations"].tolist() == list(CONFIGS)
            assert actual.min() >= 0 and actual.max() <= 128
            assert control.min() >= 0 and control.max() <= 128
            assert rotations.min() == 0 and rotations.max() == 3
            for key_offset, key_index in enumerate(KEY_INDICES):
                for config_offset, config in enumerate(CONFIGS):
                    for scenario_offset, scenario in enumerate(SCENARIOS):
                        row = by_cell[family, key_index, config, scenario]
                        shifts = rotations[key_offset, config_offset, scenario_offset]
                        derived: dict[str, float] = {}
                        drifts = []
                        for label, matrix in (("actual", actual[key_offset, config_offset, scenario_offset]),
                                              ("control", control[key_offset, config_offset, scenario_offset])):
                            hmp, p0, hnodc = _spectral(matrix)
                            positions, phase_range = _phase(matrix)
                            rotated = _rotate(matrix, shifts)
                            if not np.array_equal(np.sort(rotated, axis=-1),
                                                  np.broadcast_to(np.sort(matrix, axis=-1), rotated.shape)):
                                raise AssertionError("Rotation changed a trajectory's values")
                            rhmp, rp0, rhnodc = _spectral(rotated)
                            _rpositions, rphase_range = _phase(rotated)
                            drift = float(np.max(np.abs(rp0 - p0)))
                            assert drift < 1e-12
                            drifts.append(drift)
                            derived[f"{label}_hmp_original"] = float(hmp)
                            derived[f"{label}_hnodc_original"] = float(hnodc)
                            derived[f"{label}_p0"] = float(p0)
                            derived[f"{label}_hmp_rotated"] = float(np.mean(rhmp))
                            derived[f"{label}_hnodc_rotated"] = float(np.mean(rhnodc))
                            derived[f"{label}_phase_range_original"] = float(phase_range)
                            derived[f"{label}_phase_range_rotated"] = float(np.mean(rphase_range))
                            for i, mean in enumerate(positions, 1):
                                derived[f"{label}_position_{i}_mean_hw"] = float(mean)
                        derived["max_p0_rotation_drift"] = max(drifts)
                        for field in ("hmp_original", "hmp_rotated", "hnodc_original", "hnodc_rotated",
                                      "p0", "phase_range_original", "phase_range_rotated"):
                            derived[f"delta_{field}"] = derived[f"actual_{field}"] - derived[f"control_{field}"]
                        derived["alignment_loss_hmp"] = derived["delta_hmp_original"] - derived["delta_hmp_rotated"]
                        derived["alignment_loss_hnodc"] = derived["delta_hnodc_original"] - \
                                                           derived["delta_hnodc_rotated"]
                        for field, value in derived.items():
                            _check(row, field, value)
    summaries = _rows("matched_nonce_phase_summary.csv")
    assert len(summaries) == 2 * 3 * 2
    for summary in summaries:
        group = [by_cell[summary["family"], key, int(summary["configuration"]), summary["scenario"]]
                 for key in KEY_INDICES]
        for field, value in summary.items():
            if field.endswith("_mean") and field[:-5] in group[0]:
                assert abs(float(value) - np.mean([float(row[field[:-5]]) for row in group])) < 1e-11
    comparisons = _rows("matched_nonce_phase_cross_core.csv")
    assert len(comparisons) == 3 * 2
    for comparison in comparisons:
        config, scenario = int(comparison["configuration"]), comparison["scenario"]
        for field, value in comparison.items():
            if field.endswith("_mean"):
                metric = field[:-5]
                values = [float(by_cell["Salsa20", key, config, scenario][metric]) -
                          float(by_cell["ChaCha20", key, config, scenario][metric]) for key in KEY_INDICES]
                assert abs(float(value) - np.mean(values)) < 1e-11
    tests = _rows("matched_nonce_phase_planned_tests.csv")
    assert len(tests) == 2
    for test in tests:
        values = [float(by_cell[test["cipher"], key, 2, "single_bit"]["alignment_loss_hnodc"])
                  for key in KEY_INDICES]
        assert abs(float(test["mean"]) - np.mean(values)) < 1e-11
    adjusted = 0.0
    for rank, test in enumerate(sorted(tests, key=lambda row: float(row["p_sign_flip_two_sided"]))):
        adjusted = min(1.0, max(adjusted, (len(tests) - rank) * float(test["p_sign_flip_two_sided"])))
        assert abs(float(test["p_holm"]) - adjusted) < 1e-12
    print("Audited 960 key-cell records, two raw HW arrays, all 128 paired rotations per cell, "
          "12 summaries, six cross-core comparisons, and two planned tests")


if __name__ == "__main__":
    main()
