#!/usr/bin/env python3
"""Independently audit the archived six-cipher raw arrays and result tables."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "doc_stream_ciphers" / "data" / "unified_six_results"
PROTOCOL = ROOT / "doc_stream_ciphers" / "SIX_CIPHER_UNIFIED_PROTOCOL.txt"
FILES = {
    "Grain-128": "unified_six_grain_128_raw.npz",
    "Trivium": "unified_six_trivium_raw.npz",
    "MICKEY 2.0": "unified_six_mickey_2.0_raw.npz",
    "HC-128": "unified_six_hc_128_raw.npz",
    "Rabbit": "unified_six_rabbit_raw.npz",
    "ChaCha20": "unified_six_chacha20_raw.npz",
}
SCENARIOS = ("single_bit", "localized_four_bit")


def spectral(values: np.ndarray) -> tuple[float, float, float]:
    x = np.asarray(values, dtype=np.float64)
    power = np.mean(np.abs(np.fft.fft(x, axis=1)) ** 2, axis=0)
    p = power / power.sum()
    h = -float(np.sum(p[p > 0] * np.log2(p[p > 0])))
    a = power[1:] / power[1:].sum()
    ha = -float(np.sum(a[a > 0] * np.log2(a[a > 0]))) / np.log2(len(a))
    p0 = float(p[0])
    moment_p0 = float(np.mean(x.mean(axis=1) ** 2) /
                      (np.mean(x.mean(axis=1) ** 2) + np.mean(x.var(axis=1))))
    h2 = -p0 * np.log2(p0) - (1 - p0) * np.log2(1 - p0)
    assert abs(p0 - moment_p0) < 1e-12
    assert abs(h - h2 - (1 - p0) * np.log2(x.shape[1] - 1) * ha) < 1e-12
    return h, p0, ha


def main() -> None:
    manifest = json.loads((DATA / "unified_six_manifest.json").read_text())
    assert hashlib.sha256(PROTOCOL.read_bytes()).hexdigest() == manifest["protocol_sha256"]
    assert manifest["key_indices"] == list(range(280, 360))
    with (DATA / "unified_six_per_key.csv").open(newline="", encoding="utf-8") as handle:
        records = list(csv.DictReader(handle))
    records_by_cell = {(r["family"], int(r["key_index"]), int(r["configuration"]),
                        r["scenario"], r["window"]): r for r in records}
    assert len(records_by_cell) == len(records)
    with (DATA / "unified_six_phase_per_key.csv").open(newline="", encoding="utf-8") as handle:
        phase_rows = list(csv.DictReader(handle))
    phase_by_cell = {(int(r["key_index"]), int(r["configuration"]), r["scenario"]): r
                     for r in phase_rows}
    assert len(phase_by_cell) == len(phase_rows) == 80 * 3 * 2
    expected_records = 0
    for family, filename in FILES.items():
        with np.load(DATA / filename) as raw:
            actual, oracle = raw["actual"], raw["oracle"]
            configs = [int(c) for c in raw["configurations"]]
            assert actual.shape == oracle.shape == (80, len(configs), 2, 16, 32)
            assert raw["key_indices"].tolist() == list(range(280, 360))
            assert all(0 <= int(v) <= 128 for v in (actual.min(), actual.max(), oracle.min(), oracle.max()))
            for key_offset, key_index in enumerate(range(280, 360)):
                for config_offset, config in enumerate(configs):
                    for scenario_offset, scenario in enumerate(SCENARIOS):
                        for window, selector in (("full32", slice(None)), ("tail16", slice(16, None))):
                            row = records_by_cell[family, key_index, config, scenario, window]
                            ha, pa, aa = spectral(actual[key_offset, config_offset, scenario_offset, :, selector])
                            ho, po, ao = spectral(oracle[key_offset, config_offset, scenario_offset, :, selector])
                            for label, computed in (("actual_entropy_mean_power", ha),
                                                    ("oracle_entropy_mean_power", ho),
                                                    ("actual_dc_share", pa),
                                                    ("oracle_dc_share", po),
                                                    ("actual_entropy_no_dc_normalized", aa),
                                                    ("oracle_entropy_no_dc_normalized", ao),
                                                    ("actual_minus_oracle_entropy_mean_power", ha - ho)):
                                assert abs(float(row[label]) - computed) < 1e-11, (family, config, key_index, label)
                            assert abs(float(row["dc_attribution"]) + float(row["ac_attribution"]) - (ha - ho)) < 1e-11
                            expected_records += 1
                    if family == "ChaCha20" and config in (2, 4, 20):
                        phase = phase_by_cell[key_index, config, scenario]
                        aa = actual[key_offset, config_offset, scenario_offset].astype(float)
                        oo = oracle[key_offset, config_offset, scenario_offset].astype(float)
                        positions = {}
                        for label, values in (("actual", aa), ("oracle", oo)):
                            positions[label] = [float(values[:, i::4].mean()) for i in range(4)]
                            for i, value in enumerate(positions[label], 1):
                                assert abs(float(phase[f"{label}_position_{i}_mean_hw"]) - value) < 1e-11
                            assert abs(float(phase[f"{label}_phase_range"]) -
                                       (max(positions[label]) - min(positions[label]))) < 1e-11
                        diff = float(phase["actual_phase_range"]) - float(phase["oracle_phase_range"])
                        assert abs(float(phase["phase_range_difference"]) - diff) < 1e-11
                        hmp_a, _, hnodc_a = spectral(aa.reshape(16, 8, 4).sum(axis=2))
                        hmp_o, _, hnodc_o = spectral(oo.reshape(16, 8, 4).sum(axis=2))
                        assert abs(float(phase["aggregated_512_hmp_difference"]) - (hmp_a - hmp_o)) < 1e-11
                        assert abs(float(phase["aggregated_512_hnodc_difference"]) -
                                   (hnodc_a - hnodc_o)) < 1e-11
    assert expected_records == len(records)
    with (DATA / "unified_six_summary.csv").open(newline="", encoding="utf-8") as handle:
        summaries = list(csv.DictReader(handle))
    for summary in summaries:
        group = [records_by_cell[summary["family"], key, int(summary["configuration"]),
                                 summary["scenario"], summary["window"]] for key in range(280, 360)]
        for field, value in summary.items():
            if field.endswith("_mean") and field[:-5] in group[0]:
                assert abs(float(value) - np.mean([float(r[field[:-5]]) for r in group])) < 1e-11
    with (DATA / "unified_six_phase_summary.csv").open(newline="", encoding="utf-8") as handle:
        phase_summaries = list(csv.DictReader(handle))
    for summary in phase_summaries:
        group = [phase_by_cell[key, int(summary["configuration"]), summary["scenario"]]
                 for key in range(280, 360)]
        for field, value in summary.items():
            if field.endswith("_mean") and field[:-5] in group[0]:
                assert abs(float(value) - np.mean([float(r[field[:-5]]) for r in group])) < 1e-11
    with (DATA / "unified_six_planned_tests.csv").open(newline="", encoding="utf-8") as handle:
        tests = list(csv.DictReader(handle))
    assert len(tests) == 9
    for test in tests:
        config = int(test["configuration"])
        metric = test["metric"]
        if metric == "phase_range_difference":
            values = [float(phase_by_cell[key, config, "single_bit"][metric])
                      for key in range(280, 360)]
        else:
            values = [float(records_by_cell[test["cipher"], key, config,
                                            "single_bit", "full32"][metric])
                      for key in range(280, 360)]
        assert abs(float(test["mean_difference"]) - np.mean(values)) < 1e-11
    for family, count in (("primary_standard_hmp", 6), ("fresh_signature_replication", 3)):
        group = [r for r in tests if r["test_family"] == family]
        assert len(group) == count
        ordered = sorted(group, key=lambda r: float(r["p_sign_flip_two_sided"]))
        adjusted = 0.0
        for rank, row in enumerate(ordered):
            adjusted = min(1.0, max(adjusted, (count - rank) * float(row["p_sign_flip_two_sided"])))
            assert abs(float(row["p_holm"]) - adjusted) < 1e-12
    print(f"Audited {expected_records} key-cell-window records, six raw arrays, "
          f"{len(phase_rows)} phase records, summaries, and nine planned test means")


if __name__ == "__main__":
    main()
