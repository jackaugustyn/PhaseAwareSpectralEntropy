#!/usr/bin/env python3
"""Independently audit Salsa20 transfer arrays and all reported means."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from audit_unified_six_results import spectral


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "doc_stream_ciphers" / "data" / "salsa20_transfer_results"
PROTOCOL = ROOT / "doc_stream_ciphers" / "SALSA20_TRANSFER_PROTOCOL.txt"
KEY_INDICES = range(360, 440)
SCENARIOS = ("single_bit", "localized_four_bit")


def _rows(name: str) -> list[dict[str, str]]:
    with (DATA / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _check_means(summaries: list[dict[str, str]], groups: dict[tuple, list[dict[str, str]]],
                 keys: tuple[str, ...]) -> None:
    for summary in summaries:
        group_key = tuple(summary[key] for key in keys)
        group = groups[group_key]
        assert len(group) == 80
        for field, value in summary.items():
            if field.endswith("_mean") and field[:-5] in group[0]:
                assert abs(float(value) - np.mean([float(row[field[:-5]]) for row in group])) < 1e-11


def main() -> None:
    manifest = json.loads((DATA / "salsa20_transfer_manifest.json").read_text())
    assert hashlib.sha256(PROTOCOL.read_bytes()).hexdigest() == manifest["protocol_sha256"]
    assert manifest["key_indices"] == list(KEY_INDICES)
    records = _rows("salsa20_transfer_per_key.csv")
    by_cell = {(int(row["key_index"]), int(row["configuration"]), row["scenario"], row["window"]): row
               for row in records}
    assert len(by_cell) == len(records) == 80 * 6 * 2 * 2
    phase = _rows("salsa20_transfer_phase_per_key.csv")
    by_phase = {(int(row["key_index"]), int(row["configuration"]), row["scenario"]): row for row in phase}
    assert len(by_phase) == len(phase) == 80 * 3 * 2
    with np.load(DATA / "salsa20_transfer_raw.npz") as raw:
        actual, oracle = raw["actual"], raw["oracle"]
        configs = [int(config) for config in raw["configurations"]]
        assert configs == [2, 4, 6, 8, 12, 20]
        assert actual.shape == oracle.shape == (80, 6, 2, 16, 32)
        assert raw["key_indices"].tolist() == list(KEY_INDICES)
        assert all(0 <= int(value) <= 128 for value in
                   (actual.min(), actual.max(), oracle.min(), oracle.max()))
        for key_offset, key_index in enumerate(KEY_INDICES):
            for config_offset, config in enumerate(configs):
                for scenario_offset, scenario in enumerate(SCENARIOS):
                    aa = actual[key_offset, config_offset, scenario_offset].astype(float)
                    oo = oracle[key_offset, config_offset, scenario_offset].astype(float)
                    for window, selector in (("full32", slice(None)), ("tail16", slice(16, None))):
                        row = by_cell[key_index, config, scenario, window]
                        ha, pa, an = spectral(aa[:, selector])
                        ho, po, on = spectral(oo[:, selector])
                        computed = {
                            "actual_entropy_mean_power": ha,
                            "oracle_entropy_mean_power": ho,
                            "actual_dc_share": pa,
                            "oracle_dc_share": po,
                            "actual_entropy_no_dc_normalized": an,
                            "oracle_entropy_no_dc_normalized": on,
                            "actual_minus_oracle_entropy_mean_power": ha - ho,
                            "actual_minus_oracle_entropy_no_dc_normalized": an - on,
                        }
                        for field, value in computed.items():
                            assert abs(float(row[field]) - value) < 1e-11, (key_index, config, scenario, field)
                        assert abs(float(row["dc_attribution"]) + float(row["ac_attribution"]) -
                                   (ha - ho)) < 1e-11
                    if config in (2, 4, 20):
                        row = by_phase[key_index, config, scenario]
                        for label, values in (("actual", aa), ("oracle", oo)):
                            positions = [float(values[:, pos::4].mean()) for pos in range(4)]
                            for pos, value in enumerate(positions, 1):
                                assert abs(float(row[f"{label}_position_{pos}_mean_hw"]) - value) < 1e-11
                            assert abs(float(row[f"{label}_phase_range"]) -
                                       (max(positions) - min(positions))) < 1e-11
                        assert abs(float(row["phase_range_difference"]) -
                                   (float(row["actual_phase_range"]) - float(row["oracle_phase_range"]))) < 1e-11
                        hmp_a, _, hnodc_a = spectral(aa.reshape(16, 8, 4).sum(axis=2))
                        hmp_o, _, hnodc_o = spectral(oo.reshape(16, 8, 4).sum(axis=2))
                        assert abs(float(row["aggregated_512_hmp_difference"]) - (hmp_a - hmp_o)) < 1e-11
                        assert abs(float(row["aggregated_512_hnodc_difference"]) -
                                   (hnodc_a - hnodc_o)) < 1e-11
    groups: dict[tuple[str, ...], list[dict[str, str]]] = {}
    for row in records:
        groups.setdefault((row["configuration"], row["scenario"], row["window"]), []).append(row)
    _check_means(_rows("salsa20_transfer_summary.csv"), groups, ("configuration", "scenario", "window"))
    phase_groups: dict[tuple[str, ...], list[dict[str, str]]] = {}
    for row in phase:
        phase_groups.setdefault((row["configuration"], row["scenario"]), []).append(row)
    _check_means(_rows("salsa20_transfer_phase_summary.csv"), phase_groups, ("configuration", "scenario"))
    tests = _rows("salsa20_transfer_planned_tests.csv")
    assert len(tests) == 3
    for test in tests:
        metric, config = test["metric"], int(test["configuration"])
        if metric == "phase_range_difference":
            values = [float(by_phase[key, config, "single_bit"][metric]) for key in KEY_INDICES]
        else:
            values = [float(by_cell[key, config, "single_bit", "full32"][metric]) for key in KEY_INDICES]
        assert abs(float(test["mean_difference"]) - np.mean(values)) < 1e-11
    adjusted = 0.0
    for rank, test in enumerate(sorted(tests, key=lambda row: float(row["p_sign_flip_two_sided"]))):
        adjusted = min(1.0, max(adjusted, (len(tests) - rank) * float(test["p_sign_flip_two_sided"])))
        assert abs(float(test["p_holm"]) - adjusted) < 1e-12
    print("Audited 1920 Salsa20 key-cell-window records, 480 phase records, "
          "all summary means, and three planned test means")


if __name__ == "__main__":
    main()
