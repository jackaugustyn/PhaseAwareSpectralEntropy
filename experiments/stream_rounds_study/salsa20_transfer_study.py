#!/usr/bin/env python3
"""Prospective Salsa20 transfer test of the six-cipher block-position finding."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from extension_stream_cores import salsa20_iv_stream
from publication_study import _key_material, _summarise_trajectories
from standard_iv_validation import BLOCKS, BLOCK_BITS, MASTER_SEED, _block_hamming_weights, _mask_sets, _metrics
from unified_six_cipher_iv_study import _attribution, _context, _oracle_stream, _pairs_by_scenario


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUTPUT = ROOT / "doc_stream_ciphers" / "data" / "salsa20_transfer_results"
PROTOCOL = ROOT / "doc_stream_ciphers" / "SALSA20_TRANSFER_PROTOCOL.txt"
KEY_INDICES = tuple(range(360, 440))
CONFIGS = (2, 4, 6, 8, 12, 20)
SCENARIOS = ("single_bit", "localized_four_bit")
PHASE_CONFIGS = (2, 4, 20)
BASE_NONCES = 4
BOOTSTRAP_REPLICATES = 5000
BOOTSTRAP_SEED = 20261022
SIGN_FLIPS = 200_000
METRICS = (
    "entropy_mean_power", "dc_share", "entropy_no_dc_normalized",
    "mean_hamming_weight", "mean_temporal_variance", "ljung_box_q8",
)


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _one_key(key_index: int) -> tuple[list[dict[str, object]], np.ndarray, np.ndarray]:
    """Measure Salsa20 and its matched control across rounds for one fresh key.

    The returned HW arrays have axes ``(rounds, mask family, nonce pair,
    128-bit output segment)``; the per-key rows also contain DC/AC attribution.
    """
    master_key, _ = _key_material(MASTER_SEED, key_index)
    key = hashlib.blake2b(_context(master_key, "Salsa20", "key"), digest_size=32).digest()
    secret = hashlib.blake2b(_context(master_key, "Salsa20", "oracle"), digest_size=32).digest()
    material = hashlib.shake_256(_context(master_key, "Salsa20", "base-ivs")).digest(BASE_NONCES * 8)
    bases = tuple(material[i * 8:(i + 1) * 8] for i in range(BASE_NONCES))
    masks = _mask_sets(8)
    pairs = _pairs_by_scenario(bases, masks)
    nonces = set(bases)
    nonces.update(other for scenario in SCENARIOS for _base, other in pairs[scenario])
    shape = (len(CONFIGS), len(SCENARIOS), BASE_NONCES * 4, BLOCKS)
    actual_all = np.empty(shape, dtype=np.uint8)
    oracle_all = np.empty(shape, dtype=np.uint8)
    rows: list[dict[str, object]] = []
    for config_index, rounds in enumerate(CONFIGS):
        actual_streams = {nonce: salsa20_iv_stream(key, nonce, rounds, BLOCKS * BLOCK_BITS // 8)
                          for nonce in nonces}
        oracle_streams = {nonce: _oracle_stream(secret, "Salsa20", rounds, nonce) for nonce in nonces}
        for scenario_index, scenario in enumerate(SCENARIOS):
            actual = actual_all[config_index, scenario_index]
            oracle = oracle_all[config_index, scenario_index]
            for pair_index, (base, other) in enumerate(pairs[scenario]):
                actual[pair_index] = _block_hamming_weights(actual_streams[base], actual_streams[other])
                oracle[pair_index] = _block_hamming_weights(oracle_streams[base], oracle_streams[other])
            for window, selection in (("full32", slice(None)), ("tail16", slice(16, None))):
                measured = {"actual": _metrics(actual[:, selection]),
                            "oracle": _metrics(oracle[:, selection])}
                dc, ac = _attribution(measured["actual"], measured["oracle"], actual[:, selection].shape[1])
                row: dict[str, object] = {
                    "family": "Salsa20", "axis": "core_rounds", "configuration": rounds,
                    "is_standard": int(rounds == 20), "scenario": scenario,
                    "window": window, "key_index": key_index, "trajectories_per_key": 16,
                    "trajectory_length": actual[:, selection].shape[1],
                    "dc_attribution": dc, "ac_attribution": ac,
                    "first_block_actual_minus_oracle_mean_hw": float(actual[:, 0].mean() - oracle[:, 0].mean()),
                }
                for metric in METRICS:
                    for label in ("actual", "oracle"):
                        row[f"{label}_{metric}"] = measured[label][metric]
                    row[f"actual_minus_oracle_{metric}"] = measured["actual"][metric] - measured["oracle"][metric]
                rows.append(row)
    return rows, actual_all, oracle_all


def _summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Compute whole-key means and pointwise bootstrap intervals."""
    groups: dict[tuple[int, str, str], list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault((int(row["configuration"]), str(row["scenario"]), str(row["window"])), []).append(row)
    fields = [f"{label}_{metric}" for metric in METRICS
              for label in ("actual", "oracle", "actual_minus_oracle")]
    fields += ["dc_attribution", "ac_attribution", "first_block_actual_minus_oracle_mean_hw"]
    output: list[dict[str, object]] = []
    for group_index, ((config, scenario, window), group) in enumerate(sorted(groups.items())):
        group.sort(key=lambda row: int(row["key_index"]))
        assert [int(row["key_index"]) for row in group] == list(KEY_INDICES)
        indices = np.random.default_rng(BOOTSTRAP_SEED + group_index).integers(
            0, len(group), size=(BOOTSTRAP_REPLICATES, len(group)))
        record: dict[str, object] = {
            "family": "Salsa20", "axis": "core_rounds", "configuration": config,
            "is_standard": int(config == 20), "scenario": scenario, "window": window,
            "n_keys": len(group), "trajectories_per_key": 16,
        }
        for field in fields:
            values = np.asarray([float(row[field]) for row in group])
            means = values[indices].mean(axis=1)
            record[f"{field}_mean"] = float(values.mean())
            record[f"{field}_ci95_low"] = float(np.quantile(means, 0.025))
            record[f"{field}_ci95_high"] = float(np.quantile(means, 0.975))
        output.append(record)
    return output


def _phase_rows(pieces: list[tuple[list[dict[str, object]], np.ndarray, np.ndarray]]) -> list[dict[str, object]]:
    """Measure the four 128-bit positions within each 512-bit Salsa20 block."""
    output: list[dict[str, object]] = []
    for key_index, (_rows, actual_all, oracle_all) in zip(KEY_INDICES, pieces):
        for config in PHASE_CONFIGS:
            config_index = CONFIGS.index(config)
            for scenario_index, scenario in enumerate(SCENARIOS):
                actual = actual_all[config_index, scenario_index].astype(float)
                oracle = oracle_all[config_index, scenario_index].astype(float)
                actual_positions = [float(actual[:, pos::4].mean()) for pos in range(4)]
                oracle_positions = [float(oracle[:, pos::4].mean()) for pos in range(4)]
                agg_actual = _summarise_trajectories(actual.reshape(16, 8, 4).sum(axis=2))
                agg_oracle = _summarise_trajectories(oracle.reshape(16, 8, 4).sum(axis=2))
                row: dict[str, object] = {
                    "key_index": key_index, "configuration": config, "scenario": scenario,
                    "actual_phase_range": max(actual_positions) - min(actual_positions),
                    "oracle_phase_range": max(oracle_positions) - min(oracle_positions),
                    "phase_range_difference": (max(actual_positions) - min(actual_positions)) -
                                              (max(oracle_positions) - min(oracle_positions)),
                    "aggregated_512_hmp_difference": agg_actual["entropy_mean_power"] - agg_oracle["entropy_mean_power"],
                    "aggregated_512_hnodc_difference": agg_actual["entropy_no_dc_normalized"] -
                                                       agg_oracle["entropy_no_dc_normalized"],
                }
                for pos in range(4):
                    row[f"actual_position_{pos + 1}_mean_hw"] = actual_positions[pos]
                    row[f"oracle_position_{pos + 1}_mean_hw"] = oracle_positions[pos]
                output.append(row)
    return output


def _summarize_phase(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    fields = [field for field in rows[0] if field not in {"key_index", "configuration", "scenario"}]
    output: list[dict[str, object]] = []
    for group_index, (config, scenario) in enumerate((config, scenario)
                                                     for config in PHASE_CONFIGS for scenario in SCENARIOS):
        group = sorted((row for row in rows if row["configuration"] == config and row["scenario"] == scenario),
                       key=lambda row: int(row["key_index"]))
        assert [int(row["key_index"]) for row in group] == list(KEY_INDICES)
        indices = np.random.default_rng(BOOTSTRAP_SEED + 1000 + group_index).integers(
            0, len(group), size=(BOOTSTRAP_REPLICATES, len(group)))
        record: dict[str, object] = {"configuration": config, "scenario": scenario, "n_keys": len(group)}
        for field in fields:
            values = np.asarray([float(row[field]) for row in group])
            means = values[indices].mean(axis=1)
            record[f"{field}_mean"] = float(values.mean())
            record[f"{field}_ci95_low"] = float(np.quantile(means, 0.025))
            record[f"{field}_ci95_high"] = float(np.quantile(means, 0.975))
        output.append(record)
    return output


def _sign_flip(values: np.ndarray, seed: int) -> float:
    values = np.asarray(values, dtype=float)
    assert values.shape == (len(KEY_INDICES),)
    observed = abs(float(values.mean()))
    extreme = 0
    rng = np.random.default_rng(seed)
    for _ in range(SIGN_FLIPS // 10_000):
        signs = rng.integers(0, 2, size=(10_000, len(values)), dtype=np.int8) * 2 - 1
        extreme += int(np.count_nonzero(abs((signs * values).mean(axis=1)) >= observed))
    return (extreme + 1) / (SIGN_FLIPS + 1)


def _planned_tests(rows: list[dict[str, object]], phase_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Run the three locked Salsa20 endpoints with one Holm correction family."""
    records = []
    specs = ((2, "actual_minus_oracle_entropy_no_dc_normalized"),
             (2, "phase_range_difference"),
             (20, "actual_minus_oracle_entropy_mean_power"))
    for index, (config, metric) in enumerate(specs):
        source = phase_rows if metric == "phase_range_difference" else rows
        chosen = sorted((row for row in source if row["configuration"] == config and
                         row["scenario"] == "single_bit" and
                         (metric == "phase_range_difference" or row["window"] == "full32")),
                        key=lambda row: int(row["key_index"]))
        assert [int(row["key_index"]) for row in chosen] == list(KEY_INDICES)
        values = np.asarray([float(row[metric]) for row in chosen])
        records.append({
            "test_family": "salsa20_transfer", "cipher": "Salsa20", "configuration": config,
            "metric": metric, "n_keys": len(values), "mean_difference": float(values.mean()),
            "p_sign_flip_two_sided": _sign_flip(values, BOOTSTRAP_SEED + 10_000 + index),
            "sign_flips": SIGN_FLIPS,
        })
    maximum = 0.0
    for rank, index in enumerate(sorted(range(len(records)), key=lambda i: records[i]["p_sign_flip_two_sided"])):
        maximum = max(maximum, (len(records) - rank) * records[index]["p_sign_flip_two_sided"])
        records[index]["p_holm"] = min(1.0, maximum)
    return records


def main() -> None:
    """Generate the independent Salsa20 cohort and its archived result tables."""
    if not PROTOCOL.is_file():
        raise FileNotFoundError("Locked Salsa20 protocol is required")
    with ProcessPoolExecutor(max_workers=8) as executor:
        pieces = []
        for index, piece in enumerate(executor.map(_one_key, KEY_INDICES), 1):
            pieces.append(piece)
            if index % 10 == 0:
                print(f"Completed {index}/{len(KEY_INDICES)} Salsa20 keys", flush=True)
    rows = [row for piece in pieces for row in piece[0]]
    summary = _summarize(rows)
    phase_rows = _phase_rows(pieces)
    phase_summary = _summarize_phase(phase_rows)
    tests = _planned_tests(rows, phase_rows)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write_csv(OUTPUT / "salsa20_transfer_per_key.csv", rows)
    _write_csv(OUTPUT / "salsa20_transfer_summary.csv", summary)
    _write_csv(OUTPUT / "salsa20_transfer_phase_per_key.csv", phase_rows)
    _write_csv(OUTPUT / "salsa20_transfer_phase_summary.csv", phase_summary)
    _write_csv(OUTPUT / "salsa20_transfer_planned_tests.csv", tests)
    np.savez_compressed(
        OUTPUT / "salsa20_transfer_raw.npz",
        key_indices=np.asarray(KEY_INDICES), configurations=np.asarray(CONFIGS),
        scenarios=np.asarray(SCENARIOS),
        masks_single_bit=np.asarray([mask.hex() for mask in _mask_sets(8)["single_bit"]]),
        masks_localized_four_bit=np.asarray([mask.hex() for mask in _mask_sets(8)["localized_four_bit"]]),
        actual=np.stack([piece[1] for piece in pieces]),
        oracle=np.stack([piece[2] for piece in pieces]),
    )
    manifest = {
        "analysis": "prospective_salsa20_transfer_to_seven_cipher_article",
        "status": "addendum_locked_after_six_cipher_results_before_salsa20_trajectories",
        "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
        "master_seed": MASTER_SEED, "key_indices": KEY_INDICES,
        "family": "Salsa20", "key_bytes": 32, "nonce_bytes": 8,
        "configurations": CONFIGS, "standard": 20, "axis": "core_rounds",
        "base_nonces_per_key": BASE_NONCES, "masks_per_scenario": 4,
        "scenarios": SCENARIOS, "windows": ("full32", "tail16"),
        "output_blocks": BLOCKS, "bits_per_block": BLOCK_BITS,
        "pair_graph": "joint eight-mask forest: four disjoint eight-edge stars per key",
        "oracle": "SHAKE256 keyed by family, master key, rounds and unique nonce",
        "bootstrap_replicates": BOOTSTRAP_REPLICATES, "bootstrap_seed": BOOTSTRAP_SEED,
        "sign_flips": SIGN_FLIPS, "planned_tests": tests,
        "numpy": np.__version__,
    }
    (OUTPUT / "salsa20_transfer_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for row in tests:
        print("Planned Salsa20", row["configuration"], row["metric"], "mean",
              row["mean_difference"], "Holm p", row["p_holm"], flush=True)


if __name__ == "__main__":
    main()
