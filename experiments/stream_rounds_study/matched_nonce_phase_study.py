#!/usr/bin/env python3
"""Fresh-key matched-64-bit-nonce and within-block phase-rotation study."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream
from publication_study import _key_material
from standard_iv_validation import BLOCKS, BLOCK_BITS, MASTER_SEED, _block_hamming_weights, _mask_sets
from unified_six_cipher_iv_study import _pairs_by_scenario


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUTPUT = ROOT / "doc_stream_ciphers" / "data" / "matched_nonce_phase_results"
PROTOCOL = ROOT / "doc_stream_ciphers" / "MATCHED_NONCE_PHASE_PROTOCOL.txt"
KEY_INDICES = tuple(range(440, 520))
FAMILIES = ("ChaCha20", "Salsa20")
CONFIGS = (2, 4, 20)
SCENARIOS = ("single_bit", "localized_four_bit")
ROTATION_REPLICATES = 128
BASE_NONCES = 4
PAIR_COUNT = 16
BLOCK_LENGTH = 32
BOOTSTRAP_REPLICATES = 5000
BOOTSTRAP_SEED = 20261024
SIGN_FLIPS = 200_000
NUMERIC_FIELDS = (
    "actual_hmp_original", "control_hmp_original", "delta_hmp_original",
    "actual_hmp_rotated", "control_hmp_rotated", "delta_hmp_rotated", "alignment_loss_hmp",
    "actual_hnodc_original", "control_hnodc_original", "delta_hnodc_original",
    "actual_hnodc_rotated", "control_hnodc_rotated", "delta_hnodc_rotated",
    "alignment_loss_hnodc", "actual_p0", "control_p0", "delta_p0",
    "actual_phase_range_original", "control_phase_range_original", "delta_phase_range_original",
    "actual_phase_range_rotated", "control_phase_range_rotated", "delta_phase_range_rotated",
    "max_p0_rotation_drift",
    *(f"{label}_position_{pos}_mean_hw" for label in ("actual", "control") for pos in range(1, 5)),
)
COMPARISON_FIELDS = (
    "delta_hmp_original", "delta_hnodc_original", "delta_hnodc_rotated",
    "alignment_loss_hnodc", "delta_phase_range_original", "delta_phase_range_rotated",
)


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _spectral(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Power-averaged HMP, DC share, and normalized no-DC entropy."""
    x = np.asarray(values, dtype=np.float64)
    power = np.mean(np.abs(np.fft.fft(x, axis=-1)) ** 2, axis=-2)
    p = power / power.sum(axis=-1, keepdims=True)
    positive = np.where(p > 0, p, 1)
    hmp = -np.sum(p * np.log2(positive), axis=-1)
    ac = power[..., 1:] / power[..., 1:].sum(axis=-1, keepdims=True)
    positive_ac = np.where(ac > 0, ac, 1)
    hnodc = -np.sum(ac * np.log2(positive_ac), axis=-1) / np.log2(x.shape[-1] - 1)
    return hmp, p[..., 0], hnodc


def _phase(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Four position means and max-minus-min range; works with batch prefix."""
    x = np.asarray(values, dtype=np.float64).reshape(*values.shape[:-2], PAIR_COUNT, 8, 4)
    means = x.mean(axis=(-3, -2))
    return means, means.max(axis=-1) - means.min(axis=-1)


def _rotated(values: np.ndarray, shifts: np.ndarray) -> np.ndarray:
    """Cyclically shift each four-segment block without changing its HW multiset.

    ``values`` is 16 nonce pairs by 32 segments. ``shifts`` supplies 128
    independent schedules, one shift for each pair and 512-bit output block.
    """
    if values.shape != (PAIR_COUNT, BLOCK_LENGTH) or shifts.shape != (ROTATION_REPLICATES, PAIR_COUNT, 8):
        raise AssertionError("Unexpected trajectory or rotation shape")
    x = np.broadcast_to(values.reshape(1, PAIR_COUNT, 8, 4),
                        (ROTATION_REPLICATES, PAIR_COUNT, 8, 4))
    positions = (np.arange(4, dtype=np.uint8) + shifts[..., None]) % 4
    return np.take_along_axis(x, positions, axis=-1).reshape(ROTATION_REPLICATES, PAIR_COUNT, BLOCK_LENGTH)


def _rotation_seed(family: str, key_index: int, config: int, scenario: str) -> int:
    domain = (b"matched-phase-rotation-v1:" + family.encode() + b":" +
              key_index.to_bytes(2, "big") + config.to_bytes(2, "big") + b":" + scenario.encode())
    return int.from_bytes(hashlib.blake2b(domain, digest_size=8).digest(), "big")


def _oracle(secret: bytes, family: str, config: int, nonce: bytes) -> bytes:
    domain = (b"matched-phase-oracle-v1:" + family.encode() + b":" +
              config.to_bytes(2, "big") + secret + nonce)
    return hashlib.shake_256(domain).digest(BLOCKS * BLOCK_BITS // 8)


def _measure(actual: np.ndarray, control: np.ndarray, shifts: np.ndarray) -> dict[str, float]:
    """Compare original and rotated spectra under one paired rotation schedule.

    Applying identical shifts to observed and control trajectories isolates
    alignment while preserving each trajectory's DC power share.
    """
    measured: dict[str, float] = {}
    rotated_metrics = {}
    for label, values in (("actual", actual), ("control", control)):
        hmp, p0, hnodc = _spectral(values)
        positions, phase_range = _phase(values)
        rotated = _rotated(values, shifts)
        rhmp, rp0, rhnodc = _spectral(rotated)
        _rpositions, rphase_range = _phase(rotated)
        drift = float(np.max(np.abs(rp0 - p0)))
        if drift > 1e-12:
            raise AssertionError("Phase rotation altered DC share")
        for index in range(1, 5):
            measured[f"{label}_position_{index}_mean_hw"] = float(positions[index - 1])
        measured[f"{label}_hmp_original"] = float(hmp)
        measured[f"{label}_hnodc_original"] = float(hnodc)
        measured[f"{label}_p0"] = float(p0)
        measured[f"{label}_phase_range_original"] = float(phase_range)
        measured[f"{label}_hmp_rotated"] = float(np.mean(rhmp))
        measured[f"{label}_hnodc_rotated"] = float(np.mean(rhnodc))
        measured[f"{label}_phase_range_rotated"] = float(np.mean(rphase_range))
        rotated_metrics[label] = drift
    measured["max_p0_rotation_drift"] = max(rotated_metrics.values())
    for field in ("hmp_original", "hmp_rotated", "hnodc_original", "hnodc_rotated",
                  "p0", "phase_range_original", "phase_range_rotated"):
        measured[f"delta_{field}"] = measured[f"actual_{field}"] - measured[f"control_{field}"]
    measured["alignment_loss_hmp"] = measured["delta_hmp_original"] - measured["delta_hmp_rotated"]
    measured["alignment_loss_hnodc"] = measured["delta_hnodc_original"] - measured["delta_hnodc_rotated"]
    return measured


def _one_index(key_index: int) -> tuple[list[dict[str, object]], dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]]]:
    """Generate matched 64-bit nonce pairs for both ARX cores on one key index."""
    master_key, _ = _key_material(MASTER_SEED, key_index)
    material = hashlib.shake_256(b"matched-phase-common-nonces-v1:" + master_key).digest(BASE_NONCES * 8)
    bases = tuple(material[i * 8:(i + 1) * 8] for i in range(BASE_NONCES))
    masks = _mask_sets(8)
    pairs = _pairs_by_scenario(bases, masks)
    nonces = set(bases)
    nonces.update(other for scenario in SCENARIOS for _base, other in pairs[scenario])
    output: dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]] = {}
    rows: list[dict[str, object]] = []
    for family in FAMILIES:
        key = hashlib.blake2b(b"matched-phase-key-v1:" + family.encode() + b":" + master_key,
                              digest_size=32).digest()
        secret = hashlib.blake2b(b"matched-phase-oracle-secret-v1:" + family.encode() + b":" + master_key,
                                 digest_size=32).digest()
        actual_all = np.empty((len(CONFIGS), len(SCENARIOS), PAIR_COUNT, BLOCK_LENGTH), dtype=np.uint8)
        control_all = np.empty_like(actual_all)
        shifts_all = np.empty((len(CONFIGS), len(SCENARIOS), ROTATION_REPLICATES, PAIR_COUNT, 8),
                              dtype=np.uint8)
        for config_index, config in enumerate(CONFIGS):
            actual_streams = {
                nonce: (chacha20_iv_stream(key, bytes(4) + nonce, config, 512)
                        if family == "ChaCha20" else salsa20_iv_stream(key, nonce, config, 512))
                for nonce in nonces
            }
            oracle_streams = {nonce: _oracle(secret, family, config, nonce) for nonce in nonces}
            for scenario_index, scenario in enumerate(SCENARIOS):
                actual = actual_all[config_index, scenario_index]
                control = control_all[config_index, scenario_index]
                for pair_index, (base, other) in enumerate(pairs[scenario]):
                    actual[pair_index] = _block_hamming_weights(actual_streams[base], actual_streams[other])
                    control[pair_index] = _block_hamming_weights(oracle_streams[base], oracle_streams[other])
                shifts = np.random.default_rng(_rotation_seed(family, key_index, config, scenario)).integers(
                    0, 4, size=(ROTATION_REPLICATES, PAIR_COUNT, 8), dtype=np.uint8)
                shifts_all[config_index, scenario_index] = shifts
                row: dict[str, object] = {
                    "family": family, "configuration": config, "scenario": scenario,
                    "key_index": key_index, "n_pairs": PAIR_COUNT, "n_blocks": BLOCK_LENGTH,
                    "rotation_replicates": ROTATION_REPLICATES,
                }
                row.update(_measure(actual, control, shifts))
                rows.append(row)
        output[family] = (actual_all, control_all, shifts_all)
    return rows, output


def _summaries(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, int, str], list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault((str(row["family"]), int(row["configuration"]), str(row["scenario"])), []).append(row)
    output: list[dict[str, object]] = []
    for group_index, (cell, group) in enumerate(sorted(groups.items())):
        family, config, scenario = cell
        group.sort(key=lambda row: int(row["key_index"]))
        if [int(row["key_index"]) for row in group] != list(KEY_INDICES):
            raise AssertionError("Missing key index in summary cell")
        samples = np.random.default_rng(BOOTSTRAP_SEED + group_index).integers(
            0, len(group), size=(BOOTSTRAP_REPLICATES, len(group)))
        record: dict[str, object] = {
            "family": family, "configuration": config, "scenario": scenario, "n_keys": len(group),
        }
        for field in NUMERIC_FIELDS:
            values = np.asarray([float(row[field]) for row in group])
            boot = values[samples].mean(axis=1)
            record[f"{field}_mean"] = float(values.mean())
            record[f"{field}_ci95_low"] = float(np.quantile(boot, 0.025))
            record[f"{field}_ci95_high"] = float(np.quantile(boot, 0.975))
        output.append(record)
    return output


def _comparisons(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_cell = {(str(row["family"]), int(row["configuration"]), str(row["scenario"]), int(row["key_index"])): row
               for row in rows}
    output: list[dict[str, object]] = []
    for group_index, (config, scenario) in enumerate((config, scenario)
                                                     for config in CONFIGS for scenario in SCENARIOS):
        samples = np.random.default_rng(BOOTSTRAP_SEED + 1000 + group_index).integers(
            0, len(KEY_INDICES), size=(BOOTSTRAP_REPLICATES, len(KEY_INDICES)))
        record: dict[str, object] = {"configuration": config, "scenario": scenario, "n_paired_indices": 80,
                                     "direction": "Salsa20_minus_ChaCha20"}
        for field in COMPARISON_FIELDS:
            values = np.asarray([
                float(by_cell["Salsa20", config, scenario, key][field]) -
                float(by_cell["ChaCha20", config, scenario, key][field]) for key in KEY_INDICES
            ])
            boot = values[samples].mean(axis=1)
            record[f"{field}_mean"] = float(values.mean())
            record[f"{field}_ci95_low"] = float(np.quantile(boot, 0.025))
            record[f"{field}_ci95_high"] = float(np.quantile(boot, 0.975))
        output.append(record)
    return output


def _sign_flip(values: np.ndarray, seed: int) -> float:
    if values.shape != (len(KEY_INDICES),):
        raise AssertionError("Wrong planned-test key count")
    observed = abs(float(values.mean()))
    extreme = 0
    rng = np.random.default_rng(seed)
    for _ in range(SIGN_FLIPS // 10_000):
        signs = rng.integers(0, 2, size=(10_000, len(values)), dtype=np.int8) * 2 - 1
        extreme += int(np.count_nonzero(abs((signs * values).mean(axis=1)) >= observed))
    return (extreme + 1) / (SIGN_FLIPS + 1)


def _planned_tests(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Test the two prespecified two-round AC alignment losses across keys."""
    output: list[dict[str, object]] = []
    for index, family in enumerate(FAMILIES):
        group = sorted((row for row in rows if row["family"] == family and
                        row["configuration"] == 2 and row["scenario"] == "single_bit"),
                       key=lambda row: int(row["key_index"]))
        if [int(row["key_index"]) for row in group] != list(KEY_INDICES):
            raise AssertionError("Missing planned-test key")
        values = np.asarray([float(row["alignment_loss_hnodc"]) for row in group])
        output.append({
            "family": "matched_nonce_phase_primary", "cipher": family,
            "configuration": 2, "scenario": "single_bit", "metric": "alignment_loss_hnodc",
            "n_keys": len(values), "mean": float(values.mean()),
            "p_sign_flip_two_sided": _sign_flip(values, BOOTSTRAP_SEED + 2000 + index),
            "sign_flips": SIGN_FLIPS,
        })
    maximum = 0.0
    for rank, index in enumerate(sorted(range(len(output)), key=lambda i: output[i]["p_sign_flip_two_sided"])):
        maximum = max(maximum, (len(output) - rank) * float(output[index]["p_sign_flip_two_sided"]))
        output[index]["p_holm"] = min(1.0, maximum)
    return output


def main() -> None:
    """Save per-key rotations, matched raw arrays, summaries, and planned tests."""
    if not PROTOCOL.is_file():
        raise FileNotFoundError("Locked matched-nonce phase protocol is required")
    with ProcessPoolExecutor(max_workers=8) as executor:
        pieces = []
        for index, piece in enumerate(executor.map(_one_index, KEY_INDICES), 1):
            pieces.append(piece)
            if index % 10 == 0:
                print(f"Completed {index}/{len(KEY_INDICES)} matched master-key indices", flush=True)
    rows = [row for cell_rows, _data in pieces for row in cell_rows]
    summaries = _summaries(rows)
    comparisons = _comparisons(rows)
    tests = _planned_tests(rows)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write_csv(OUTPUT / "matched_nonce_phase_per_key.csv", rows)
    _write_csv(OUTPUT / "matched_nonce_phase_summary.csv", summaries)
    _write_csv(OUTPUT / "matched_nonce_phase_cross_core.csv", comparisons)
    _write_csv(OUTPUT / "matched_nonce_phase_planned_tests.csv", tests)
    for family in FAMILIES:
        selected = [data[family] for _rows, data in pieces]
        np.savez_compressed(
            OUTPUT / f"matched_phase_{family.lower()}_raw.npz",
            key_indices=np.asarray(KEY_INDICES), configurations=np.asarray(CONFIGS),
            scenarios=np.asarray(SCENARIOS),
            masks_single_bit=np.asarray([mask.hex() for mask in _mask_sets(8)["single_bit"]]),
            masks_localized_four_bit=np.asarray([mask.hex() for mask in _mask_sets(8)["localized_four_bit"]]),
            actual=np.stack([entry[0] for entry in selected]),
            control=np.stack([entry[1] for entry in selected]),
            rotations=np.stack([entry[2] for entry in selected]),
        )
    manifest = {
        "analysis": "matched_64bit_nonce_phase_rotation_study",
        "status": "protocol_fixed_before_master_indices_440_519_generated",
        "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
        "master_seed": MASTER_SEED, "master_key_indices": KEY_INDICES,
        "families": FAMILIES, "configurations": CONFIGS, "standard_rounds": 20,
        "scenarios": SCENARIOS, "base_nonces_per_index": BASE_NONCES,
        "pairs_per_scenario": PAIR_COUNT, "output_blocks": BLOCK_LENGTH,
        "bits_per_block": BLOCK_BITS, "rotation_replicates": ROTATION_REPLICATES,
        "rotation_type": "independent uniform cyclic shifts within each 4x128-bit cipher block; paired actual/control",
        "oracle": "SHAKE256 keyed by family, master key, round setting, unique shared-domain 64-bit nonce",
        "bootstrap_replicates": BOOTSTRAP_REPLICATES, "bootstrap_seed": BOOTSTRAP_SEED,
        "sign_flips": SIGN_FLIPS, "planned_tests": tests,
        "numpy": np.__version__,
    }
    (OUTPUT / "matched_nonce_phase_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for row in tests:
        print("Planned phase-loss", row["cipher"], "mean", row["mean"],
              "Holm p", row["p_holm"], flush=True)


if __name__ == "__main__":
    main()
