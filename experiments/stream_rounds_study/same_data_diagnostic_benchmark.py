#!/usr/bin/env python3
"""Descriptive comparison of diagnostics on identical matched-nonce streams."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream
from matched_nonce_phase_study import _oracle, _phase, _spectral
from publication_study import _key_material
from standard_iv_validation import MASTER_SEED, _mask_sets
from unified_six_cipher_iv_study import _pairs_by_scenario


ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "doc_stream_ciphers"
SOURCE = PAPER / "data" / "matched_nonce_phase_results"
OUTPUT = PAPER / "data" / "same_data_benchmark_results"
PROTOCOL = PAPER / "SAME_DATA_DIAGNOSTIC_BENCHMARK.txt"
KEY_INDICES = tuple(range(440, 520))
FAMILIES = ("ChaCha20", "Salsa20")
CONFIGS = (2, 4, 20)
METRICS = ("mean_hw", "sac_rms", "lag4", "phase_range", "hmp", "p0", "hnodc")
BOOTSTRAP_REPLICATES = 5000
BOOTSTRAP_SEED = 20261028


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _lag4(values: np.ndarray) -> float:
    """Return pooled lag-four autocorrelation of centered HW trajectories."""
    centered = np.asarray(values, dtype=np.float64)
    centered = centered - centered.mean(axis=-1, keepdims=True)
    energy = float(np.sum(centered * centered))
    if energy == 0:
        raise AssertionError("Zero centered energy in lag-four comparator")
    return float(np.sum(centered[:, :-4] * centered[:, 4:]) / energy)


def _scores(hw: np.ndarray, bit_counts: np.ndarray) -> dict[str, float]:
    """Compute direct and spectral diagnostics on the same nonce-pair streams.

    ``hw`` is 16 pairs by 32 segments; ``bit_counts`` counts flips at each
    of 512 positions across the 128 block/pair observations.
    """
    if hw.shape != (16, 32) or bit_counts.shape != (512,):
        raise AssertionError("Unexpected same-data comparator shape")
    if int(bit_counts.sum()) != int(hw.sum()):
        raise AssertionError("Bitwise and HW counts disagree")
    hmp, p0, hnodc = _spectral(hw)
    _means, phase_range = _phase(hw)
    return {
        "mean_hw": float(hw.mean()),
        "sac_rms": float(np.sqrt(np.mean((bit_counts / 128.0 - 0.5) ** 2))),
        "lag4": _lag4(hw),
        "phase_range": float(phase_range),
        "hmp": float(hmp),
        "p0": float(p0),
        "hnodc": float(hnodc),
    }


def _one_index(task: tuple[int, np.ndarray, np.ndarray]) -> tuple[list[dict[str, object]], np.ndarray, np.ndarray]:
    """Regenerate bitwise counts and check them against archived HW values."""
    key_index, reference_actual, reference_control = task
    master_key, _ = _key_material(MASTER_SEED, key_index)
    material = hashlib.shake_256(b"matched-phase-common-nonces-v1:" + master_key).digest(32)
    bases = tuple(material[i * 8:(i + 1) * 8] for i in range(4))
    pairs = _pairs_by_scenario(bases, _mask_sets(8))["single_bit"]
    nonces = {nonce for pair in pairs for nonce in pair}
    actual_counts = np.empty((2, 3, 512), dtype=np.uint8)
    control_counts = np.empty_like(actual_counts)
    rows: list[dict[str, object]] = []
    for family_index, family in enumerate(FAMILIES):
        key = hashlib.blake2b(b"matched-phase-key-v1:" + family.encode() + b":" + master_key,
                              digest_size=32).digest()
        secret = hashlib.blake2b(b"matched-phase-oracle-secret-v1:" + family.encode() + b":" + master_key,
                                 digest_size=32).digest()
        for config_index, config in enumerate(CONFIGS):
            actual_streams = {
                nonce: (chacha20_iv_stream(key, bytes(4) + nonce, config, 512)
                        if family == "ChaCha20" else salsa20_iv_stream(key, nonce, config, 512))
                for nonce in nonces
            }
            control_streams = {nonce: _oracle(secret, family, config, nonce) for nonce in nonces}
            for label, streams, reference, destination in (
                ("actual", actual_streams, reference_actual, actual_counts),
                ("control", control_streams, reference_control, control_counts),
            ):
                counts = np.zeros(512, dtype=np.uint16)
                for pair_index, (base, other) in enumerate(pairs):
                    xor = np.bitwise_xor(np.frombuffer(streams[base], dtype=np.uint8),
                                         np.frombuffer(streams[other], dtype=np.uint8))
                    bits = np.unpackbits(xor, bitorder="big").reshape(8, 512)
                    counts += bits.sum(axis=0, dtype=np.uint16)
                    reconstructed_hw = bits.reshape(32, 128).sum(axis=1, dtype=np.uint16)
                    if not np.array_equal(reconstructed_hw, reference[family_index, config_index, pair_index]):
                        raise AssertionError((family, key_index, config, label, pair_index,
                                              "regenerated stream disagrees with archived HW"))
                if counts.max() > 128:
                    raise AssertionError("Bit-flip count exceeds 128 trials")
                destination[family_index, config_index] = counts.astype(np.uint8)
            observed = _scores(reference_actual[family_index, config_index],
                               actual_counts[family_index, config_index])
            control = _scores(reference_control[family_index, config_index],
                              control_counts[family_index, config_index])
            row: dict[str, object] = {"family": family, "configuration": config,
                                      "scenario": "single_bit", "key_index": key_index,
                                      "n_pairs": 16, "n_blocks": 32, "bit_trials_per_position": 128}
            for metric in METRICS:
                row[f"actual_{metric}"] = observed[metric]
                row[f"control_{metric}"] = control[metric]
                row[f"delta_{metric}"] = observed[metric] - control[metric]
            rows.append(row)
    return rows, actual_counts, control_counts


def _summaries(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Summarize observed-control scores with whole-key bootstrap intervals."""
    output: list[dict[str, object]] = []
    for family_index, family in enumerate(FAMILIES):
        for config_index, config in enumerate(CONFIGS):
            selected = sorted((row for row in rows if row["family"] == family and
                               row["configuration"] == config), key=lambda row: int(row["key_index"]))
            if [int(row["key_index"]) for row in selected] != list(KEY_INDICES):
                raise AssertionError("Missing benchmark key index")
            samples = np.random.default_rng(BOOTSTRAP_SEED + family_index * 3 + config_index).integers(
                0, 80, size=(BOOTSTRAP_REPLICATES, 80))
            summary: dict[str, object] = {"family": family, "configuration": config,
                                          "scenario": "single_bit", "n_keys": 80}
            for metric in METRICS:
                values = np.asarray([float(row[f"delta_{metric}"]) for row in selected])
                boot = values[samples].mean(axis=1)
                summary[f"delta_{metric}_mean"] = float(values.mean())
                summary[f"delta_{metric}_ci95_low"] = float(np.quantile(boot, 0.025))
                summary[f"delta_{metric}_ci95_high"] = float(np.quantile(boot, 0.975))
            output.append(summary)
    return output


def main() -> None:
    """Save the descriptive same-stream comparator and its integrity manifest."""
    if not PROTOCOL.is_file():
        raise FileNotFoundError("Fixed same-data benchmark plan is required")
    reference_actual = []
    reference_control = []
    input_hashes = {}
    for family in FAMILIES:
        path = SOURCE / f"matched_phase_{family.lower()}_raw.npz"
        input_hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        with np.load(path) as raw:
            if raw["key_indices"].tolist() != list(KEY_INDICES) or raw["configurations"].tolist() != list(CONFIGS):
                raise AssertionError("Unexpected archived key indices or configurations")
            reference_actual.append(raw["actual"][:, :, 0])
            reference_control.append(raw["control"][:, :, 0])
    actual = np.stack(reference_actual, axis=1)
    control = np.stack(reference_control, axis=1)
    if actual.shape != (80, 2, 3, 16, 32) or control.shape != (80, 2, 3, 16, 32):
        raise AssertionError("Unexpected archived HW shapes")
    tasks = [(key_index, actual[i], control[i]) for i, key_index in enumerate(KEY_INDICES)]
    with ProcessPoolExecutor(max_workers=8) as executor:
        pieces = list(executor.map(_one_index, tasks))
    rows = [row for block, _actual, _control in pieces for row in block]
    summaries = _summaries(rows)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write_csv(OUTPUT / "same_data_benchmark_per_key.csv", rows)
    _write_csv(OUTPUT / "same_data_benchmark_summary.csv", summaries)
    np.savez_compressed(
        OUTPUT / "same_data_benchmark_bit_counts.npz",
        key_indices=np.asarray(KEY_INDICES), families=np.asarray(FAMILIES),
        configurations=np.asarray(CONFIGS), scenario="single_bit",
        actual=np.stack([piece[1] for piece in pieces]),
        control=np.stack([piece[2] for piece in pieces]),
    )
    manifest = {
        "analysis": "same_data_diagnostic_benchmark",
        "status": "descriptive_secondary_analysis_of_known_matched_nonce_cohort",
        "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
        "input_raw_sha256": input_hashes,
        "master_key_indices": KEY_INDICES, "families": FAMILIES,
        "configurations": CONFIGS, "scenario": "single_bit",
        "pairs_per_key": 16, "output_bits_per_pair": 4096,
        "bit_trials_per_position": 128,
        "metrics": METRICS, "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
    }
    (OUTPUT / "same_data_benchmark_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Regenerated and HW-gated 80 matched indices for both ciphers and three round settings")
    for summary in summaries:
        print(summary["family"], summary["configuration"],
              "mean HW", f"{summary['delta_mean_hw_mean']:+.4f}",
              "AC", f"{summary['delta_hnodc_mean']:+.5f}",
              "lag4", f"{summary['delta_lag4_mean']:+.4f}")


if __name__ == "__main__":
    main()
