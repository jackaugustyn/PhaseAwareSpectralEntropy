#!/usr/bin/env python3
"""Fresh-key, ordinary-IV/nonce study of six stream ciphers.

The locked design is in doc_stream_ciphers/SIX_CIPHER_UNIFIED_PROTOCOL.txt.
All six families use key indices 280--359 and the same trajectory estimator.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from extension_stream_cores import (
    chacha20_iv_stream, hc128_iv_stream, mickey20_iv_stream, rabbit_iv_stream,
)
from publication_study import _key_material, _summarise_trajectories
from standard_iv_validation import BLOCKS, BLOCK_BITS, MASTER_SEED, _block_hamming_weights, _mask_sets, _metrics
from spectral_crypto_analyzer.primitives import _grain128_keystream_128, _trivium_keystream_128

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUTPUT = ROOT / "doc_stream_ciphers" / "data" / "unified_six_results"
PROTOCOL = ROOT / "doc_stream_ciphers" / "SIX_CIPHER_UNIFIED_PROTOCOL.txt"
KEY_INDICES = tuple(range(280, 360))
SCENARIOS = ("single_bit", "localized_four_bit")
BASE_IVS = 4
BOOTSTRAP_REPLICATES = 5000
BOOTSTRAP_SEED = 20261021
SIGN_FLIPS = 200_000
METRICS = (
    "entropy_mean_power", "dc_share", "entropy_no_dc_normalized",
    "mean_hamming_weight", "mean_temporal_variance", "ljung_box_q8",
)


def grain_stream(key: bytes, iv: bytes, clocks: int, nbytes: int) -> bytes:
    """Generate ``nbytes`` of Grain-128 after the requested initialization clocks."""
    return _grain128_keystream_128(key, iv, clocks, nbytes * 8)


def trivium_stream(key: bytes, iv: bytes, clocks: int, nbytes: int) -> bytes:
    """Generate ``nbytes`` of Trivium after the requested initialization clocks."""
    return _trivium_keystream_128(key, iv, clocks, nbytes * 8)


FAMILIES = {
    "Grain-128": {
        "iv_bytes": 12, "key_bytes": 16, "configs": (0, 32, 64, 128, 192, 256),
        "standard": 256, "axis": "initialization_clocks", "stream": grain_stream,
    },
    "Trivium": {
        "iv_bytes": 10, "key_bytes": 10, "configs": (0, 64, 128, 192, 384, 768, 1152),
        "standard": 1152, "axis": "initialization_clocks", "stream": trivium_stream,
    },
    "MICKEY 2.0": {
        "iv_bytes": 10, "key_bytes": 10, "configs": (0, 25, 50, 75, 100),
        "standard": 100, "axis": "final_blank_clocks", "stream": mickey20_iv_stream,
    },
    "HC-128": {
        "iv_bytes": 16, "key_bytes": 16, "configs": (0, 256, 512, 768, 1024),
        "standard": 1024, "axis": "initialization_steps", "stream": hc128_iv_stream,
    },
    "Rabbit": {
        "iv_bytes": 8, "key_bytes": 16, "configs": (0, 1, 2, 3, 4),
        "standard": 4, "axis": "iv_setup_iterations", "stream": rabbit_iv_stream,
    },
    "ChaCha20": {
        "iv_bytes": 12, "key_bytes": 32, "configs": (2, 4, 6, 8, 12, 20),
        "standard": 20, "axis": "core_rounds", "stream": chacha20_iv_stream,
    },
}


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _context(master_key: bytes, family: str, label: str) -> bytes:
    """Separate key, oracle, and IV derivations for each cipher family."""
    return f"unified-six-iv-v1:{label}:{family}:".encode() + master_key


def _oracle_stream(secret: bytes, family: str, config: int, iv: bytes) -> bytes:
    """Return the graph-matched SHAKE256 stream for one IV vertex.

    Reusing the same IV yields the same control stream, matching IV reuse in
    the observed pair graph. The family and configuration have separate domains.
    """
    domain = (b"unified-six-oracle-v1:" + family.encode() + b":" +
              config.to_bytes(2, "big") + secret + iv)
    return hashlib.shake_256(domain).digest(BLOCKS * BLOCK_BITS // 8)


def _pairs_by_scenario(bases: tuple[bytes, ...], masks_by_scenario: dict[str, list[bytes]]) -> dict[str, list[tuple[bytes, bytes]]]:
    """Construct paired IVs and reject collisions in the shared mask graph."""
    iv_bytes = len(bases[0])
    all_masks = [mask for scenario in SCENARIOS for mask in masks_by_scenario[scenario]]
    vertices = set(bases)
    pairs: dict[str, list[tuple[bytes, bytes]]] = {}
    for scenario in SCENARIOS:
        pairs[scenario] = []
        for base in bases:
            for mask in masks_by_scenario[scenario]:
                other = (int.from_bytes(base, "big") ^ int.from_bytes(mask, "big")).to_bytes(iv_bytes, "big")
                pairs[scenario].append((base, other))
                vertices.add(other)
    if len(vertices) != BASE_IVS * (1 + len(all_masks)):
        raise AssertionError("Joint IV-pair graph contains a collision or cycle")
    return pairs


def _entropy(p: float, a: float, t: int) -> float:
    """Reconstruct full spectral entropy from DC share and normalized AC entropy."""
    h2 = -p * np.log2(p) - (1 - p) * np.log2(1 - p)
    return float(h2 + (1 - p) * np.log2(t - 1) * a)


def _attribution(actual: dict[str, float], oracle: dict[str, float], t: int) -> tuple[float, float]:
    """Split the observed-control entropy difference symmetrically into DC and AC parts."""
    p_a, p_o = actual["dc_share"], oracle["dc_share"]
    a_a, a_o = actual["entropy_no_dc_normalized"], oracle["entropy_no_dc_normalized"]
    dc = 0.5 * (_entropy(p_a, a_a, t) - _entropy(p_o, a_a, t) +
                _entropy(p_a, a_o, t) - _entropy(p_o, a_o, t))
    full = actual["entropy_mean_power"] - oracle["entropy_mean_power"]
    ac = full - dc
    if abs(full - dc - ac) > 1e-12:
        raise AssertionError("Attribution does not reconstruct entropy contrast")
    return dc, ac


def _one_key(task: tuple[str, int]) -> tuple[list[dict[str, object]], np.ndarray, np.ndarray]:
    """Measure every setting and mask family for one independent cipher key.

    Returns per-key metric rows and raw HW arrays with axes
    ``(configuration, mask family, IV pair, 128-bit output block)``.
    """
    family, key_index = task
    spec = FAMILIES[family]
    iv_bytes, key_bytes = int(spec["iv_bytes"]), int(spec["key_bytes"])
    configs = tuple(spec["configs"])
    master_key, _ = _key_material(MASTER_SEED, key_index)
    key = hashlib.blake2b(_context(master_key, family, "key"), digest_size=key_bytes).digest()
    secret = hashlib.blake2b(_context(master_key, family, "oracle"), digest_size=32).digest()
    material = hashlib.shake_256(_context(master_key, family, "base-ivs")).digest(BASE_IVS * iv_bytes)
    bases = tuple(material[i * iv_bytes:(i + 1) * iv_bytes] for i in range(BASE_IVS))
    masks = _mask_sets(iv_bytes)
    pairs = _pairs_by_scenario(bases, masks)
    ivs = set(bases)
    ivs.update(other for scenario in SCENARIOS for _base, other in pairs[scenario])
    shape = (len(configs), len(SCENARIOS), BASE_IVS * 4, BLOCKS)
    actual_all = np.empty(shape, dtype=np.uint8)
    oracle_all = np.empty(shape, dtype=np.uint8)
    rows: list[dict[str, object]] = []
    for config_index, config in enumerate(configs):
        actual_streams = {iv: spec["stream"](key, iv, config, BLOCKS * BLOCK_BITS // 8) for iv in ivs}
        oracle_streams = {iv: _oracle_stream(secret, family, config, iv) for iv in ivs}
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
                    "family": family, "axis": spec["axis"], "configuration": config,
                    "is_standard": int(config == spec["standard"]), "scenario": scenario,
                    "window": window, "key_index": key_index, "trajectories_per_key": actual.shape[0],
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
    """Bootstrap means and pointwise intervals using whole keys as replicates."""
    groups: dict[tuple[str, int, str, str], list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault((str(row["family"]), int(row["configuration"]),
                           str(row["scenario"]), str(row["window"])), []).append(row)
    output: list[dict[str, object]] = []
    fields = [f"{label}_{metric}" for metric in METRICS
              for label in ("actual", "oracle", "actual_minus_oracle")]
    fields += ["dc_attribution", "ac_attribution", "first_block_actual_minus_oracle_mean_hw"]
    for group_index, ((family, config, scenario, window), group) in enumerate(sorted(groups.items())):
        group.sort(key=lambda row: int(row["key_index"]))
        if [int(row["key_index"]) for row in group] != list(KEY_INDICES):
            raise AssertionError("Missing key index in summary cell")
        indices = np.random.default_rng(BOOTSTRAP_SEED + group_index).integers(
            0, len(group), size=(BOOTSTRAP_REPLICATES, len(group)))
        record: dict[str, object] = {
            "family": family, "axis": FAMILIES[family]["axis"], "configuration": config,
            "is_standard": int(config == FAMILIES[family]["standard"]),
            "scenario": scenario, "window": window, "n_keys": len(group),
            "trajectories_per_key": BASE_IVS * 4,
        }
        for field in fields:
            values = np.asarray([float(row[field]) for row in group])
            means = values[indices].mean(axis=1)
            record[f"{field}_mean"] = float(values.mean())
            record[f"{field}_ci95_low"] = float(np.quantile(means, 0.025))
            record[f"{field}_ci95_high"] = float(np.quantile(means, 0.975))
        output.append(record)
    return output


def _phase_rows(pieces: list[tuple[list[dict[str, object]], np.ndarray, np.ndarray]],
                tasks: list[tuple[str, int]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for (_rows, actual_all, oracle_all), (family, key_index) in zip(pieces, tasks):
        if family != "ChaCha20":
            continue
        for config in (2, 4, 20):
            i = FAMILIES[family]["configs"].index(config)
            for scenario_index, scenario in enumerate(SCENARIOS):
                actual = actual_all[i, scenario_index].astype(float)
                oracle = oracle_all[i, scenario_index].astype(float)
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
                    "aggregated_512_hnodc_difference": agg_actual["entropy_no_dc_normalized"] - agg_oracle["entropy_no_dc_normalized"],
                }
                for pos in range(4):
                    row[f"actual_position_{pos + 1}_mean_hw"] = actual_positions[pos]
                    row[f"oracle_position_{pos + 1}_mean_hw"] = oracle_positions[pos]
                output.append(row)
    return output


def _summarize_phase(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    fields = [name for name in rows[0] if name not in {"key_index", "configuration", "scenario"}]
    for group_index, (config, scenario) in enumerate((config, scenario) for config in (2, 4, 20) for scenario in SCENARIOS):
        group = sorted((row for row in rows if row["configuration"] == config and row["scenario"] == scenario),
                       key=lambda row: int(row["key_index"]))
        if [int(row["key_index"]) for row in group] != list(KEY_INDICES):
            raise AssertionError("Missing phase key index")
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
    if values.shape != (len(KEY_INDICES),):
        raise AssertionError("Planned test has wrong number of keys")
    observed = abs(float(values.mean()))
    extreme = 0
    rng = np.random.default_rng(seed)
    for _ in range(SIGN_FLIPS // 10_000):
        signs = rng.integers(0, 2, size=(10_000, len(values)), dtype=np.int8) * 2 - 1
        extreme += int(np.count_nonzero(abs((signs * values).mean(axis=1)) >= observed))
    return (extreme + 1) / (SIGN_FLIPS + 1)


def _holm(records: list[dict[str, object]]) -> None:
    order = sorted(range(len(records)), key=lambda i: float(records[i]["p_sign_flip_two_sided"]))
    maximum = 0.0
    for rank, index in enumerate(order):
        maximum = max(maximum, (len(records) - rank) * float(records[index]["p_sign_flip_two_sided"]))
        records[index]["p_holm"] = min(1.0, maximum)


def _planned_tests(rows: list[dict[str, object]], phase_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Evaluate the six standard endpoints and three selected fresh-key signatures."""
    output: list[dict[str, object]] = []
    for family_index, (family, spec) in enumerate(FAMILIES.items()):
        selected = sorted((row for row in rows if row["family"] == family and
                           row["configuration"] == spec["standard"] and
                           row["scenario"] == "single_bit" and row["window"] == "full32"),
                          key=lambda row: int(row["key_index"]))
        values = np.asarray([float(row["actual_minus_oracle_entropy_mean_power"]) for row in selected])
        output.append({
            "test_family": "primary_standard_hmp", "cipher": family,
            "configuration": spec["standard"], "metric": "actual_minus_oracle_entropy_mean_power",
            "n_keys": len(values), "mean_difference": float(values.mean()),
            "p_sign_flip_two_sided": _sign_flip(values, BOOTSTRAP_SEED + 10_000 + family_index),
            "sign_flips": SIGN_FLIPS,
        })
    _holm(output)
    signatures = (("Trivium", 64, "actual_minus_oracle_entropy_no_dc_normalized"),
                  ("ChaCha20", 2, "actual_minus_oracle_entropy_no_dc_normalized"))
    secondary: list[dict[str, object]] = []
    for index, (family, config, metric) in enumerate(signatures):
        selected = sorted((row for row in rows if row["family"] == family and
                           row["configuration"] == config and row["scenario"] == "single_bit" and
                           row["window"] == "full32"), key=lambda row: int(row["key_index"]))
        values = np.asarray([float(row[metric]) for row in selected])
        secondary.append({
            "test_family": "fresh_signature_replication", "cipher": family,
            "configuration": config, "metric": metric, "n_keys": len(values),
            "mean_difference": float(values.mean()),
            "p_sign_flip_two_sided": _sign_flip(values, BOOTSTRAP_SEED + 11_000 + index),
            "sign_flips": SIGN_FLIPS,
        })
    phase = sorted((row for row in phase_rows if row["configuration"] == 2 and
                    row["scenario"] == "single_bit"), key=lambda row: int(row["key_index"]))
    values = np.asarray([float(row["phase_range_difference"]) for row in phase])
    secondary.append({
        "test_family": "fresh_signature_replication", "cipher": "ChaCha20",
        "configuration": 2, "metric": "phase_range_difference", "n_keys": len(values),
        "mean_difference": float(values.mean()),
        "p_sign_flip_two_sided": _sign_flip(values, BOOTSTRAP_SEED + 11_002),
        "sign_flips": SIGN_FLIPS,
    })
    _holm(secondary)
    return output + secondary


def main() -> None:
    """Generate and save the locked six-cipher cohort, tables, and raw arrays."""
    if not PROTOCOL.is_file():
        raise FileNotFoundError("Locked protocol is required")
    tasks = [(family, index) for family in FAMILIES for index in KEY_INDICES]
    with ProcessPoolExecutor(max_workers=8) as executor:
        pieces = []
        for index, piece in enumerate(executor.map(_one_key, tasks), 1):
            pieces.append(piece)
            if index % 20 == 0:
                print(f"Completed {index}/{len(tasks)} key-cipher tasks", flush=True)
    rows = [row for piece in pieces for row in piece[0]]
    summary = _summarize(rows)
    phase_rows = _phase_rows(pieces, tasks)
    phase_summary = _summarize_phase(phase_rows)
    tests = _planned_tests(rows, phase_rows)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write_csv(OUTPUT / "unified_six_per_key.csv", rows)
    _write_csv(OUTPUT / "unified_six_summary.csv", summary)
    _write_csv(OUTPUT / "unified_six_phase_per_key.csv", phase_rows)
    _write_csv(OUTPUT / "unified_six_phase_summary.csv", phase_summary)
    _write_csv(OUTPUT / "unified_six_planned_tests.csv", tests)
    for family in FAMILIES:
        selected = [piece for piece, task in zip(pieces, tasks) if task[0] == family]
        iv_bytes = int(FAMILIES[family]["iv_bytes"])
        np.savez_compressed(
            OUTPUT / f"unified_six_{family.lower().replace(' ', '_').replace('-', '_')}_raw.npz",
            key_indices=np.asarray(KEY_INDICES), configurations=np.asarray(FAMILIES[family]["configs"]),
            scenarios=np.asarray(SCENARIOS),
            masks_single_bit=np.asarray([mask.hex() for mask in _mask_sets(iv_bytes)["single_bit"]]),
            masks_localized_four_bit=np.asarray([mask.hex() for mask in _mask_sets(iv_bytes)["localized_four_bit"]]),
            actual=np.stack([piece[1] for piece in selected]),
            oracle=np.stack([piece[2] for piece in selected]),
        )
    manifest = {
        "analysis": "unified_six_cipher_ordinary_iv_nonce_study",
        "status": "locked_before_key_indices_280_359_generated",
        "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
        "master_seed": MASTER_SEED, "key_indices": KEY_INDICES,
        "families": {name: {k: v for k, v in spec.items() if k != "stream"}
                     for name, spec in FAMILIES.items()},
        "base_ivs_per_key": BASE_IVS, "masks_per_scenario": 4,
        "scenarios": SCENARIOS, "windows": ("full32", "tail16"),
        "output_blocks": BLOCKS, "bits_per_block": BLOCK_BITS,
        "pair_graph": "joint eight-mask forest: four disjoint eight-edge stars per key",
        "oracle": "SHAKE256 keyed by family, master key, configuration and IV/nonce",
        "bootstrap_replicates": BOOTSTRAP_REPLICATES, "bootstrap_seed": BOOTSTRAP_SEED,
        "sign_flips": SIGN_FLIPS, "planned_tests": tests,
        "numpy": np.__version__,
    }
    (OUTPUT / "unified_six_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for row in tests:
        print("Planned", row["test_family"], row["cipher"], row["configuration"],
              row["metric"], "mean", row["mean_difference"], "Holm p", row["p_holm"], flush=True)


if __name__ == "__main__":
    main()
