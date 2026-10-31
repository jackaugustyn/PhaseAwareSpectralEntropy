#!/usr/bin/env python3
"""Paired ARX finalization interventions and mixed nonce-word derivatives.

The existing vector-checked emitted stream is converted back to its working
state by subtraction modulo 2**32. Thus all finalization variants use exactly
the same core evaluation; the established cipher implementations are intact.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import csv
import hashlib
import json
import platform
import sys
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from arx_mechanism_analysis import initial_state
from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream
from analyze_arx_resolution import measure, METRICS
from arx_resolution_validation import aggregate_words, holm, sign_flip_pvalues
from publication_study import _key_material

FAMILIES = ("ChaCha20", "Salsa20")
FINALIZATIONS = ("add", "none", "xor")
POPCOUNT = np.asarray([i.bit_count() for i in range(256)], dtype=np.uint8)
PROTOCOL = ROOT / "doc_stream_ciphers" / "ARX_FEEDFORWARD_PROTOCOL.txt"
PROTOCOL_SHA256 = "b416c7fb7b6697e26c4707b9e6c70981245f22eaecd243c480319ea393090ef8"
OUT = ROOT / "doc_stream_ciphers" / "data" / "arx_feedforward_results"
ROUNDS = (2, 4)
INDICES = tuple(range(1000, 1080))
SMOKE_INDICES = (1080, 1081)
SEED = 20261030
SIGN_SEED = 2026103001
BOOT_SEED = 2026103002
BOOTSTRAPS = 5000
SIGN_FLIPS = 100000


def global_bit(word: int, bit: int) -> int:
    return 32 * word + 8 * (bit // 8) + 7 - bit % 8


PANEL = [
    {"name": f"aligned_{b:02d}", "kind": "aligned", "word_bits_lsb": [[0, b], [1, b]],
     "bits_msb_first": [global_bit(0, b), global_bit(1, b)]} for b in range(32)
] + [
    {"name": f"offset_00_{b:02d}", "kind": "offset", "word_bits_lsb": [[0, 0], [1, b]],
     "bits_msb_first": [global_bit(0, 0), global_bit(1, b)]} for b in (7, 15, 30, 31)
] + [
    {"name": f"within_{a:02d}_{b:02d}", "kind": "within", "word_bits_lsb": [[1, a], [1, b]],
     "bits_msb_first": [global_bit(1, a), global_bit(1, b)]} for a, b in ((0, 15), (7, 30))
]
GROUPS = {"aligned_all32": list(range(32)), "aligned_nonmsb31": list(range(31)),
          "offset4": list(range(32, 36)), "within2": list(range(36, 38))}
RAW_SHAPES = {
    "observed_singleton": (2, 2, 3, 64, 4, 16, 16),
    "oracle_singleton": (2, 2, 3, 64, 4, 16, 16),
    "observed_d2": (2, 2, 3, 38, 4, 16, 16),
    "oracle_d2": (2, 2, 3, 38, 4, 16, 16),
    "observed_d2_word7": (2, 2, 3, 38, 4, 16),
    "oracle_d2_word7": (2, 2, 3, 38, 4, 16),
    "salsa2_singleton_word7": (3, 64, 4, 16),
    "salsa2_c": (33, 4, 16),
}
RAW_AXES = {
    "singleton": ["key", "cipher", "round", "variant", "mask_msb_first", "base", "block512", "word32"],
    "d2": ["key", "cipher", "round", "variant", "panel_pair", "base", "block512", "word32"],
    "d2_word7": ["key", "cipher", "round", "variant", "panel_pair", "base", "block512"],
    "salsa2_singleton_word7": ["key", "variant", "mask_msb_first", "base", "block512"],
    "salsa2_c": ["key", "base_then_global_word0_masks_0_to_31", "base", "block512"],
}


def finalize(working: np.ndarray, initial: np.ndarray) -> np.ndarray:
    """Return add/none/xor finalizations with explicit uint32 arithmetic."""
    core = np.asarray(working, dtype=np.uint32)
    source = np.asarray(initial, dtype=np.uint32)
    if core.shape != source.shape or core.shape[-1] != 16:
        raise ValueError("Working and initial arrays must have matching 16-word blocks")
    return np.stack((np.add(core, source, dtype=np.uint32), core,
                     np.bitwise_xor(core, source)))


def initial_blocks(key: bytes, nonce: bytes, family: str, blocks: int = 16) -> np.ndarray:
    if len(key) != 32 or len(nonce) != 8 or family not in FAMILIES or blocks < 1:
        raise ValueError("Expected a 256-bit key, shared 64-bit nonce and supported cipher")
    return np.asarray([initial_state(key, nonce, counter, family) for counter in range(blocks)],
                      dtype=np.uint32)


def finalized_words(key: bytes, nonce: bytes, family: str, rounds: int,
                    blocks: int = 16) -> np.ndarray:
    """Decode production ADD, recover the core, then apply all finalizations."""
    source = initial_blocks(key, nonce, family, blocks)
    if family == "ChaCha20":
        emitted = chacha20_iv_stream(key, bytes(4) + nonce, rounds, blocks * 64)
    else:
        emitted = salsa20_iv_stream(key, nonce, rounds, blocks * 64)
    added = np.frombuffer(emitted, dtype="<u4").reshape(blocks, 16)
    working = np.subtract(added, source, dtype=np.uint32)
    result = finalize(working, source)
    if not np.array_equal(result[0], added):
        raise AssertionError("Finalization round trip failed")
    return result


def difference_hw(*vertices: np.ndarray) -> np.ndarray:
    """HW32 of the XOR of two or four streams, before any aggregation."""
    if len(vertices) not in (2, 4):
        raise ValueError("A first or second derivative needs two or four vertices")
    difference = np.asarray(vertices[0], dtype=np.uint32).copy()
    for vertex in vertices[1:]:
        if np.shape(vertex) != difference.shape:
            raise ValueError("All derivative vertices must have identical axes")
        np.bitwise_xor(difference, np.asarray(vertex, dtype=np.uint32), out=difference)
    octets = difference.astype("<u4", copy=False).view(np.uint8).reshape(*difference.shape, 4)
    return POPCOUNT[octets].sum(axis=-1, dtype=np.uint8)


def changed_nonce(base: bytes, bits: tuple[int, ...]) -> bytes:
    value = bytearray(base)
    for bit in bits:
        if bit not in range(64):
            raise ValueError("Nonce bits use MSB-first byte numbering 0..63")
        value[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(value)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes() -> dict[str, str]:
    names = ("arx_feedforward_study.py", "arx_mechanism_analysis.py", "analyze_arx_resolution.py",
             "arx_resolution_validation.py", "extension_stream_cores.py", "publication_study.py",
             "literature_mask_followup.py")
    paths = [Path(__file__).with_name(name) for name in names]
    paths.append(ROOT / "src" / "spectral_crypto_analyzer" / "primitives.py")
    return {str(path.relative_to(ROOT)): sha256(path) for path in paths}


def specification(indices: tuple[int, ...]) -> dict[str, object]:
    if sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise AssertionError("Locked protocol changed")
    if indices not in (INDICES, SMOKE_INDICES):
        raise ValueError("Only the fixed final cohort or separate smoke cohort is allowed")
    return {"protocol_sha256": PROTOCOL_SHA256, "source_sha256": source_hashes(),
            "key_indices": list(indices), "seed": SEED, "families": list(FAMILIES),
            "rounds": list(ROUNDS), "variants": list(FINALIZATIONS), "panel": PANEL,
            "raw_per_key_shapes": {name: list(shape) for name, shape in RAW_SHAPES.items()},
            "raw_axes": RAW_AXES, "numpy_version": np.__version__,
            "python_version": platform.python_version()}


def fingerprint(spec: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()


def save_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def save_npz(path: Path, arrays: dict[str, np.ndarray]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        np.savez_compressed(stream, **arrays)
    temporary.replace(path)


def save_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _record(checks: dict[str, dict[str, int]], name: str, equalities: np.ndarray) -> None:
    view = np.asarray(equalities, dtype=bool)
    record = checks.setdefault(name, {"comparisons": 0, "violations": 0})
    record["comparisons"] += int(view.size)
    record["violations"] += int(np.count_nonzero(~view))


def xor_vertices(*vertices: np.ndarray) -> np.ndarray:
    return np.bitwise_xor.reduce(np.asarray(vertices, dtype=np.uint32), axis=0)


def lb(c: np.ndarray, bit: int) -> np.ndarray:
    step = np.uint32(1 << bit)
    return np.bitwise_xor(np.add(np.bitwise_xor(c, step), step, dtype=np.uint32), c)


def generate_one(index: int) -> tuple[dict[str, np.ndarray], dict[str, dict[str, int]]]:
    if index not in INDICES + SMOKE_INDICES:
        raise ValueError("Index outside the fixed cohort and smoke indices")
    master, _ = _key_material(SEED, index)
    material = hashlib.shake_256(b"ff-intervention-nonces-v1:" + master).digest(32)
    bases = [material[8 * i:8 * (i + 1)] for i in range(4)]
    groups = []
    for base in bases:
        vertices = {base, *(changed_nonce(base, (bit,)) for bit in range(64)),
                    *(changed_nonce(base, tuple(pair["bits_msb_first"])) for pair in PANEL)}
        if len(vertices) != 103:
            raise AssertionError("Each nonce graph must have 103 distinct vertices")
        groups.append(vertices)
    if len(set.union(*groups)) != 412:
        raise AssertionError("The four nonce graphs must be disjoint")
    arrays = {name: np.empty(shape, dtype=np.uint32 if name.endswith("word7") or name == "salsa2_c" else np.uint8)
              for name, shape in RAW_SHAPES.items()}
    checks: dict[str, dict[str, int]] = {}
    for fi, family in enumerate(FAMILIES):
        label = family.encode() + b":"
        key = hashlib.blake2b(b"ff-intervention-key-v1:" + label + master, digest_size=32).digest()
        secret = hashlib.blake2b(b"ff-intervention-secret-v1:" + label + master, digest_size=32).digest()
        domain = b"ff-intervention-oracle-v1:" + label
        for ri, rounds in enumerate(ROUNDS):
            for bi, (base, vertices) in enumerate(zip(bases, groups)):
                actual, oracle = {}, {}
                for nonce in vertices:
                    actual[nonce] = finalized_words(key, nonce, family, rounds)
                    random_core = np.frombuffer(hashlib.shake_256(
                        domain + secret + rounds.to_bytes(2, "big") + nonce).digest(1024), dtype="<u4").reshape(16, 16)
                    oracle[nonce] = finalize(random_core, initial_blocks(key, nonce, family))
                for mask in range(64):
                    other = changed_nonce(base, (mask,))
                    for prefix, streams in (("observed", actual), ("oracle", oracle)):
                        arrays[f"{prefix}_singleton"][fi, ri, :, mask, bi] = difference_hw(streams[base], streams[other])
                    if fi == 1 and rounds == 2:
                        arrays["salsa2_singleton_word7"][:, mask, bi] = actual[base][..., 7] ^ actual[other][..., 7]
                if fi == 1 and rounds == 2:
                    cbase = actual[base][1, :, 7] ^ np.uint32(int.from_bytes(base[4:], "little"))
                    arrays["salsa2_c"][0, bi] = cbase
                    for mask in range(32):
                        other = changed_nonce(base, (mask,))
                        arrays["salsa2_c"][mask + 1, bi] = actual[other][1, :, 7] ^ np.uint32(int.from_bytes(other[4:], "little"))
                    for bit in range(32):
                        mask = global_bit(1, bit)
                        other = changed_nonce(base, (mask,))
                        c_other = actual[other][1, :, 7] ^ np.uint32(int.from_bytes(other[4:], "little"))
                        _record(checks, "salsa2_c_independent_of_second_word", c_other == cbase)
                        single = arrays["salsa2_singleton_word7"][:, mask, bi]
                        _record(checks, "salsa2_none_singleton_word7_exact_bit", single[1] == np.uint32(1 << bit))
                        _record(checks, "salsa2_xor_singleton_word7_zero", single[2] == 0)
                        _record(checks, "salsa2_add_singleton_word7_lb", single[0] == lb(cbase, bit))
                        if bit == 31:
                            _record(checks, "salsa2_add_msb_singleton_word7_zero", single[0] == 0)
                for pi, pair in enumerate(PANEL):
                    a, b = pair["bits_msb_first"]
                    vertex_list = (base, changed_nonce(base, (a,)), changed_nonce(base, (b,)), changed_nonce(base, (a, b)))
                    for prefix, streams in (("observed", actual), ("oracle", oracle)):
                        selected = [streams[v] for v in vertex_list]
                        derivative = xor_vertices(*selected)
                        arrays[f"{prefix}_d2"][fi, ri, :, pi, bi] = difference_hw(*selected)
                        arrays[f"{prefix}_d2_word7"][fi, ri, :, pi, bi] = derivative[..., 7]
                        _record(checks, f"{prefix}_d2_none_equals_xor_all_words", derivative[1] == derivative[2])
                    if fi == 1 and rounds == 2:
                        values = arrays["observed_d2_word7"][fi, ri, :, pi, bi]
                        if pair["kind"] == "within":
                            _record(checks, "salsa2_within_second_word_d2_word7_all_variants_zero", values == 0)
                        else:
                            _record(checks, "salsa2_mixed_d2_word7_none_xor_zero", values[1:] == 0)
                            bit = pair["word_bits_lsb"][1][1]
                            expected = lb(arrays["salsa2_c"][a + 1, bi], bit) ^ lb(arrays["salsa2_c"][0, bi], bit)
                            _record(checks, "salsa2_mixed_add_d2_word7_conditional_lb", values[0] == expected)
                            if bit == 31:
                                _record(checks, "salsa2_mixed_msb_add_d2_word7_zero", values[0] == 0)
    return arrays, checks


def generate(directory: Path, indices: tuple[int, ...]) -> dict[str, object]:
    directory.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = directory / "checkpoints"
    checkpoint_dir.mkdir(exist_ok=True)
    spec = specification(indices)
    token = fingerprint(spec)
    manifest_path = directory / "generation_manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text())["fingerprint"] != token:
        raise AssertionError("Resume rejected: fingerprint changed")
    manifest = {**spec, "fingerprint": token, "status": "generating", "smoke": indices == SMOKE_INDICES,
                "reference": "SHAKE256 working stream per nonce; actual initial state shared across add/none/xor transformations"}
    save_json(manifest_path, manifest)
    collected = {name: [] for name in RAW_SHAPES}
    checks: dict[str, dict[str, int]] = {}
    checkpoint_hashes = {}
    started = perf_counter()
    for completed, index in enumerate(indices, 1):
        path = checkpoint_dir / f"key_{index}.npz"
        metadata = path.with_suffix(".json")
        if metadata.exists():
            old = json.loads(metadata.read_text())
            if old["fingerprint"] != token or old["key_index"] != index or sha256(path) != old["raw_sha256"]:
                raise AssertionError(f"Invalid checkpoint {index}")
            with np.load(path) as raw:
                arrays = {name: raw[name] for name in RAW_SHAPES}
            local = old["structural_checks"]
        else:
            arrays, local = generate_one(index)
            save_npz(path, arrays)
            save_json(metadata, {"fingerprint": token, "key_index": index,
                                 "raw_sha256": sha256(path), "structural_checks": local})
        for name, shape in RAW_SHAPES.items():
            if arrays[name].shape != shape:
                raise AssertionError(f"Wrong raw shape: {name}")
            if name.endswith(("singleton", "d2")) and arrays[name].max() > 32:
                raise AssertionError(f"HW32 outside range: {name}")
            collected[name].append(arrays[name])
        for name, value in local.items():
            total = checks.setdefault(name, {"comparisons": 0, "violations": 0})
            for field in total:
                total[field] += value[field]
        checkpoint_hashes[path.name] = sha256(path)
        if completed % 10 == 0 or completed == len(indices):
            print(f"Feed-forward generation {completed}/{len(indices)} keys; {perf_counter()-started:.1f}s", flush=True)
    if specification(indices) != spec:
        raise AssertionError("Source or protocol changed during generation")
    final = {name: np.stack(values) for name, values in collected.items()}
    final["key_indices"] = np.asarray(indices, dtype=np.int32)
    raw_path = directory / "arx_feedforward_raw.npz"
    save_npz(raw_path, final)
    manifest.update(status="complete", raw_sha256=sha256(raw_path), checkpoint_sha256=checkpoint_hashes,
                    structural_checks=checks, generation_elapsed_seconds=perf_counter()-started)
    save_json(manifest_path, manifest)
    if any(check["violations"] for check in checks.values()):
        raise AssertionError(f"Deterministic prediction violation; raw data retained: {checks}")
    return manifest


def summarize(rows: list[dict[str, object]], axes: tuple[str, ...], metrics: tuple[str, ...],
              indices: np.ndarray, draws: np.ndarray) -> list[dict[str, object]]:
    groups: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault(tuple(row[name] for name in axes), []).append(row)
    result = []
    for identity, group in groups.items():
        group.sort(key=lambda row: int(row["key_index"]))
        if [row["key_index"] for row in group] != indices.tolist():
            raise AssertionError("Each summary must retain exactly one observation per entire key")
        values = np.asarray([[row[name] for name in metrics] for row in group], dtype=float)
        boot = values[draws].mean(axis=1)
        limits = np.quantile(boot, (0.025, 0.975), axis=0)
        row = dict(zip(axes, identity))
        row["n_keys"] = len(indices)
        for column, name in enumerate(metrics):
            row[f"{name}_mean"] = float(values[:, column].mean())
            row[f"{name}_ci95_low"] = float(limits[0, column])
            row[f"{name}_ci95_high"] = float(limits[1, column])
        result.append(row)
    return result


def analyze(directory: Path) -> dict[str, object]:
    generation_path = directory / "generation_manifest.json"
    generation = json.loads(generation_path.read_text())
    indices_tuple = tuple(generation["key_indices"])
    if generation["status"] != "complete" or fingerprint(specification(indices_tuple)) != generation["fingerprint"]:
        raise AssertionError("Only complete data with matching source/protocol hashes can be analyzed")
    raw_path = directory / "arx_feedforward_raw.npz"
    if sha256(raw_path) != generation["raw_sha256"]:
        raise AssertionError("Raw data hash changed")
    with np.load(raw_path) as raw:
        arrays = {name: raw[name] for name in RAW_SHAPES}
        indices = raw["key_indices"]
    np.testing.assert_array_equal(indices, indices_tuple)
    for name, shape in RAW_SHAPES.items():
        if arrays[name].shape != (len(indices), *shape):
            raise AssertionError(f"Wrong raw axes: {name}")
    draws = np.random.default_rng(BOOT_SEED).integers(0, len(indices), (BOOTSTRAPS, len(indices)), dtype=np.int16)
    per_key = []
    paired = []
    gaps = {}
    for fi, family in enumerate(FAMILIES):
        for ri, rounds in enumerate(ROUNDS):
            for segment in (32, 64, 128):
                local = {}
                for vi, variant in enumerate(FINALIZATIONS):
                    measured = [measure(aggregate_words(arrays[f"{prefix}_singleton"][:, fi, ri, vi], segment, 0, 16), segment)
                                for prefix in ("observed", "oracle")]
                    endpoints = {}
                    for name in METRICS:
                        actual, control = measured[0][name], measured[1][name]
                        delta = actual - control
                        endpoints[f"actual_{name}"] = actual.mean(axis=-1)
                        endpoints[f"control_{name}"] = control.mean(axis=-1)
                        endpoints[f"delta_{name}"] = delta.mean(axis=-1)
                        endpoints[f"word_gap_delta_{name}"] = (delta[:, 32:] - delta[:, :32]).mean(axis=-1)
                    local[variant] = endpoints["word_gap_delta_hmp"]
                    gaps[family, rounds, segment, variant] = local[variant]
                    for ki, key in enumerate(indices):
                        per_key.append({"key_index": int(key), "family": family, "rounds": rounds,
                                        "segment_bits": segment, "variant": variant,
                                        **{name: float(values[ki]) for name, values in endpoints.items()}})
                for ki, key in enumerate(indices):
                    paired.append({"key_index": int(key), "family": family, "rounds": rounds,
                                   "segment_bits": segment,
                                   "G_add_minus_none": float(local["add"][ki] - local["none"][ki]),
                                   "G_add_minus_xor": float(local["add"][ki] - local["xor"][ki])})
            print(f"Feed-forward analysis {family}/{rounds}: singleton metrics complete", flush=True)
    endpoint_names = tuple(name for name in per_key[0] if name not in ("key_index", "family", "rounds", "segment_bits", "variant"))
    summary = summarize(per_key, ("family", "rounds", "segment_bits", "variant"), endpoint_names, indices, draws)
    paired_summary = summarize(paired, ("family", "rounds", "segment_bits"),
                               ("G_add_minus_none", "G_add_minus_xor"), indices, draws)
    save_csv(directory / "arx_feedforward_per_key.csv", per_key)
    save_csv(directory / "arx_feedforward_summary.csv", summary)
    save_csv(directory / "arx_feedforward_paired_per_key.csv", paired)
    save_csv(directory / "arx_feedforward_paired_summary.csv", paired_summary)

    singleton_profiles = []
    d2_profiles = []
    pair_profiles = []
    interactions = []
    j_values = {}
    for fi, family in enumerate(FAMILIES):
        for ri, rounds in enumerate(ROUNDS):
            local_interaction = {}
            for vi, variant in enumerate(FINALIZATIONS):
                for group, masks in (("nonce_word_1", list(range(32))), ("nonce_word_2", list(range(32, 64)))):
                    values = [arrays[f"{prefix}_singleton"][:, fi, ri, vi][:, masks].mean(axis=(1, 2, 3))
                              for prefix in ("observed", "oracle")]
                    for ki, key in enumerate(indices):
                        for word in range(16):
                            observed, control = (float(x[ki, word]) for x in values)
                            singleton_profiles.append({"key_index": int(key), "family": family, "rounds": rounds,
                                                       "variant": variant, "group": group, "word": word,
                                                       "observed": observed, "control": control, "delta": observed-control})
                for group, masks in GROUPS.items():
                    values = [arrays[f"{prefix}_d2"][:, fi, ri, vi][:, masks].mean(axis=(1, 2, 3))
                              for prefix in ("observed", "oracle")]
                    if group == "aligned_nonmsb31":
                        local_interaction[f"A_{variant}_observed"] = values[0][:, 7]
                        local_interaction[f"A_{variant}_control"] = values[1][:, 7]
                    for ki, key in enumerate(indices):
                        for word in range(16):
                            observed, control = (float(x[ki, word]) for x in values)
                            d2_profiles.append({"key_index": int(key), "family": family, "rounds": rounds,
                                                "variant": variant, "group": group, "word": word,
                                                "observed": observed, "control": control, "delta": observed-control})
                values = [arrays[f"{prefix}_d2"][:, fi, ri, vi, :, :, :, 7].mean(axis=(-2, -1))
                          for prefix in ("observed", "oracle")]
                for ki, key in enumerate(indices):
                    for pi, panel in enumerate(PANEL):
                        observed, control = (float(x[ki, pi]) for x in values)
                        pair_profiles.append({"key_index": int(key), "family": family, "rounds": rounds,
                                              "variant": variant, "pair_index": pi, "pair_name": panel["name"],
                                              "kind": panel["kind"], "observed": observed,
                                              "control": control, "delta": observed-control})
            local_interaction["J"] = ((local_interaction["A_add_observed"] - local_interaction["A_none_observed"])
                                       - (local_interaction["A_add_control"] - local_interaction["A_none_control"]))
            j_values[family, rounds] = local_interaction["J"]
            for ki, key in enumerate(indices):
                interactions.append({"key_index": int(key), "family": family, "rounds": rounds,
                                     **{name: float(x[ki]) for name, x in local_interaction.items()}})
    for name, rows in (("singleton", singleton_profiles), ("d2", d2_profiles)):
        save_csv(directory / f"per_key_{name}_profiles.csv", rows)
        save_csv(directory / f"{name}_profiles_summary.csv", summarize(
            rows, ("family", "rounds", "variant", "group", "word"), ("observed", "control", "delta"), indices, draws))
    save_csv(directory / "per_key_d2_word7_pairs.csv", pair_profiles)
    save_csv(directory / "d2_word7_pairs_summary.csv", summarize(
        pair_profiles, ("family", "rounds", "variant", "pair_index", "pair_name", "kind"),
        ("observed", "control", "delta"), indices, draws))
    save_csv(directory / "interaction_per_key.csv", interactions)
    interaction_metrics = tuple(name for name in interactions[0] if name not in ("key_index", "family", "rounds"))
    save_csv(directory / "interaction_summary.csv", summarize(interactions, ("family", "rounds"), interaction_metrics, indices, draws))

    values = np.column_stack((gaps["Salsa20", 2, 128, "none"],
                              gaps["Salsa20", 2, 128, "add"] - gaps["Salsa20", 2, 128, "none"],
                              gaps["ChaCha20", 2, 128, "add"] - gaps["ChaCha20", 2, 128, "none"],
                              j_values["Salsa20", 2]))
    pvalues, extremes = sign_flip_pvalues(values, SIGN_FLIPS, SIGN_SEED)
    adjusted = holm(pvalues)
    limits = np.quantile(values[draws].mean(axis=1), (0.025, 0.975), axis=0)
    labels = ("Salsa20 G_none", "Salsa20 G_add minus G_none", "ChaCha20 G_add minus G_none", "Salsa20 mixed output-word-7 interaction J")
    planned = []
    for column, label in enumerate(labels):
        planned.append({"endpoint": f"E{column+1}", "label": label,
                        "family": "ChaCha20" if column == 2 else "Salsa20", "rounds": 2,
                        "n_keys": len(indices), "mean": float(values[:, column].mean()),
                        "ci95_low": float(limits[0, column]), "ci95_high": float(limits[1, column]),
                        "unit": "bits" if column < 3 else "changed_bits_per_output_word",
                        "sign_flip_extremes": int(extremes[column]), "replicates": SIGN_FLIPS,
                        "p_two_sided_plus_one": float(pvalues[column]), "p_holm_four": float(adjusted[column]),
                        "cohort": "smoke_only" if generation["smoke"] else "independent_followup"})
    save_csv(directory / "arx_feedforward_planned_tests.csv", planned)
    save_json(directory / "structural_checks.json", generation["structural_checks"])
    manifest = {**specification(indices_tuple),
                "status": "smoke_complete" if generation["smoke"] else "completed_independent_followup",
                "generation_manifest_sha256": sha256(generation_path), "raw_sha256": sha256(raw_path),
                "power_estimator": "Mean of Q=4 complete Fourier powers per singleton mask before normalization",
                "window": "full8192", "segment_bits": [32, 64, 128],
                "contrast_order": "observed minus reference; G second nonce word minus first, matching bit positions",
                "intervention_reference": "Same random working R(vertex), three actual-X finalizations; R reused across shared vertices",
                "bootstrap": {"replicates": BOOTSTRAPS, "seed": BOOT_SEED, "unit": "whole master-key pair",
                              "interval": "pointwise percentile 95%; shared draws across all variants and metrics"},
                "sign_flip": {"replicates": SIGN_FLIPS, "seed": SIGN_SEED, "unit": "whole master-key pair",
                              "statistic": "absolute mean", "roundoff_tolerance": "1e-12 * max(1,abs(mean))",
                              "pvalue": "(extremes+1)/(replicates+1)", "holm_family": ["E1", "E2", "E3", "E4"]},
                "planned_endpoints": labels, "d2_groups": GROUPS,
                "structural_checks": generation["structural_checks"],
                "output_rows": {"per_key": len(per_key), "summary": len(summary), "planned": len(planned),
                                "d2_profiles_per_key": len(d2_profiles)},
                "output_sha256": {path.name: sha256(path) for path in sorted(directory.glob("*.csv"))}}
    save_json(directory / "arx_feedforward_manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--analyze-only", action="store_true")
    args = parser.parse_args()
    directory = args.output or (Path("/tmp/arx_feedforward_smoke") if args.smoke else OUT)
    if args.smoke and not directory.resolve().is_relative_to(Path("/tmp")):
        parser.error("Smoke data must be written under /tmp")
    if not args.analyze_only:
        generate(directory, SMOKE_INDICES if args.smoke else INDICES)
    result = analyze(directory)
    print(json.dumps({"status": result["status"], "rows": result["output_rows"],
                      "structural_checks": result["structural_checks"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
