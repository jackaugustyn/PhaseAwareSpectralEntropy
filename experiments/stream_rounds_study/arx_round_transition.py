#!/usr/bin/env python3
"""Prospective single-round ARX transition study with named operation witnesses.

All existing cipher implementations and earlier cohorts remain unchanged.
The vector evaluator executes individual column/row/diagonal rounds, never
rounding an odd request to an even number of rounds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from arx_feedforward_study import (PANEL, GROUPS, FINALIZATIONS, changed_nonce,
                                  initial_blocks, save_csv, save_json, save_npz,
                                  sha256, fingerprint, summarize)
from arx_resolution_validation import aggregate_words, holm, sign_flip_pvalues
from analyze_arx_resolution import measure, METRICS
from publication_study import _key_material

PROTOCOL = ROOT / "doc_stream_ciphers/ARX_ROUND_TRANSITION_PROTOCOL.txt"
PROTOCOL_SHA256 = "88a8b1812f32af7904c6a5b656350a047bac87804ca7209a551ae99360a6f6b1"
OUT = ROOT / "doc_stream_ciphers/data/arx_round_transition"
FAMILIES = ("ChaCha20", "Salsa20")
ROUNDS = (2, 3, 4)
INDICES = tuple(range(1400, 1480))
SMOKE_INDICES = (1480, 1481)
SEED, SIGN_SEED, BOOT_SEED = 20261031, 2026103105, 2026103106
SIGN_FLIPS, BOOTSTRAPS = 100000, 5000
CHECKPOINTS = ("round3_column_qr_15_3_7_11_before_c",
               "round3_column_qr_15_3_7_11_after_c")
POPCOUNT = np.asarray([i.bit_count() for i in range(256)], dtype=np.uint8)
RAW_SHAPES = {
    "observed_singleton": (2, 3, 3, 64, 4, 16, 16),
    "oracle_singleton": (2, 3, 3, 64, 4, 16, 16),
    "observed_d2": (2, 3, 3, 38, 4, 16, 16),
    "oracle_d2": (2, 3, 3, 38, 4, 16, 16),
    "observed_d2_word7": (2, 3, 3, 38, 4, 16),
    "oracle_d2_word7": (2, 3, 3, 38, 4, 16),
    "salsa3_checkpoint_d2_word7": (2, 2, 4, 16),
}
RAW_AXES = {
    "singleton": ["key", "cipher", "round", "variant", "mask_msb_first", "base", "block512", "word32"],
    "d2": ["key", "cipher", "round", "variant", "panel_pair", "base", "block512", "word32"],
    "d2_word7": ["key", "cipher", "round", "variant", "panel_pair", "base", "block512"],
    "salsa3_checkpoint_d2_word7": ["key", "named_operation_checkpoint", "within_second_word_pair", "base", "block512"],
}


def _rot(x: np.ndarray, bits: int) -> np.ndarray:
    return (x << np.uint32(bits)) | (x >> np.uint32(32 - bits))


def working_rounds(initial: np.ndarray, family: str,
                   rounds: tuple[int, ...] = ROUNDS) -> tuple[np.ndarray, dict[str, np.ndarray]]:
    """Return requested working states and Salsa's named third-round word-7 states.

    The first axis of the returned state indexes requested SINGLE rounds.
    Remaining leading axes are arbitrary batches, followed by 16 words.
    """
    if family not in FAMILIES or not rounds or tuple(sorted(set(rounds))) != rounds:
        raise ValueError("Expected supported cipher and increasing distinct single rounds")
    if rounds[0] < 1 or rounds[-1] > 20:
        raise ValueError("Single-round requests must be between 1 and 20")
    state = np.asarray(initial, dtype=np.uint32).copy()
    if state.shape[-1:] != (16,):
        raise ValueError("A state must contain 16 uint32 words")
    snapshots, checkpoints = [], {}
    for r in range(1, rounds[-1] + 1):
        if family == "ChaCha20":
            schedule = (((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
                        if r % 2 else
                        ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)))
        else:
            schedule = (((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11))
                        if r % 2 else
                        ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)))
        for a, b, c, d in schedule:
            if family == "ChaCha20":
                state[..., a] += state[..., b]
                state[..., d] = _rot(state[..., d] ^ state[..., a], 16)
                state[..., c] += state[..., d]
                state[..., b] = _rot(state[..., b] ^ state[..., c], 12)
                state[..., a] += state[..., b]
                state[..., d] = _rot(state[..., d] ^ state[..., a], 8)
                state[..., c] += state[..., d]
                state[..., b] = _rot(state[..., b] ^ state[..., c], 7)
            else:
                state[..., b] ^= _rot(state[..., a] + state[..., d], 7)
                selected = r == 3 and (a, b, c, d) == (15, 3, 7, 11)
                if selected:
                    checkpoints[CHECKPOINTS[0]] = state[..., 7].copy()
                state[..., c] ^= _rot(state[..., b] + state[..., a], 9)
                if selected:
                    checkpoints[CHECKPOINTS[1]] = state[..., 7].copy()
                state[..., d] ^= _rot(state[..., c] + state[..., b], 13)
                state[..., a] ^= _rot(state[..., d] + state[..., c], 18)
        if r in rounds:
            snapshots.append(state.copy())
    return np.stack(snapshots), checkpoints


def finalize_rounds(working: np.ndarray, initial: np.ndarray) -> np.ndarray:
    """Output axes: round, variant(add/none/xor), then initial-state axes."""
    w, x = np.asarray(working, dtype=np.uint32), np.asarray(initial, dtype=np.uint32)
    if w.shape[1:] != x.shape:
        raise ValueError("Working states must have one leading round axis")
    return np.stack((np.add(w, x, dtype=np.uint32), w, w ^ x), axis=1)


def hw32(values: np.ndarray) -> np.ndarray:
    x = np.asarray(values, dtype="<u4")
    octets = np.ascontiguousarray(x).view(np.uint8).reshape(*x.shape, 4)
    return POPCOUNT[octets].sum(axis=-1, dtype=np.uint8)


def cohort_inputs(index: int) -> tuple[bytes, list[bytes], list[bytes]]:
    if index not in INDICES + SMOKE_INDICES:
        raise ValueError("Index outside fixed final or smoke cohorts")
    master, _ = _key_material(SEED, index)
    material = hashlib.shake_256(b"rt-single-round-nonces-v1:" + master).digest(32)
    bases = [material[8*b:8*(b+1)] for b in range(4)]
    vertices = []
    for base in bases:
        group = [base] + [changed_nonce(base, (bit,)) for bit in range(64)]
        group += [changed_nonce(base, tuple(pair["bits_msb_first"])) for pair in PANEL]
        if len(set(group)) != 103:
            raise AssertionError("Each base must have 103 distinct vertices")
        vertices.extend(group)
    if len(set(vertices)) != 412:
        raise AssertionError("The four nonce graphs must be disjoint")
    return master, bases, vertices


def initial_vertex_blocks(key: bytes, vertices: list[bytes], family: str) -> np.ndarray:
    source = np.broadcast_to(initial_blocks(key, bytes(8), family), (len(vertices), 16, 16)).copy()
    n = np.frombuffer(b"".join(vertices), dtype="<u4").reshape(len(vertices), 2)
    a, b = (14, 15) if family == "ChaCha20" else (6, 7)
    source[..., a], source[..., b] = n[:, 0, None], n[:, 1, None]
    return source


def derivative_vertices(values: np.ndarray, order: int) -> np.ndarray:
    """Vertex axis is -3 (then block, word); output replaces it by mask,base."""
    if values.shape[-3:] != (412, 16, 16) or order not in (1, 2):
        raise ValueError("Expected 412 nonce vertices and order 1 or 2")
    bases = 103 * np.arange(4)
    if order == 1:
        indices = bases[None, :] + np.arange(1, 65)[:, None]
        return values[..., bases, :, :][..., None, :, :, :] ^ values[..., indices, :, :]
    pairs = np.asarray([p["bits_msb_first"] for p in PANEL])
    ia = bases[None, :] + pairs[:, 0, None] + 1
    ib = bases[None, :] + pairs[:, 1, None] + 1
    iab = bases[None, :] + np.arange(65, 103)[:, None]
    return (values[..., bases, :, :][..., None, :, :, :] ^ values[..., ia, :, :]
            ^ values[..., ib, :, :] ^ values[..., iab, :, :])


def _record(checks: dict, name: str, equalities: np.ndarray) -> None:
    x = np.asarray(equalities, dtype=bool)
    checks[name] = {"comparisons": int(x.size), "violations": int(np.count_nonzero(~x))}


def generate_one(index: int) -> tuple[dict[str, np.ndarray], dict]:
    master, _, vertices = cohort_inputs(index)
    arrays = {name: np.empty(shape, dtype=np.uint32 if name.endswith("word7") else np.uint8)
              for name, shape in RAW_SHAPES.items()}
    checks = {}
    for fi, family in enumerate(FAMILIES):
        suffix = family.encode() + b":"
        key = hashlib.blake2b(b"rt-single-round-key-v1:" + suffix + master, digest_size=32).digest()
        secret = hashlib.blake2b(b"rt-single-round-secret-v1:" + suffix + master, digest_size=32).digest()
        source = initial_vertex_blocks(key, vertices, family)
        working, checkpoints = working_rounds(source, family)
        oracle = np.stack([np.stack([np.frombuffer(hashlib.shake_256(
            b"rt-single-round-oracle-v1:" + suffix + secret + r.to_bytes(2, "big") + nonce
        ).digest(1024), dtype="<u4").reshape(16, 16) for nonce in vertices]) for r in ROUNDS])
        for prefix, states in (("observed", working), ("oracle", oracle)):
            emitted = finalize_rounds(states, source)
            singleton = derivative_vertices(emitted, 1)
            d2 = derivative_vertices(emitted, 2)
            arrays[prefix + "_singleton"][fi] = hw32(singleton)
            arrays[prefix + "_d2"][fi] = hw32(d2)
            arrays[prefix + "_d2_word7"][fi] = d2[..., 7]
            _record(checks, prefix + "_" + family + "_d2_none_equals_xor_all_words", d2[:, 1] == d2[:, 2])
        if family == "Salsa20":
            _record(checks, "salsa2_within_second_word_word7_zero_all_variants",
                    arrays["observed_d2_word7"][fi, 0, :, 36:38] == 0)
            _record(checks, "salsa3_checkpoint_before_c_equals_round2_word7",
                    checkpoints[CHECKPOINTS[0]] == working[0, ..., 7])
            _record(checks, "salsa3_checkpoint_after_c_equals_round3_word7",
                    checkpoints[CHECKPOINTS[1]] == working[1, ..., 7])
            for ci, name in enumerate(CHECKPOINTS):
                # Embedding in a temporary word axis uses the same verified vertex map.
                cp = np.zeros((412, 16, 16), dtype=np.uint32)
                cp[..., 7] = checkpoints[name]
                arrays["salsa3_checkpoint_d2_word7"][ci] = derivative_vertices(cp, 2)[36:38, ..., 7]
            _record(checks, "salsa3_within_second_word_d2_before_c_zero",
                    arrays["salsa3_checkpoint_d2_word7"][0] == 0)
    return arrays, checks


def source_hashes() -> dict[str, str]:
    names = ("arx_round_transition.py", "arx_feedforward_study.py", "arx_mechanism_analysis.py",
             "arx_resolution_validation.py", "analyze_arx_resolution.py", "publication_study.py",
             "literature_mask_followup.py", "extension_stream_cores.py")
    paths = [Path(__file__).with_name(name) for name in names]
    paths.append(ROOT / "src/spectral_crypto_analyzer/primitives.py")
    return {str(p.relative_to(ROOT)): sha256(p) for p in paths}


def specification(indices: tuple[int, ...]) -> dict:
    if sha256(PROTOCOL) != PROTOCOL_SHA256 or indices not in (INDICES, SMOKE_INDICES):
        raise AssertionError("Protocol hash or fixed cohort does not match")
    return {"protocol_sha256": PROTOCOL_SHA256, "source_sha256": source_hashes(),
            "key_indices": list(indices), "seed": SEED, "families": list(FAMILIES),
            "rounds": list(ROUNDS), "variants": list(FINALIZATIONS), "panel": PANEL,
            "operation_checkpoints": list(CHECKPOINTS), "raw_axes": RAW_AXES,
            "raw_per_key_shapes": {n: list(s) for n, s in RAW_SHAPES.items()},
            "reference": "Separate R_r(v) by round; shared across finalizations within a round",
            "numpy_version": np.__version__, "python_version": platform.python_version()}


def generate(directory: Path, indices: tuple[int, ...]) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = directory / "checkpoints"
    checkpoint_dir.mkdir(exist_ok=True)
    spec = specification(indices)
    token = fingerprint(spec)
    manifest_path = directory / "generation_manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text())["fingerprint"] != token:
        raise AssertionError("Resume rejected: source, protocol or cohort fingerprint changed")
    manifest = {**spec, "fingerprint": token, "status": "generating", "smoke": indices == SMOKE_INDICES}
    save_json(manifest_path, manifest)
    collected = {name: [] for name in RAW_SHAPES}
    checks, checkpoint_hashes = {}, {}
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
            save_json(metadata, {"fingerprint": token, "key_index": index, "raw_sha256": sha256(path),
                                 "structural_checks": local})
        for name, shape in RAW_SHAPES.items():
            expected_dtype = np.uint32 if name.endswith("word7") else np.uint8
            if arrays[name].shape != shape or arrays[name].dtype != expected_dtype:
                raise AssertionError(f"Invalid raw array {name}")
            if expected_dtype == np.uint8 and arrays[name].max() > 32:
                raise AssertionError("HW32 out of range")
            collected[name].append(arrays[name])
        for name, value in local.items():
            total = checks.setdefault(name, {"comparisons": 0, "violations": 0})
            for field in total:
                total[field] += value[field]
        checkpoint_hashes[path.name] = sha256(path)
        if completed % 10 == 0 or completed == len(indices):
            print(f"Round-transition generation {completed}/{len(indices)} keys; {perf_counter()-started:.1f}s", flush=True)
    if specification(indices) != spec:
        raise AssertionError("Source or protocol changed during generation")
    final = {name: np.stack(values) for name, values in collected.items()}
    final["key_indices"] = np.asarray(indices, dtype=np.int32)
    raw_path = directory / "arx_round_transition_raw.npz"
    save_npz(raw_path, final)
    manifest.update(status="complete", raw_sha256=sha256(raw_path), checkpoint_sha256=checkpoint_hashes,
                    structural_checks=checks, generation_elapsed_seconds=perf_counter()-started)
    save_json(manifest_path, manifest)
    if any(x["violations"] for x in checks.values()):
        raise AssertionError("Deterministic invariant failed; raw data retained")
    return manifest


def analyze(directory: Path) -> dict:
    generation_path = directory / "generation_manifest.json"
    generation = json.loads(generation_path.read_text())
    cohort = tuple(generation["key_indices"])
    if generation["status"] != "complete" or fingerprint(specification(cohort)) != generation["fingerprint"]:
        raise AssertionError("Analysis requires completed data and matching source/protocol hashes")
    raw_path = directory / "arx_round_transition_raw.npz"
    if sha256(raw_path) != generation["raw_sha256"]:
        raise AssertionError("Raw data hash changed")
    with np.load(raw_path) as raw:
        arrays = {name: raw[name] for name in RAW_SHAPES}
        indices = raw["key_indices"]
    np.testing.assert_array_equal(indices, cohort)
    for name, shape in RAW_SHAPES.items():
        if arrays[name].shape != (len(indices), *shape):
            raise AssertionError(f"Wrong raw axes: {name}")
    draws = np.random.default_rng(BOOT_SEED).integers(0, len(indices), (BOOTSTRAPS, len(indices)), dtype=np.int16)

    singletons, spectral = [], {}
    for fi, family in enumerate(FAMILIES):
        for ri, r in enumerate(ROUNDS):
            for vi, variant in enumerate(FINALIZATIONS):
                for width in (32, 64, 128):
                    observed, reference = [measure(aggregate_words(
                        arrays[prefix + "_singleton"][:, fi, ri, vi], width, 0, 16), width)
                        for prefix in ("observed", "oracle")]
                    metrics = {}
                    for name in METRICS:
                        a, c = observed[name], reference[name]
                        metrics["actual_" + name] = a.mean(axis=-1)
                        metrics["control_" + name] = c.mean(axis=-1)
                        metrics["delta_" + name] = (a-c).mean(axis=-1)
                        metrics["word_gap_delta_" + name] = ((a-c)[:, 32:] - (a-c)[:, :32]).mean(axis=-1)
                    spectral[family, r, variant, width] = metrics
                    for ki, key in enumerate(indices):
                        singletons.append({"key_index": int(key), "family": family, "rounds": r,
                                           "variant": variant, "segment_bits": width,
                                           **{name: float(x[ki]) for name, x in metrics.items()}})
            print(f"Round-transition analysis {family}/{r}: singleton metrics complete", flush=True)
    fields = tuple(n for n in singletons[0] if n not in ("key_index", "family", "rounds", "variant", "segment_bits"))
    save_csv(directory / "singleton_per_key.csv", singletons)
    save_csv(directory / "singleton_summary.csv", summarize(singletons,
             ("family", "rounds", "variant", "segment_bits"), fields, indices, draws))

    profiles, pairs, interaction_rows, within_rows = [], [], [], []
    j_values, within_values = {}, {}
    for fi, family in enumerate(FAMILIES):
        for ri, r in enumerate(ROUNDS):
            interaction = {}
            for vi, variant in enumerate(FINALIZATIONS):
                for group, masks in GROUPS.items():
                    a, c = [arrays[prefix + "_d2"][:, fi, ri, vi][:, masks].mean(axis=(1, 2, 3))
                            for prefix in ("observed", "oracle")]
                    if group == "aligned_nonmsb31":
                        interaction[f"A_{variant}_observed"] = a[:, 7]
                        interaction[f"A_{variant}_control"] = c[:, 7]
                    if group == "within2":
                        delta = a[:, 7] - c[:, 7]
                        within_values[family, r, variant] = (a[:, 7], c[:, 7], delta)
                        word_values = arrays["observed_d2_word7"][:, fi, ri, vi, 36:38]
                        zero_fraction = (word_values == 0).mean(axis=(1, 2, 3))
                        for ki, key in enumerate(indices):
                            within_rows.append({"key_index": int(key), "family": family, "rounds": r,
                                                "variant": variant, "observed": float(a[ki, 7]),
                                                "control": float(c[ki, 7]), "delta": float(delta[ki]),
                                                "observed_zero_fraction": float(zero_fraction[ki])})
                    for ki, key in enumerate(indices):
                        for word in range(16):
                            profiles.append({"key_index": int(key), "family": family, "rounds": r,
                                             "variant": variant, "group": group, "word": word,
                                             "observed": float(a[ki, word]), "control": float(c[ki, word]),
                                             "delta": float(a[ki, word]-c[ki, word])})
                a, c = [arrays[prefix + "_d2"][:, fi, ri, vi, :, :, :, 7].mean(axis=(-2, -1))
                        for prefix in ("observed", "oracle")]
                for ki, key in enumerate(indices):
                    for pi, pair in enumerate(PANEL):
                        pairs.append({"key_index": int(key), "family": family, "rounds": r,
                                      "variant": variant, "pair_index": pi, "pair_name": pair["name"],
                                      "kind": pair["kind"], "observed": float(a[ki, pi]),
                                      "control": float(c[ki, pi]), "delta": float(a[ki, pi]-c[ki, pi])})
            interaction["J"] = ((interaction["A_add_observed"] - interaction["A_none_observed"])
                                  - (interaction["A_add_control"] - interaction["A_none_control"]))
            j_values[family, r] = interaction["J"]
            for ki, key in enumerate(indices):
                interaction_rows.append({"key_index": int(key), "family": family, "rounds": r,
                                         **{n: float(x[ki]) for n, x in interaction.items()}})
    save_csv(directory / "d2_profiles_per_key.csv", profiles)
    save_csv(directory / "d2_profiles_summary.csv", summarize(profiles,
             ("family", "rounds", "variant", "group", "word"), ("observed", "control", "delta"), indices, draws))
    save_csv(directory / "d2_word7_pairs_per_key.csv", pairs)
    save_csv(directory / "d2_word7_pairs_summary.csv", summarize(pairs,
             ("family", "rounds", "variant", "pair_index", "pair_name", "kind"), ("observed", "control", "delta"), indices, draws))
    save_csv(directory / "within_word_per_key.csv", within_rows)
    save_csv(directory / "within_word_summary.csv", summarize(within_rows,
             ("family", "rounds", "variant"), ("observed", "control", "delta", "observed_zero_fraction"), indices, draws))
    fields = tuple(n for n in interaction_rows[0] if n not in ("key_index", "family", "rounds"))
    save_csv(directory / "interaction_per_key.csv", interaction_rows)
    save_csv(directory / "interaction_summary.csv", summarize(interaction_rows,
             ("family", "rounds"), fields, indices, draws))

    transitions = []
    for family in FAMILIES:
        for before, after in ((2, 3), (3, 4), (2, 4)):
            for variant in FINALIZATIONS:
                w0, w1 = within_values[family, before, variant], within_values[family, after, variant]
                for width in (32, 64, 128):
                    s0, s1 = spectral[family, before, variant, width], spectral[family, after, variant, width]
                    metrics = {
                        "within_word7_observed_change": w1[0]-w0[0],
                        "within_word7_control_change": w1[1]-w0[1],
                        "within_word7_delta_change": w1[2]-w0[2],
                        "delta_F512_change": s1["delta_block_fundamental_share"]-s0["delta_block_fundamental_share"],
                        "delta_G_change": s1["word_gap_delta_hmp"]-s0["word_gap_delta_hmp"],
                        "J_change": j_values[family, after]-j_values[family, before],
                    }
                    for ki, key in enumerate(indices):
                        transitions.append({"key_index": int(key), "family": family, "round_before": before,
                                            "round_after": after, "variant": variant, "segment_bits": width,
                                            **{n: float(x[ki]) for n, x in metrics.items()}})
    fields = tuple(n for n in transitions[0] if n not in
                   ("key_index", "family", "round_before", "round_after", "variant", "segment_bits"))
    save_csv(directory / "transition_per_key.csv", transitions)
    save_csv(directory / "transition_summary.csv", summarize(transitions,
             ("family", "round_before", "round_after", "variant", "segment_bits"), fields, indices, draws))

    checkpoints, checkpoint_counts = [], {}
    for ci, name in enumerate(CHECKPOINTS):
        witnesses = arrays["salsa3_checkpoint_d2_word7"][:, ci]
        values = hw32(witnesses)
        checkpoint_counts[name] = {"word_comparisons": int(witnesses.size),
                                   "zero_words": int(np.count_nonzero(witnesses == 0)),
                                   "nonzero_words": int(np.count_nonzero(witnesses))}
        for pi, panel_index in enumerate((36, 37)):
            mean_hw = values[:, pi].mean(axis=(1, 2))
            zero_fraction = (witnesses[:, pi] == 0).mean(axis=(1, 2))
            for ki, key in enumerate(indices):
                checkpoints.append({"key_index": int(key), "checkpoint": name, "pair_index": panel_index,
                                    "pair_name": PANEL[panel_index]["name"], "mean_hw": float(mean_hw[ki]),
                                    "zero_fraction": float(zero_fraction[ki])})
    save_csv(directory / "operation_checkpoint_per_key.csv", checkpoints)
    save_csv(directory / "operation_checkpoint_summary.csv", summarize(checkpoints,
             ("checkpoint", "pair_index", "pair_name"), ("mean_hw", "zero_fraction"), indices, draws))
    save_json(directory / "operation_checkpoint_counts.json", checkpoint_counts)

    values = np.column_stack((
        within_values["Salsa20", 3, "none"][2] - within_values["Salsa20", 2, "none"][2],
        spectral["Salsa20", 3, "add", 128]["delta_block_fundamental_share"]
        - spectral["Salsa20", 2, "add", 128]["delta_block_fundamental_share"]))
    pvalues, extremes = sign_flip_pvalues(values, SIGN_FLIPS, SIGN_SEED)
    adjusted = holm(pvalues)
    limits = np.quantile(values[draws].mean(axis=1), (0.025, 0.975), axis=0)
    labels = ("Salsa20 within-x7 word7 none DeltaA3 minus DeltaA2",
              "Salsa20 add DeltaF512(3) minus DeltaF512(2) at 128 bits")
    planned = []
    for column, label in enumerate(labels):
        planned.append({"endpoint": f"T{column+1}", "label": label, "family": "Salsa20",
                        "round_before": 2, "round_after": 3, "n_keys": len(indices),
                        "mean": float(values[:, column].mean()), "ci95_low": float(limits[0, column]),
                        "ci95_high": float(limits[1, column]),
                        "unit": "changed_bits_per_output_word" if column == 0 else "dimensionless_power_fraction",
                        "sign_flip_extremes": int(extremes[column]), "replicates": SIGN_FLIPS,
                        "p_two_sided_plus_one": float(pvalues[column]), "p_holm_two": float(adjusted[column]),
                        "cohort": "smoke_only" if generation["smoke"] else "independent_followup"})
    save_csv(directory / "arx_round_transition_planned_tests.csv", planned)
    save_json(directory / "structural_checks.json", generation["structural_checks"])
    manifest = {**specification(cohort), "status": "smoke_complete" if generation["smoke"] else "completed_independent_followup",
                "generation_manifest_sha256": sha256(generation_path), "raw_sha256": sha256(raw_path),
                "power_estimator": "Q=4 full Fourier power vectors per singleton mask, then average mask-level statistics",
                "window": "full8192", "segment_bits": [32, 64, 128],
                "bootstrap": {"replicates": BOOTSTRAPS, "seed": BOOT_SEED, "unit": "whole master-key pair",
                              "interval": "pointwise percentile 95%; identical draws across settings"},
                "sign_flip": {"replicates": SIGN_FLIPS, "seed": SIGN_SEED, "unit": "whole master-key pair",
                              "statistic": "absolute mean", "roundoff_tolerance": "1e-12 * max(1,abs(mean))",
                              "pvalue": "(extremes+1)/(replicates+1)", "holm_family": ["T1", "T2"]},
                "planned_endpoints": labels, "d2_groups": GROUPS,
                "structural_checks": generation["structural_checks"], "operation_checkpoint_counts": checkpoint_counts,
                "output_rows": {"singleton_per_key": len(singletons), "transition_per_key": len(transitions),
                                "d2_profiles_per_key": len(profiles), "planned": len(planned)},
                "output_sha256": {p.name: sha256(p) for p in sorted(directory.glob("*.csv"))}}
    save_json(directory / "arx_round_transition_manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--analyze-only", action="store_true")
    args = parser.parse_args()
    directory = args.output or (Path("/tmp/arx_round_transition_smoke") if args.smoke else OUT)
    if args.smoke and not directory.resolve().is_relative_to(Path("/tmp")):
        parser.error("Smoke data must be written under /tmp")
    if not args.analyze_only:
        generate(directory, SMOKE_INDICES if args.smoke else INDICES)
    result = analyze(directory)
    print(json.dumps({"status": result["status"], "rows": result["output_rows"],
                      "structural_checks": result["structural_checks"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
