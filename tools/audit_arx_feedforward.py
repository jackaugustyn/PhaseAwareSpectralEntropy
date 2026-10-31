#!/usr/bin/env python3
"""Independently audit the locked feed-forward follow-up; read-only by default.

No generator, cipher-core, measurement, or inference functions are imported.
Two archived keys are reconstructed from separately written working-state
arithmetic. Every stored scalar and conditional word identity is checked.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "doc_stream_ciphers/data/arx_feedforward_results"
PROTOCOL = ROOT / "doc_stream_ciphers/ARX_FEEDFORWARD_PROTOCOL.txt"
PROTOCOL_HASH = "b416c7fb7b6697e26c4707b9e6c70981245f22eaecd243c480319ea393090ef8"
FAMILIES = ("ChaCha20", "Salsa20")
VARIANTS = ("add", "none", "xor")
ROUNDS = (2, 4)
MASK = (1 << 32) - 1
METRICS = ("hmp", "hnodc", "p0", "mean_hw_fraction", "block_harmonic_share",
           "block_fundamental_share", "phase_range_fraction")
GROUPS = {"aligned_all32": tuple(range(32)), "aligned_nonmsb31": tuple(range(31)),
          "offset4": tuple(range(32, 36)), "within2": (36, 37)}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def rot(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & MASK


def chacha_quarter(a: int, b: int, c: int, d: int) -> tuple[int, ...]:
    a = (a + b) & MASK
    d = rot(d ^ a, 16)
    c = (c + d) & MASK
    b = rot(b ^ c, 12)
    a = (a + b) & MASK
    d = rot(d ^ a, 8)
    c = (c + d) & MASK
    b = rot(b ^ c, 7)
    return a, b, c, d


def salsa_quarter(a: int, b: int, c: int, d: int) -> tuple[int, ...]:
    b ^= rot((a + d) & MASK, 7)
    c ^= rot((b + a) & MASK, 9)
    d ^= rot((c + b) & MASK, 13)
    a ^= rot((d + c) & MASK, 18)
    return a, b, c, d


def reference_initial(key: bytes, nonce: bytes, family: str, counter: int) -> list[int]:
    constants = list(struct.unpack("<4I", b"expand 32-byte k"))
    key_words = list(struct.unpack("<8I", key))
    n0, n1 = struct.unpack("<2I", nonce)
    if family == "ChaCha20":
        return constants + key_words + [counter, 0, n0, n1]
    return [constants[0], *key_words[:4], constants[1], n0, n1,
            counter, 0, constants[2], *key_words[4:], constants[3]]


def reference_working(initial: list[int], family: str, rounds: int) -> list[int]:
    state = initial.copy()
    if family == "ChaCha20":
        quarter = chacha_quarter
        column = tuple((j, j + 4, j + 8, j + 12) for j in range(4))
        second = tuple((j, 4 + (j + 1) % 4, 8 + (j + 2) % 4,
                        12 + (j + 3) % 4) for j in range(4))
    else:
        quarter = salsa_quarter
        column = tuple(tuple(((j + k) % 4) * 4 + j for k in range(4)) for j in range(4))
        second = tuple(tuple(j * 4 + (j + k) % 4 for k in range(4)) for j in range(4))
    for _ in range(rounds // 2):
        for schedule in (column, second):
            for indices in schedule:
                result = quarter(*(state[j] for j in indices))
                for j, value in zip(indices, result):
                    state[j] = value
    return state


def finalized_reference(key: bytes, nonce: bytes, family: str, rounds: int,
                        secret: bytes | None = None) -> np.ndarray:
    initial = [reference_initial(key, nonce, family, counter) for counter in range(16)]
    if secret is None:
        working = [reference_working(state, family, rounds) for state in initial]
    else:
        message = (b"ff-intervention-oracle-v1:" + family.encode() + b":" + secret
                   + rounds.to_bytes(2, "big") + nonce)
        words = struct.unpack("<256I", hashlib.shake_256(message).digest(1024))
        working = [list(words[16 * j:16 * (j + 1)]) for j in range(16)]
    added = [[(a + b) & MASK for a, b in zip(w, x)] for w, x in zip(working, initial)]
    xored = [[a ^ b for a, b in zip(w, x)] for w, x in zip(working, initial)]
    return np.asarray([added, working, xored], dtype=np.uint32)


def popcount(value: np.ndarray) -> np.ndarray:
    octets = np.ascontiguousarray(value, dtype="<u4").view(np.uint8).reshape(*value.shape, 4)
    return np.unpackbits(octets, axis=-1).sum(axis=-1, dtype=np.uint8)


def nonce_bit(word: int, bit: int) -> int:
    return 32 * word + 8 * (bit // 8) + 7 - bit % 8


def panel() -> list[dict]:
    local = [((0, b), (1, b), f"aligned_{b:02d}", "aligned") for b in range(32)]
    local += [((0, 0), (1, b), f"offset_00_{b:02d}", "offset") for b in (7, 15, 30, 31)]
    local += [((1, a), (1, b), f"within_{a:02d}_{b:02d}", "within") for a, b in ((0, 15), (7, 30))]
    return [{"name": name, "kind": kind, "word_bits_lsb": [list(a), list(b)],
             "bits_msb_first": [nonce_bit(*a), nonce_bit(*b)]} for a, b, name, kind in local]


def flip(base: bytes, *bits: int) -> bytes:
    value = int.from_bytes(base, "big")
    for bit in bits:
        value ^= 1 << (63 - bit)
    return value.to_bytes(8, "big")


def affine_column(c: np.ndarray, bit: int) -> np.ndarray:
    """Use the disjoint-carry closed form, not the generator's f(2^b)-f(0)."""
    values = np.asarray(c, dtype=np.uint32)
    if bit == 31:
        return np.zeros_like(values)
    advanced = ((values.astype(np.uint64) + (1 << (bit + 1))) & MASK).astype(np.uint32)
    return np.where((values & np.uint32(1 << bit)) == 0, values ^ advanced, 0).astype(np.uint32)


def fixture_checks() -> dict:
    cases = 0
    for width in range(1, 9):
        mask = (1 << width) - 1
        total_weight = 0
        for c in range(1 << width):
            columns = [0 if c & (1 << bit) or bit == width - 1 else
                       c ^ ((c + (1 << (bit + 1))) & mask) for bit in range(width)]
            total_weight += sum(value.bit_count() for value in columns)
            for u in range(1 << width):
                result = c
                for bit, column in enumerate(columns):
                    if u & (1 << bit):
                        result ^= column
                assert result == ((u ^ c) + u) & mask
                cases += 1
        assert total_weight == (width - 2) * (1 << width) + 2
    return {"exhaustive_affine_cases_word_widths_1_to_8": cases}


def audit_words(raw: dict[str, np.ndarray], indices: np.ndarray) -> dict:
    masks = panel()
    streams = singleton_checks = d2_checks = direct_equalities = 0
    selected = sorted(set((0, len(indices) - 1)))
    for key_pos in selected:
        key_index = int(indices[key_pos])
        master = hashlib.blake2b(f"stream-publication-v1:20261030:{key_index}".encode(), digest_size=32).digest()
        material = hashlib.shake_256(b"ff-intervention-nonces-v1:" + master).digest(32)
        bases = [material[i:i + 8] for i in range(0, 32, 8)]
        all_vertices = set()
        for base in bases:
            all_vertices |= {base, *(flip(base, bit) for bit in range(64)),
                             *(flip(base, *pair["bits_msb_first"]) for pair in masks)}
        assert len(all_vertices) == 412
        for fi, family in enumerate(FAMILIES):
            suffix = family.encode() + b":" + master
            key = hashlib.blake2b(b"ff-intervention-key-v1:" + suffix, digest_size=32).digest()
            secret = hashlib.blake2b(b"ff-intervention-secret-v1:" + suffix, digest_size=32).digest()
            for ri, rounds in enumerate(ROUNDS):
                actual = {v: finalized_reference(key, v, family, rounds) for v in all_vertices}
                oracle = {v: finalized_reference(key, v, family, rounds, secret) for v in all_vertices}
                streams += len(actual)
                for bi, base in enumerate(bases):
                    for bit in range(64):
                        for label, collection in (("observed", actual), ("oracle", oracle)):
                            difference = collection[base] ^ collection[flip(base, bit)]
                            np.testing.assert_array_equal(popcount(difference), raw[f"{label}_singleton"][key_pos, fi, ri, :, bit, bi])
                            singleton_checks += 1
                            if family == "Salsa20" and rounds == 2 and label == "observed":
                                np.testing.assert_array_equal(difference[..., 7], raw["salsa2_singleton_word7"][key_pos, :, bit, bi])
                    for pi, pair in enumerate(masks):
                        a, b = pair["bits_msb_first"]
                        vertices = base, flip(base, a), flip(base, b), flip(base, a, b)
                        for label, collection in (("observed", actual), ("oracle", oracle)):
                            difference = np.bitwise_xor.reduce(np.stack([collection[v] for v in vertices]), axis=0)
                            np.testing.assert_array_equal(popcount(difference), raw[f"{label}_d2"][key_pos, fi, ri, :, pi, bi])
                            np.testing.assert_array_equal(difference[..., 7], raw[f"{label}_d2_word7"][key_pos, fi, ri, :, pi, bi])
                            np.testing.assert_array_equal(difference[1], difference[2])
                            direct_equalities += difference[1].size
                            d2_checks += 1
                    if family == "Salsa20" and rounds == 2:
                        for ci, nonce in enumerate([base] + [flip(base, bit) for bit in range(32)]):
                            c = actual[nonce][1, :, 7] ^ np.uint32(int.from_bytes(nonce[4:], "little"))
                            np.testing.assert_array_equal(c, raw["salsa2_c"][key_pos, ci, bi])
    return {"regenerated_key_indices": [int(indices[i]) for i in selected],
            "independent_cipher_streams": streams, "independent_cipher_blocks": streams * 16,
            "independent_reference_streams": streams,
            "singleton_trajectories_all_variants_verified": singleton_checks,
            "d2_trajectories_all_variants_verified": d2_checks,
            "direct_none_xor_d2_word_equalities_verified": direct_equalities}


def audit_identities(raw: dict[str, np.ndarray]) -> dict:
    checks = {}
    for prefix in ("observed", "oracle"):
        values = raw[f"{prefix}_d2"]
        np.testing.assert_array_equal(values[:, :, :, 1], values[:, :, :, 2])
        checks[f"{prefix}_none_xor_all_word_hw_equalities"] = values[:, :, :, 1].size
        words = raw[f"{prefix}_d2_word7"]
        np.testing.assert_array_equal(popcount(words), values[..., 7])
        np.testing.assert_array_equal(words[:, :, :, 1], words[:, :, :, 2])
        checks[f"{prefix}_none_xor_word7_bitwise_equalities"] = words[:, :, :, 1].size
    singleton = raw["salsa2_singleton_word7"]
    np.testing.assert_array_equal(popcount(singleton), raw["observed_singleton"][:, 1, 0, ..., 7])
    c0 = raw["salsa2_c"][:, 0]
    for bit in range(32):
        mask = nonce_bit(1, bit)
        np.testing.assert_array_equal(singleton[:, 0, mask], affine_column(c0, bit))
        assert np.all(singleton[:, 1, mask] == np.uint32(1 << bit))
        assert not singleton[:, 2, mask].any()
    checks["salsa2_singleton_word7_conditional_uint32_predictions"] = int(c0.size * 32 * 3)
    mixed = raw["observed_d2_word7"][:, 1, 0]
    for pi, pair in enumerate(panel()):
        if pair["kind"] == "within":
            assert not mixed[:, :, pi].any()
        else:
            a = pair["bits_msb_first"][0]
            bit = pair["word_bits_lsb"][1][1]
            expected = affine_column(raw["salsa2_c"][:, a + 1], bit) ^ affine_column(c0, bit)
            np.testing.assert_array_equal(mixed[:, 0, pi], expected)
            assert not mixed[:, 1:, pi].any()
    checks["salsa2_d2_word7_conditional_uint32_predictions"] = int(mixed.size)
    # For fixed C, the singleton response lengths cover a suffix of the word.
    total_hw = popcount(singleton[:, 0, 32:]).sum(axis=1)
    trailing_ones = np.zeros_like(c0, dtype=np.int16)
    continuing = np.ones(c0.shape, dtype=bool)
    for bit in range(32):
        continuing &= (c0 & np.uint32(1 << bit)) != 0
        trailing_ones += continuing
    np.testing.assert_array_equal(total_hw, np.maximum(31 - trailing_ones, 0))
    checks["salsa2_total_singleton_hw_from_trailing_ones_C"] = c0.size
    return {"violations": 0, "checked_values": checks,
            "scope": "All stored word7 uint32 and all-word HW arrays; other-word bitwise equality is independently regenerated on two keys and recorded for all keys in generation metadata."}


def spectral_reference(words: np.ndarray, segment: int) -> dict[str, np.ndarray]:
    flat = words.astype(float).reshape(*words.shape[:-2], -1)
    step = segment // 32
    trajectory = sum(flat[..., j::step] for j in range(step))
    size = trajectory.shape[-1]
    power = np.mean(np.abs(np.fft.rfft(trajectory, axis=-1)) ** 2, axis=-2)
    multiplicity = np.full(size // 2 + 1, 2.0)
    multiplicity[[0, -1]] = 1.0
    total = np.sum(power * multiplicity, axis=-1, keepdims=True)
    probability = power / total
    entropy = -np.sum(multiplicity * probability * np.log2(np.where(probability > 0, probability, 1)), axis=-1)
    ac_total = np.sum(power[..., 1:] * multiplicity[1:], axis=-1, keepdims=True)
    assert np.all(ac_total > 0)
    ac = power[..., 1:] / ac_total
    ac_entropy = -np.sum(multiplicity[1:] * ac * np.log2(np.where(ac > 0, ac, 1)), axis=-1) / np.log2(size - 1)
    block_means = trajectory.reshape(*trajectory.shape[:-1], 16, 512 // segment).mean(axis=(-3, -2))
    return {"hmp": entropy, "hnodc": ac_entropy, "p0": probability[..., 0],
            "mean_hw_fraction": trajectory.mean(axis=(-2, -1)) / segment,
            "phase_range_fraction": np.ptp(block_means, axis=-1) / segment,
            "block_harmonic_share": np.sum(power[..., 16::16] * multiplicity[16::16], axis=-1) / ac_total[..., 0],
            "block_fundamental_share": 2 * power[..., 16] / ac_total[..., 0]}


def inference_reference(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(2026103001)
    absolute = np.abs(values.mean(axis=0))
    tolerance = 1e-12 * np.maximum(1.0, absolute)
    extremes = np.zeros(values.shape[1], dtype=np.int64)
    for _ in range(50):
        signs = rng.integers(0, 2, (2000, len(values)), dtype=np.int8) * 2 - 1
        simulated = np.abs(signs @ values / len(values))
        extremes += np.count_nonzero(simulated >= absolute - tolerance, axis=0)
    raw = (extremes + 1) / 100001
    order = np.argsort(raw)
    adjusted = np.empty_like(raw)
    adjusted[order] = np.minimum(1, np.maximum.accumulate(raw[order] * np.arange(len(raw), 0, -1)))
    return raw, adjusted, extremes


def audit_statistics(directory: Path, raw: dict[str, np.ndarray], indices: np.ndarray) -> dict:
    n = len(indices)
    key_positions = {str(int(key)): i for i, key in enumerate(indices)}
    draws = np.random.default_rng(2026103002).integers(0, n, (5000, n), dtype=np.int16)
    weights = np.zeros((5000, n))
    np.add.at(weights, (np.repeat(np.arange(5000), n), draws.ravel()), 1 / n)
    errors = {"per_key": 0.0, "mean": 0.0, "ci": 0.0}
    audited_tables = {}

    def check_table(per_key_name: str, summary_name: str, axes: tuple[str, ...], names: tuple[str, ...], expected: dict) -> None:
        normal = {tuple(map(str, identity)): value for identity, value in expected.items()}
        seen = set()
        with (directory / per_key_name).open(newline="") as stream:
            for row in csv.DictReader(stream):
                identity = tuple(row[axis] for axis in axes)
                ki = key_positions[row["key_index"]]
                assert (identity, ki) not in seen
                seen.add((identity, ki))
                actual = np.asarray([float(row[name]) for name in names])
                errors["per_key"] = max(errors["per_key"], float(np.max(np.abs(actual - normal[identity][ki]))))
        assert len(seen) == n * len(normal)
        summaries = {tuple(row[axis] for axis in axes): row for row in read_csv(directory / summary_name)}
        assert summaries.keys() == normal.keys()
        identities = list(normal)
        # Count-weighted bootstrap avoids allocating resample x key x metric.
        for start in range(0, len(identities), 32):
            chunk = identities[start:start + 32]
            values = np.concatenate([normal[item] for item in chunk], axis=1)
            averages = values.mean(axis=0)
            limits = np.quantile(weights @ values, (0.025, 0.975), axis=0)
            for j, identity in enumerate(chunk):
                record = summaries[identity]
                assert int(record["n_keys"]) == n
                for k, name in enumerate(names):
                    pos = j * len(names) + k
                    errors["mean"] = max(errors["mean"], abs(float(record[f"{name}_mean"]) - averages[pos]))
                    for q, side in enumerate(("low", "high")):
                        errors["ci"] = max(errors["ci"], abs(float(record[f"{name}_ci95_{side}"]) - limits[q, pos]))
        audited_tables[per_key_name] = {"per_key_rows": len(seen), "summary_rows": len(normal)}

    singleton, paired, gaps = {}, {}, {}
    endpoint_names = tuple(f"{prefix}_{metric}" for metric in METRICS
                           for prefix in ("actual", "control", "delta", "word_gap_delta"))
    for fi, family in enumerate(FAMILIES):
        for ri, rounds in enumerate(ROUNDS):
            for segment in (32, 64, 128):
                for vi, variant in enumerate(VARIANTS):
                    a, c = [spectral_reference(raw[f"{prefix}_singleton"][:, fi, ri, vi], segment)
                            for prefix in ("observed", "oracle")]
                    values = []
                    for name in METRICS:
                        delta = a[name] - c[name]
                        values.extend((a[name].mean(axis=1), c[name].mean(axis=1), delta.mean(axis=1),
                                       (delta[:, 32:] - delta[:, :32]).mean(axis=1)))
                    singleton[family, rounds, segment, variant] = np.column_stack(values)
                    gaps[family, rounds, segment, variant] = values[3]
                paired[family, rounds, segment] = np.column_stack(
                    [gaps[family, rounds, segment, "add"] - gaps[family, rounds, segment, variant] for variant in ("none", "xor")])
    check_table("arx_feedforward_per_key.csv", "arx_feedforward_summary.csv",
                ("family", "rounds", "segment_bits", "variant"), endpoint_names, singleton)
    check_table("arx_feedforward_paired_per_key.csv", "arx_feedforward_paired_summary.csv",
                ("family", "rounds", "segment_bits"), ("G_add_minus_none", "G_add_minus_xor"), paired)

    singleton_profiles, d2_profiles, word7_pairs, interactions = {}, {}, {}, {}
    masks = panel()
    for fi, family in enumerate(FAMILIES):
        for ri, rounds in enumerate(ROUNDS):
            interaction_values = []
            for vi, variant in enumerate(VARIANTS):
                for label, groups, output in (
                    ("singleton", {"nonce_word_1": tuple(range(32)), "nonce_word_2": tuple(range(32, 64))}, singleton_profiles),
                    ("d2", GROUPS, d2_profiles)):
                    for group, positions in groups.items():
                        a, c = [raw[f"{prefix}_{label}"][:, fi, ri, vi][:, positions].mean(axis=(1, 2, 3))
                                for prefix in ("observed", "oracle")]
                        for word in range(16):
                            output[family, rounds, variant, group, word] = np.column_stack((a[:, word], c[:, word], a[:, word] - c[:, word]))
                        if label == "d2" and group == "aligned_nonmsb31":
                            interaction_values.extend((a[:, 7], c[:, 7]))
                for pi, info in enumerate(masks):
                    a, c = [raw[f"{prefix}_d2"][:, fi, ri, vi, pi, :, :, 7].mean(axis=(1, 2))
                            for prefix in ("observed", "oracle")]
                    word7_pairs[family, rounds, variant, pi, info["name"], info["kind"]] = np.column_stack((a, c, a - c))
            j = (interaction_values[0] - interaction_values[2]) - (interaction_values[1] - interaction_values[3])
            interactions[family, rounds] = np.column_stack(interaction_values + [j])
    axes = ("family", "rounds", "variant", "group", "word")
    check_table("per_key_singleton_profiles.csv", "singleton_profiles_summary.csv", axes,
                ("observed", "control", "delta"), singleton_profiles)
    check_table("per_key_d2_profiles.csv", "d2_profiles_summary.csv", axes,
                ("observed", "control", "delta"), d2_profiles)
    check_table("per_key_d2_word7_pairs.csv", "d2_word7_pairs_summary.csv",
                ("family", "rounds", "variant", "pair_index", "pair_name", "kind"),
                ("observed", "control", "delta"), word7_pairs)
    interaction_names = tuple(f"A_{variant}_{source}" for variant in VARIANTS for source in ("observed", "control")) + ("J",)
    check_table("interaction_per_key.csv", "interaction_summary.csv", ("family", "rounds"), interaction_names, interactions)
    values = np.column_stack((gaps["Salsa20", 2, 128, "none"], paired["Salsa20", 2, 128][:, 0],
                              paired["ChaCha20", 2, 128][:, 0], interactions["Salsa20", 2][:, -1]))
    p, holm, extremes = inference_reference(values)
    limits = np.quantile(weights @ values, (0.025, 0.975), axis=0)
    planned = read_csv(directory / "arx_feedforward_planned_tests.csv")
    assert [row["endpoint"] for row in planned] == ["E1", "E2", "E3", "E4"]
    for column, row in enumerate(planned):
        assert int(row["sign_flip_extremes"]) == extremes[column]
        assert int(row["replicates"]) == 100000 and int(row["n_keys"]) == n
        assert abs(float(row["p_two_sided_plus_one"]) - p[column]) < 1e-15
        assert abs(float(row["p_holm_four"]) - holm[column]) < 1e-15
        errors["mean"] = max(errors["mean"], abs(float(row["mean"]) - values[:, column].mean()))
        for q, side in enumerate(("low", "high")):
            errors["ci"] = max(errors["ci"], abs(float(row[f"ci95_{side}"]) - limits[q, column]))
    if max(errors.values()) > 2e-11:
        raise AssertionError(f"Scalar audit failed: {errors}")
    return {"max_absolute_errors": errors, "tables": audited_tables,
            "planned_means": values.mean(axis=0).tolist(), "planned_holm_p": holm.tolist(),
            "planned_sign_flip_extremes": extremes.tolist(),
            "method": "Independent strided aggregation, weighted real FFT, all per-key/mean/pointwise intervals, count-weighted bootstrap, plus-one sign flips and four-test Holm."}


def audit(directory: Path) -> dict:
    manifest_path = directory / "arx_feedforward_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    generation = json.loads((directory / "generation_manifest.json").read_text())
    assert sha(PROTOCOL) == PROTOCOL_HASH == manifest["protocol_sha256"] == generation["protocol_sha256"]
    assert sha(directory / "generation_manifest.json") == manifest["generation_manifest_sha256"]
    assert manifest["source_sha256"] == generation["source_sha256"]
    for name, digest in manifest["source_sha256"].items():
        assert sha(ROOT / name) == digest, name
    for name, digest in manifest["output_sha256"].items():
        assert sha(directory / name) == digest, name
    assert manifest["panel"] == panel()
    assert manifest["families"] == list(FAMILIES) and manifest["variants"] == list(VARIANTS)
    assert manifest["rounds"] == list(ROUNDS)
    raw_path = directory / "arx_feedforward_raw.npz"
    assert sha(raw_path) == manifest["raw_sha256"] == generation["raw_sha256"]
    with np.load(raw_path) as archive:
        raw = {name: archive[name] for name in archive.files}
    indices = raw["key_indices"]
    expected_indices = np.arange(1080, 1082) if generation["smoke"] else np.arange(1000, 1080)
    np.testing.assert_array_equal(indices, expected_indices)
    np.testing.assert_array_equal(indices, manifest["key_indices"])
    for name, shape in manifest["raw_per_key_shapes"].items():
        assert raw[name].shape == (len(indices), *shape), name
        if "word7" not in name and name != "salsa2_c":
            assert raw[name].dtype == np.uint8 and raw[name].max() <= 32
        else:
            assert raw[name].dtype == np.uint32
    for name, checks in generation["structural_checks"].items():
        assert checks["violations"] == 0 and checks["comparisons"] > 0, name
    assert json.loads((directory / "structural_checks.json").read_text()) == generation["structural_checks"]
    result = {"status": "passed", "auditor_source_sha256": sha(Path(__file__)),
              "manifest_sha256": sha(manifest_path), "raw_sha256": sha(raw_path),
              "protocol_sha256": sha(PROTOCOL), "keys": len(indices),
              "fixtures": fixture_checks()}
    result["word_regeneration"] = audit_words(raw, indices)
    print("Independent working-state/word audit passed", flush=True)
    result["conditional_identities"] = audit_identities(raw)
    print("Full-cohort conditional uint32 audit passed", flush=True)
    result["statistics"] = audit_statistics(directory, raw, indices)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT)
    parser.add_argument("--write", action="store_true", help="Write independent_audit.json in the selected new data directory")
    args = parser.parse_args()
    result = audit(args.directory)
    if args.write:
        (args.directory / "independent_audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
