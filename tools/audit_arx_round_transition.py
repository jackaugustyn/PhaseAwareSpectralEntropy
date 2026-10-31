#!/usr/bin/env python3
"""Independent scalar-core and numerical audit of the 2/3/4-round study.

No functions from the study generator, production cipher implementation,
measurement code, or statistical routines are imported.
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
DEFAULT = ROOT / "doc_stream_ciphers/data/arx_round_transition"
MASK = (1 << 32) - 1
FAMILIES = ("ChaCha20", "Salsa20")
ROUNDS = (2, 3, 4)
VARIANTS = ("add", "none", "xor")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rotate(value: int, n: int) -> int:
    return ((value << n) | (value >> (32 - n))) & MASK


def initial(key: bytes, nonce: bytes, counter: int, family: str) -> list[int]:
    c = struct.unpack("<4I", b"expand 32-byte k")
    k = struct.unpack("<8I", key)
    n = struct.unpack("<2I", nonce)
    if family == "ChaCha20":
        return [*c, *k, counter, 0, *n]
    return [c[0], *k[:4], c[1], *n, counter, 0, c[2], *k[4:], c[3]]


def scalar_working(state: list[int], family: str) -> tuple[dict[int, list[int]], tuple[int, int] | None]:
    """Four explicit single rounds; capture Salsa's named c=word7 update."""
    w = state.copy()
    snapshots: dict[int, list[int]] = {}
    witness = None
    if family == "ChaCha20":
        schedules = (
            ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)),
            ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)),
        )
    else:
        schedules = (
            ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11)),
            ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)),
        )
    for r in range(1, 5):
        for a, b, c, d in schedules[(r - 1) % 2]:
            if family == "ChaCha20":
                w[a] = (w[a] + w[b]) & MASK
                w[d] = rotate(w[d] ^ w[a], 16)
                w[c] = (w[c] + w[d]) & MASK
                w[b] = rotate(w[b] ^ w[c], 12)
                w[a] = (w[a] + w[b]) & MASK
                w[d] = rotate(w[d] ^ w[a], 8)
                w[c] = (w[c] + w[d]) & MASK
                w[b] = rotate(w[b] ^ w[c], 7)
            else:
                w[b] ^= rotate((w[a] + w[d]) & MASK, 7)
                before = w[c]
                w[c] ^= rotate((w[b] + w[a]) & MASK, 9)
                if r == 3 and (a, b, c, d) == (15, 3, 7, 11):
                    witness = (before, w[c])
                w[d] ^= rotate((w[c] + w[b]) & MASK, 13)
                w[a] ^= rotate((w[d] + w[c]) & MASK, 18)
        if r in ROUNDS:
            snapshots[r] = w.copy()
    return snapshots, witness


def scalar_stream(key: bytes, nonce: bytes, family: str) -> tuple[np.ndarray, np.ndarray | None]:
    output = np.empty((3, 3, 16, 16), dtype=np.uint32)
    checkpoints = np.empty((2, 16), dtype=np.uint32) if family == "Salsa20" else None
    for block in range(16):
        source = initial(key, nonce, block, family)
        snapshots, witness = scalar_working(source, family)
        for ri, r in enumerate(ROUNDS):
            w = snapshots[r]
            output[ri, 0, block] = [(x + y) & MASK for x, y in zip(w, source)]
            output[ri, 1, block] = w
            output[ri, 2, block] = [x ^ y for x, y in zip(w, source)]
        if checkpoints is not None:
            assert witness is not None
            checkpoints[:, block] = witness
    return output, checkpoints


def popcount(words: np.ndarray) -> np.ndarray:
    values = np.ascontiguousarray(words, dtype="<u4")
    octets = values.view(np.uint8).reshape(*values.shape, 4)
    return np.unpackbits(octets, axis=-1).sum(axis=-1, dtype=np.uint8)


def flip(nonce: bytes, *positions: int) -> bytes:
    value = int.from_bytes(nonce, "big")
    for bit in positions:
        value ^= 1 << (63 - bit)
    return value.to_bytes(8, "big")


def global_bit(word: int, bit: int) -> int:
    return 32 * word + 8 * (bit // 8) + 7 - bit % 8


def panel_bits() -> list[tuple[int, int]]:
    pairs = [(global_bit(0, b), global_bit(1, b)) for b in range(32)]
    pairs += [(global_bit(0, 0), global_bit(1, b)) for b in (7, 15, 30, 31)]
    pairs += [(global_bit(1, a), global_bit(1, b)) for a, b in ((0, 15), (7, 30))]
    return pairs


def statistics(words: np.ndarray, width: int) -> dict[str, np.ndarray]:
    """Strided word aggregation and weighted one-sided FFT, Q=4 per mask."""
    size = width // 32
    w = np.asarray(words, dtype=float)
    segments = sum(w[..., shift::size] for shift in range(size))
    x = segments.reshape(*segments.shape[:-2], -1)
    n = x.shape[-1]
    pwr = (np.abs(np.fft.rfft(x, axis=-1)) ** 2).mean(axis=-2)
    multiplicity = np.full(pwr.shape[-1], 2.0)
    multiplicity[0] = multiplicity[-1] = 1.0
    total = (pwr * multiplicity).sum(axis=-1, keepdims=True)
    p = np.divide(pwr, total, out=np.zeros_like(pwr), where=total > 0)
    h = -(multiplicity * p * np.log2(np.where(p > 0, p, 1))).sum(axis=-1)
    ac = (pwr[..., 1:] * multiplicity[1:]).sum(axis=-1)
    acp = np.divide(pwr[..., 1:], ac[..., None], out=np.zeros_like(pwr[..., 1:]), where=ac[..., None] > 0)
    ah = -(multiplicity[1:] * acp * np.log2(np.where(acp > 0, acp, 1))).sum(axis=-1) / np.log2(n - 1)
    fundamental = n // (512 // width)
    f = np.divide(2 * pwr[..., fundamental], ac, out=np.zeros_like(ac), where=ac > 0)
    harmonics = np.arange(fundamental, pwr.shape[-1], fundamental)
    hp = (pwr[..., harmonics] * multiplicity[harmonics]).sum(axis=-1)
    hs = np.divide(hp, ac, out=np.zeros_like(ac), where=ac > 0)
    phase = segments.mean(axis=(-3, -2))
    return {"hmp": h, "hnodc": ah, "p0": p[..., 0],
            "mean_hw_fraction": x.mean(axis=(-2, -1)) / width,
            "block_harmonic_share": hs, "block_fundamental_share": f,
            "phase_range_fraction": np.ptp(phase, axis=-1) / width}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def reference_stream(key: bytes, secret: bytes, nonce: bytes, family: str) -> np.ndarray:
    source = np.asarray([initial(key, nonce, block, family) for block in range(16)], dtype=np.uint32)
    result = np.empty((3, 3, 16, 16), dtype=np.uint32)
    for ri, r in enumerate(ROUNDS):
        message = (b"rt-single-round-oracle-v1:" + family.encode() + b":"
                   + secret + r.to_bytes(2, "big") + nonce)
        w = np.frombuffer(hashlib.shake_256(message).digest(1024), dtype="<u4").reshape(16, 16)
        result[ri, 0] = ((w.astype(np.uint64) + source) & MASK).astype(np.uint32)
        result[ri, 1] = w
        result[ri, 2] = w ^ source
    return result


def audit_raw(raw: dict[str, np.ndarray], indices: np.ndarray) -> dict:
    counts = {"cipher_blocks_regenerated_through_four_single_rounds": 0,
              "reference_blocks_regenerated": 0, "singleton_arrays_verified": 0,
              "second_derivative_arrays_verified": 0, "checkpoint_words_verified": 0,
              "regenerated_none_xor_uint32_equalities": 0}
    selected = sorted(set((0, len(indices) - 1)))
    pairs = panel_bits()
    for key_position in selected:
        index = int(indices[key_position])
        master = hashlib.blake2b(f"stream-publication-v1:20261031:{index}".encode(), digest_size=32).digest()
        material = hashlib.shake_256(b"rt-single-round-nonces-v1:" + master).digest(32)
        bases = [material[j:j + 8] for j in range(0, 32, 8)]
        vertices = {v for base in bases for v in
                    (base, *(flip(base, bit) for bit in range(64)), *(flip(base, a, b) for a, b in pairs))}
        assert len(vertices) == 412
        for fi, family in enumerate(FAMILIES):
            suffix = family.encode() + b":" + master
            key = hashlib.blake2b(b"rt-single-round-key-v1:" + suffix, digest_size=32).digest()
            secret = hashlib.blake2b(b"rt-single-round-secret-v1:" + suffix, digest_size=32).digest()
            evaluated = {v: scalar_stream(key, v, family) for v in sorted(vertices)}
            actual = {v: result[0] for v, result in evaluated.items()}
            oracle = {v: reference_stream(key, secret, v, family) for v in sorted(vertices)}
            counts["cipher_blocks_regenerated_through_four_single_rounds"] += 16 * len(vertices)
            counts["reference_blocks_regenerated"] += 3 * 16 * len(vertices)
            for bi, base in enumerate(bases):
                for bit in range(64):
                    for label, collection in (("observed", actual), ("oracle", oracle)):
                        delta = collection[base] ^ collection[flip(base, bit)]
                        np.testing.assert_array_equal(popcount(delta), raw[f"{label}_singleton"][key_position, fi, :, :, bit, bi])
                        counts["singleton_arrays_verified"] += 1
                for pi, (a, b) in enumerate(pairs):
                    square = (base, flip(base, a), flip(base, b), flip(base, a, b))
                    for label, collection in (("observed", actual), ("oracle", oracle)):
                        delta = np.bitwise_xor.reduce(np.stack([collection[v] for v in square]), axis=0)
                        np.testing.assert_array_equal(popcount(delta), raw[f"{label}_d2"][key_position, fi, :, :, pi, bi])
                        np.testing.assert_array_equal(delta[..., 7], raw[f"{label}_d2_word7"][key_position, fi, :, :, pi, bi])
                        np.testing.assert_array_equal(delta[:, 1], delta[:, 2])
                        counts["regenerated_none_xor_uint32_equalities"] += delta[:, 1].size
                        counts["second_derivative_arrays_verified"] += 1
                    if family == "Salsa20" and pi >= 36:
                        checkpoint = np.bitwise_xor.reduce(np.stack([evaluated[v][1] for v in square]), axis=0)
                        np.testing.assert_array_equal(checkpoint, raw["salsa3_checkpoint_d2_word7"][key_position, :, pi - 36, bi])
                        counts["checkpoint_words_verified"] += checkpoint.size
        print(f"Independent scalar regeneration passed for key {index}", flush=True)
    for label in ("observed", "oracle"):
        hw = raw[f"{label}_d2"]
        d2 = raw[f"{label}_d2_word7"]
        np.testing.assert_array_equal(hw[:, :, :, 1], hw[:, :, :, 2])
        np.testing.assert_array_equal(d2[:, :, :, 1], d2[:, :, :, 2])
        np.testing.assert_array_equal(popcount(d2), hw[..., 7])
        counts[f"{label}_full_cohort_none_xor_word7_equalities"] = d2[:, :, :, 1].size
    within = raw["observed_d2_word7"][:, 1, :, :, 36:38]
    assert not within[:, 0].any(), "Salsa two-round within-word derivative must vanish"
    checkpoint = raw["salsa3_checkpoint_d2_word7"]
    np.testing.assert_array_equal(checkpoint[:, 0], within[:, 0, 1])
    np.testing.assert_array_equal(checkpoint[:, 1], within[:, 1, 1])
    counts["checkpoint_before_zero"] = int((checkpoint[:, 0] == 0).sum())
    counts["checkpoint_after_zero"] = int((checkpoint[:, 1] == 0).sum())
    counts["checkpoint_before_after_contexts_each"] = int(checkpoint[:, 0].size)
    counts["regenerated_key_indices"] = [int(indices[i]) for i in selected]
    return counts


def inference(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Independently recompute the fixed two-endpoint sign-flip family and CIs."""
    n = len(values)
    rng = np.random.default_rng(2026103105)
    extremes = np.zeros(values.shape[1], dtype=np.int64)
    observed = np.abs(values.mean(axis=0))
    tolerance = 1e-12 * np.maximum(1.0, observed)
    for start in range(0, 100000, 4096):
        signs = 2 * rng.integers(0, 2, (min(4096, 100000 - start), n), dtype=np.int8) - 1
        simulated = np.abs(np.einsum("ij,jk->ik", signs, values, optimize=False) / n)
        extremes += (simulated >= observed - tolerance).sum(axis=0)
    p = (extremes + 1) / 100001
    order = np.argsort(p)
    adjusted = np.empty_like(p)
    adjusted[order] = np.minimum(1, np.maximum.accumulate(p[order] * np.arange(len(p), 0, -1)))
    # Count-weighted bootstrap is equivalent to indexing complete key rows.
    draws = np.random.default_rng(2026103106).integers(0, n, (5000, n), dtype=np.int16)
    weights = np.asarray([np.bincount(row, minlength=n) for row in draws], dtype=float) / n
    limits = np.quantile(weights @ values, (0.025, 0.975), axis=0)
    return p, adjusted, extremes, limits


def calculated_endpoints(raw: dict[str, np.ndarray]) -> tuple[np.ndarray, dict, dict]:
    gaps, powers = {}, {}
    for fi, family in enumerate(FAMILIES):
        for ri, r in enumerate(ROUNDS):
            for vi, variant in enumerate(VARIANTS):
                for width in (32, 64, 128):
                    a, c = [statistics(raw[f"{prefix}_singleton"][:, fi, ri, vi], width)
                            for prefix in ("observed", "oracle")]
                    gaps[family, r, variant, width] = (a["hmp"][:, 32:] - c["hmp"][:, 32:]).mean(axis=1) - (a["hmp"][:, :32] - c["hmp"][:, :32]).mean(axis=1)
                    powers[family, r, variant, width] = (a["block_fundamental_share"] - c["block_fundamental_share"]).mean(axis=1)
    # Raw axes: key, family, round, variant, mask-pair, base, block, word.
    a = raw["observed_d2"][:, 1, :, 1, 36:38, :, :, 7].mean(axis=(2, 3, 4))
    c = raw["oracle_d2"][:, 1, :, 1, 36:38, :, :, 7].mean(axis=(2, 3, 4))
    t1 = (a[:, 1] - c[:, 1]) - (a[:, 0] - c[:, 0])
    t2 = powers["Salsa20", 3, "add", 128] - powers["Salsa20", 2, "add", 128]
    return np.column_stack((t1, t2)), gaps, powers


def audit_statistics(directory: Path, raw: dict[str, np.ndarray], indices: np.ndarray) -> dict:
    n = len(indices)
    draws = np.random.default_rng(2026103106).integers(0, n, (5000, n), dtype=np.int16)
    weights = np.asarray([np.bincount(row, minlength=n) for row in draws], dtype=float) / n
    index_lookup = {int(key): i for i, key in enumerate(indices)}
    maximum = {"per_key": 0.0, "mean": 0.0, "interval": 0.0}
    counts = {}
    integer_axes = {"rounds", "segment_bits", "word", "pair_index", "round_before", "round_after"}

    def verify_table(stem: str, axes: tuple[str, ...], expected: dict) -> None:
        per = read_rows(directory / f"{stem}_per_key.csv")
        summary = read_rows(directory / f"{stem}_summary.csv")
        assert len(per) == n * len(expected) and len(summary) == len(expected), stem
        def identity(row: dict) -> tuple:
            return tuple(int(row[a]) if a in integer_axes else row[a] for a in axes)
        seen = set()
        for row in per:
            key = identity(row)
            ki = index_lookup[int(row["key_index"])]
            assert (key, ki) not in seen
            seen.add((key, ki))
            for name, values in expected[key].items():
                maximum["per_key"] = max(maximum["per_key"], abs(float(row[name]) - values[ki]))
        assert {identity(row) for row in summary} == set(expected)
        for row in summary:
            group = expected[identity(row)]
            assert int(row["n_keys"]) == n
            fields = list(group)
            values = np.column_stack([group[f] for f in fields])
            limits = np.quantile(weights @ values, (0.025, 0.975), axis=0)
            for j, name in enumerate(fields):
                maximum["mean"] = max(maximum["mean"], abs(float(row[name + "_mean"]) - values[:, j].mean()))
                for q, side in enumerate(("low", "high")):
                    maximum["interval"] = max(maximum["interval"], abs(float(row[f"{name}_ci95_{side}"]) - limits[q, j]))
        counts[stem] = {"per_key_rows": len(per), "summary_rows": len(summary)}

    singleton, profiles, pairs, within, interactions = {}, {}, {}, {}, {}
    group_masks = {"aligned_all32": list(range(32)), "aligned_nonmsb31": list(range(31)),
                   "offset4": list(range(32, 36)), "within2": [36, 37]}
    pair_names = [f"aligned_{b:02d}" for b in range(32)] + [f"offset_00_{b:02d}" for b in (7, 15, 30, 31)] + ["within_00_15", "within_07_30"]
    pair_kinds = ["aligned"] * 32 + ["offset"] * 4 + ["within"] * 2
    for fi, family in enumerate(FAMILIES):
        for ri, r in enumerate(ROUNDS):
            interaction = {}
            for vi, variant in enumerate(VARIANTS):
                for width in (32, 64, 128):
                    a, c = [statistics(raw[f"{label}_singleton"][:, fi, ri, vi], width)
                            for label in ("observed", "oracle")]
                    fields = {}
                    for metric in a:
                        d = a[metric] - c[metric]
                        fields["actual_" + metric] = a[metric].mean(axis=1)
                        fields["control_" + metric] = c[metric].mean(axis=1)
                        fields["delta_" + metric] = d.mean(axis=1)
                        fields["word_gap_delta_" + metric] = (d[:, 32:] - d[:, :32]).mean(axis=1)
                    singleton[family, r, variant, width] = fields
                for group, masks in group_masks.items():
                    a, c = [raw[f"{label}_d2"][:, fi, ri, vi][:, masks].mean(axis=(1, 2, 3))
                            for label in ("observed", "oracle")]
                    for word in range(16):
                        profiles[family, r, variant, group, word] = {"observed": a[:, word], "control": c[:, word], "delta": a[:, word] - c[:, word]}
                    if group == "aligned_nonmsb31":
                        interaction[f"A_{variant}_observed"] = a[:, 7]
                        interaction[f"A_{variant}_control"] = c[:, 7]
                    if group == "within2":
                        zero = (raw["observed_d2_word7"][:, fi, ri, vi, 36:38] == 0).mean(axis=(1, 2, 3))
                        within[family, r, variant] = {"observed": a[:, 7], "control": c[:, 7], "delta": a[:, 7] - c[:, 7], "observed_zero_fraction": zero}
                a, c = [raw[f"{label}_d2"][:, fi, ri, vi, :, :, :, 7].mean(axis=(2, 3))
                        for label in ("observed", "oracle")]
                for pi in range(38):
                    pairs[family, r, variant, pi, pair_names[pi], pair_kinds[pi]] = {"observed": a[:, pi], "control": c[:, pi], "delta": a[:, pi] - c[:, pi]}
            interaction["J"] = interaction["A_add_observed"] - interaction["A_none_observed"] - interaction["A_add_control"] + interaction["A_none_control"]
            interactions[family, r] = interaction
    verify_table("singleton", ("family", "rounds", "variant", "segment_bits"), singleton)
    verify_table("d2_profiles", ("family", "rounds", "variant", "group", "word"), profiles)
    verify_table("d2_word7_pairs", ("family", "rounds", "variant", "pair_index", "pair_name", "kind"), pairs)
    verify_table("within_word", ("family", "rounds", "variant"), within)
    verify_table("interaction", ("family", "rounds"), interactions)
    transitions = {}
    for family in FAMILIES:
        for before, after in ((2, 3), (3, 4), (2, 4)):
            for variant in VARIANTS:
                w0, w1 = within[family, before, variant], within[family, after, variant]
                for width in (32, 64, 128):
                    s0, s1 = singleton[family, before, variant, width], singleton[family, after, variant, width]
                    transitions[family, before, after, variant, width] = {
                        "within_word7_observed_change": w1["observed"] - w0["observed"],
                        "within_word7_control_change": w1["control"] - w0["control"],
                        "within_word7_delta_change": w1["delta"] - w0["delta"],
                        "delta_F512_change": s1["delta_block_fundamental_share"] - s0["delta_block_fundamental_share"],
                        "delta_G_change": s1["word_gap_delta_hmp"] - s0["word_gap_delta_hmp"],
                        "J_change": interactions[family, after]["J"] - interactions[family, before]["J"],
                    }
    verify_table("transition", ("family", "round_before", "round_after", "variant", "segment_bits"), transitions)
    operation = {}
    checkpoint_counts = {}
    for ci, label in enumerate(("before_c", "after_c")):
        name = "round3_column_qr_15_3_7_11_" + label
        w = raw["salsa3_checkpoint_d2_word7"][:, ci]
        checkpoint_counts[name] = {"word_comparisons": w.size, "zero_words": int((w == 0).sum()), "nonzero_words": int((w != 0).sum())}
        for pi in range(2):
            operation[name, 36 + pi, pair_names[36 + pi]] = {"mean_hw": popcount(w[:, pi]).mean(axis=(1, 2)), "zero_fraction": (w[:, pi] == 0).mean(axis=(1, 2))}
    verify_table("operation_checkpoint", ("checkpoint", "pair_index", "pair_name"), operation)
    assert json.loads((directory / "operation_checkpoint_counts.json").read_text()) == checkpoint_counts
    values = np.column_stack((transitions["Salsa20", 2, 3, "none", 128]["within_word7_delta_change"], transitions["Salsa20", 2, 3, "add", 128]["delta_F512_change"]))
    p, adjusted, extremes, limits = inference(values)
    planned = read_rows(directory / "arx_round_transition_planned_tests.csv")
    assert [row["endpoint"] for row in planned] == ["T1", "T2"]
    for j, row in enumerate(planned):
        assert int(row["sign_flip_extremes"]) == extremes[j]
        assert int(row["replicates"]) == 100000 and int(row["n_keys"]) == n
        assert abs(float(row["p_two_sided_plus_one"]) - p[j]) < 1e-15
        assert abs(float(row["p_holm_two"]) - adjusted[j]) < 1e-15
        maximum["mean"] = max(maximum["mean"], abs(float(row["mean"]) - values[:, j].mean()))
        for q, side in enumerate(("low", "high")):
            maximum["interval"] = max(maximum["interval"], abs(float(row["ci95_" + side]) - limits[q, j]))
    assert max(maximum.values()) < 2e-11, maximum
    return {"max_absolute_errors": maximum, "tables": counts, "planned_means": values.mean(axis=0).tolist(),
            "planned_holm_p": adjusted.tolist(), "planned_sign_flip_extremes": extremes.tolist(),
            "method": "Weighted one-sided FFT; independently reconstructed raw means, seven table families, count-weighted paired bootstrap and two-test Holm sign flips."}


def audit(directory: Path) -> dict:
    manifest_path = directory / "arx_round_transition_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    generation_path = directory / "generation_manifest.json"
    generation = json.loads(generation_path.read_text())
    protocol = ROOT / "doc_stream_ciphers/ARX_ROUND_TRANSITION_PROTOCOL.txt"
    expected_hash = "88a8b1812f32af7904c6a5b656350a047bac87804ca7209a551ae99360a6f6b1"
    assert digest(protocol) == expected_hash == manifest["protocol_sha256"] == generation["protocol_sha256"]
    assert digest(generation_path) == manifest["generation_manifest_sha256"]
    assert manifest["source_sha256"] == generation["source_sha256"]
    for name, sha in manifest["source_sha256"].items():
        assert digest(ROOT / name) == sha, name
    for name, sha in manifest["output_sha256"].items():
        assert digest(directory / name) == sha, name
    for name, sha in generation["checkpoint_sha256"].items():
        assert digest(directory / "checkpoints" / name) == sha, name
    assert manifest["families"] == list(FAMILIES) and manifest["rounds"] == list(ROUNDS) and manifest["variants"] == list(VARIANTS)
    assert [tuple(p["bits_msb_first"]) for p in manifest["panel"]] == panel_bits()
    raw_path = directory / "arx_round_transition_raw.npz"
    assert digest(raw_path) == manifest["raw_sha256"] == generation["raw_sha256"]
    with np.load(raw_path) as archive:
        raw = {name: archive[name] for name in archive.files}
    indices = raw["key_indices"]
    expected = np.arange(1480, 1482) if generation["smoke"] else np.arange(1400, 1480)
    np.testing.assert_array_equal(indices, expected)
    np.testing.assert_array_equal(indices, manifest["key_indices"])
    for name, shape in manifest["raw_per_key_shapes"].items():
        assert raw[name].shape == (len(indices), *shape), name
        expected_type = np.uint32 if name.endswith("word7") else np.uint8
        assert raw[name].dtype == expected_type, name
        if expected_type == np.uint8:
            assert raw[name].max() <= 32
    assert json.loads((directory / "structural_checks.json").read_text()) == generation["structural_checks"] == manifest["structural_checks"]
    for check in generation["structural_checks"].values():
        assert check["comparisons"] > 0 and check["violations"] == 0
    result = {"status": "passed", "auditor_source_sha256": digest(Path(__file__)), "protocol_sha256": expected_hash,
              "manifest_sha256": digest(manifest_path), "raw_sha256": digest(raw_path), "keys": len(indices)}
    result["independent_core_and_checkpoint_audit"] = audit_raw(raw, indices)
    result["statistics"] = audit_statistics(directory, raw, indices)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = audit(args.directory)
    if args.write:
        (args.directory / "independent_audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
