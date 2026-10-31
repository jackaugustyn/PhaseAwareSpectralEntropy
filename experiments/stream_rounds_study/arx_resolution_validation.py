#!/usr/bin/env python3
"""Generate and analyze the protocol-fixed independent ARX resolution cohort."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from analyze_arx_resolution import measure, METRICS
from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream
from publication_study import _key_material

PROTOCOL = ROOT / "doc_stream_ciphers" / "ARX_RESOLUTION_VALIDATION_PROTOCOL.txt"
PROTOCOL_SHA256 = "01421b276761aa61f8ab69b1339e83c8a5492615d5fa5f3d632e844295a7032b"
OUT = ROOT / "doc_stream_ciphers" / "data" / "arx_resolution_validation"
SEED = 20261029
FAMILIES = ("ChaCha20", "Salsa20")
ROUNDS = (2, 4)
INDICES = tuple(range(840, 920))
SMOKE_INDICES = (920, 921)
SEGMENTS = (32, 64, 128)
WINDOWS = {"full8192": (0, 16), "first4096": (0, 8), "last4096": (8, 16)}
SIGN_FLIPS = 100000
SIGN_SEED = 2026102901
BOOTSTRAPS = 5000
BOOTSTRAP_SEED = 2026102902
PLANNED = (("Salsa20", 32, "positive"), ("Salsa20", 64, "positive"),
           ("Salsa20", 128, "positive"), ("ChaCha20", 32, "positive"),
           ("ChaCha20", 64, "negative"))
POPCOUNT = np.asarray([i.bit_count() for i in range(256)], dtype=np.uint8)
PER_KEY_SHAPE = (2, 2, 64, 4, 16, 16)
COUNTER_WORDS = (4, 5, 6, 7, 11)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes() -> dict[str, str]:
    files = (Path(__file__), Path(__file__).with_name("analyze_arx_resolution.py"),
             Path(__file__).with_name("extension_stream_cores.py"),
             Path(__file__).with_name("publication_study.py"),
             ROOT / "src" / "spectral_crypto_analyzer" / "primitives.py")
    return {str(path.relative_to(ROOT)): sha256(path) for path in files}


def specification(indices: tuple[int, ...]) -> dict[str, object]:
    if sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise AssertionError("Locked protocol hash changed")
    if indices not in (INDICES, SMOKE_INDICES):
        raise ValueError("Use the full fixed cohort, or the separate two-key smoke cohort")
    return {"protocol_sha256": PROTOCOL_SHA256, "source_sha256": source_hashes(),
            "seed": SEED, "key_indices": list(indices), "families": FAMILIES,
            "rounds": ROUNDS, "per_key_shape": PER_KEY_SHAPE,
            "numpy_version": np.__version__, "python_version": platform.python_version()}


def fingerprint(spec: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()


def _json(path: Path, data: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _save_raw(path: Path, **arrays: np.ndarray) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        np.savez_compressed(stream, **arrays)
    temporary.replace(path)


def flip_nonce(base: bytes, bit: int) -> bytes:
    data = bytearray(base)
    data[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(data)


def word_hw(left: bytes, right: bytes) -> np.ndarray:
    if len(left) != 1024 or len(right) != 1024:
        raise ValueError("Expected sixteen complete 512-bit blocks")
    difference = np.bitwise_xor(np.frombuffer(left, dtype=np.uint8),
                                np.frombuffer(right, dtype=np.uint8))
    return POPCOUNT[difference].reshape(16, 16, 4).sum(axis=-1, dtype=np.uint8)


def counter_violations(stream: bytes) -> int:
    words = np.frombuffer(stream, dtype="<u4").reshape(16, 16)[:, COUNTER_WORDS]
    return int(np.count_nonzero(words[1:] != words[:1]))


def generate_one(key_index: int) -> tuple[np.ndarray, np.ndarray, dict[str, int]]:
    """Keep shared base vertices fixed across the 64 edges of each nonce star."""
    if key_index not in INDICES + SMOKE_INDICES:
        raise ValueError("Key index is outside the locked validation/smoke cohorts")
    master, _ = _key_material(SEED, key_index)
    material = hashlib.shake_256(b"resolution-validation-nonces-v1:" + master).digest(32)
    bases = tuple(material[8*i:8*(i+1)] for i in range(4))
    others = tuple(tuple(flip_nonce(base, bit) for bit in range(64)) for base in bases)
    vertices = set(bases)
    vertices.update(nonce for group in others for nonce in group)
    if len(vertices) != 260:
        raise AssertionError(f"Nonce stars intersect for key {key_index}")
    actual = np.empty(PER_KEY_SHAPE, dtype=np.uint8)
    oracle = np.empty_like(actual)
    count = {"salsa2_emitted_counter_independence_violations": 0,
             "salsa2_emitted_counter_independence_comparisons": 0}
    for fi, family in enumerate(FAMILIES):
        label = family.encode() + b":"
        key = hashlib.blake2b(b"resolution-validation-key-v1:" + label + master,
                              digest_size=32).digest()
        secret = hashlib.blake2b(b"resolution-validation-secret-v1:" + label + master,
                                 digest_size=32).digest()
        domain = b"resolution-validation-oracle-v1:" + label
        cipher = chacha20_iv_stream if family == "ChaCha20" else salsa20_iv_stream
        for ri, rounds in enumerate(ROUNDS):
            def stream_for(nonce: bytes) -> bytes:
                nonce_arg = b"\0" * 4 + nonce if fi == 0 else nonce
                stream = cipher(key, nonce_arg, rounds, 1024)
                if fi == 1 and rounds == 2:
                    count["salsa2_emitted_counter_independence_violations"] += counter_violations(stream)
                    count["salsa2_emitted_counter_independence_comparisons"] += 15 * len(COUNTER_WORDS)
                return stream

            def null_for(nonce: bytes) -> bytes:
                return hashlib.shake_256(domain + secret + rounds.to_bytes(2, "big") + nonce).digest(1024)

            base_streams = [stream_for(base) for base in bases]
            base_oracles = [null_for(base) for base in bases]
            for bi, group in enumerate(others):
                for bit, other in enumerate(group):
                    actual[fi, ri, bit, bi] = word_hw(base_streams[bi], stream_for(other))
                    oracle[fi, ri, bit, bi] = word_hw(base_oracles[bi], null_for(other))
    return actual, oracle, count


def aggregate_words(words: np.ndarray, segment_bits: int,
                    block_start: int, block_stop: int) -> np.ndarray:
    x = np.asarray(words)
    if x.shape[-2:] != (16, 16) or segment_bits not in SEGMENTS:
        raise ValueError("Expected sixteen 16-word blocks and segment width 32/64/128")
    if not 0 <= block_start < block_stop <= 16:
        raise ValueError("Window must contain complete blocks")
    width = segment_bits // 32
    shape = (*x.shape[:-2], block_stop-block_start, 16//width, width)
    return x[..., block_start:block_stop, :].reshape(shape).sum(
        axis=-1, dtype=np.uint16).reshape(*x.shape[:-2], -1)


def holm(pvalues: np.ndarray) -> np.ndarray:
    p = np.asarray(pvalues, dtype=float)
    if p.ndim != 1 or np.any((p < 0) | (p > 1)):
        raise ValueError("Expected a vector of p values in [0,1]")
    order = np.argsort(p, kind="stable")
    adjusted = np.empty_like(p)
    adjusted[order] = np.minimum(1, np.maximum.accumulate(
        p[order] * np.arange(len(p), 0, -1)))
    return adjusted


def sign_flip_pvalues(values: np.ndarray, replicates: int = SIGN_FLIPS,
                      seed: int = SIGN_SEED) -> tuple[np.ndarray, np.ndarray]:
    """Two-sided mean tests with one shared sign per entire independent key."""
    values = np.asarray(values, dtype=float)
    if values.ndim != 2 or not np.all(np.isfinite(values)) or replicates < 1:
        raise ValueError("Expected finite key-by-endpoint values and positive replicate count")
    actual = np.abs(values.mean(axis=0))
    tolerance = 1e-12 * np.maximum(1, actual)
    counts = np.zeros(values.shape[1], dtype=np.int64)
    rng = np.random.default_rng(seed)
    for start in range(0, replicates, 4096):
        signs = 2*rng.integers(0, 2, (min(4096, replicates-start), len(values)), dtype=np.int8)-1
        permuted = np.abs(signs @ values / len(values))
        counts += np.count_nonzero(permuted >= actual - tolerance, axis=0)
    return (counts + 1) / (replicates + 1), counts


def structural_checks(actual: np.ndarray) -> dict[str, dict[str, int]]:
    """Count every fixed structural equality, without statistical testing."""
    salsa = actual[:, 1, 0]
    checks: dict[str, dict[str, int]] = {}
    arrays = {
        "salsa2_first_nonce_word_output1_zero": salsa[:, :32, :, :, 1],
        "salsa2_second_nonce_word_outputs0_1_2_3_6_zero": salsa[:, 32:, :, :, (0, 1, 2, 3, 6)],
        "salsa2_second_nonce_msb_mask56_output7_zero": salsa[:, 56, :, :, 7],
    }
    for name, array in arrays.items():
        checks[name] = {"comparisons": int(array.size), "violations": int(np.count_nonzero(array))}
    repeated = salsa[..., COUNTER_WORDS]
    unequal = repeated[..., 1:, :] != repeated[..., :1, :]
    checks["salsa2_nonce_difference_hw_counter_independence"] = {
        "comparisons": int(unequal.size), "violations": int(np.count_nonzero(unequal))}
    return checks


def generate(directory: Path, indices: tuple[int, ...]) -> dict[str, object]:
    directory.mkdir(parents=True, exist_ok=True)
    checkpoints = directory / "checkpoints"
    checkpoints.mkdir(exist_ok=True)
    spec = specification(indices)
    token = fingerprint(spec)
    manifest_path = directory / "generation_manifest.json"
    if manifest_path.exists():
        old = json.loads(manifest_path.read_text())
        if old["fingerprint"] != token:
            raise AssertionError("Resume rejected: protocol, source, cohort or software differs")
    manifest = {**spec, "fingerprint": token, "status": "generating",
                "smoke": indices == SMOKE_INDICES,
                "oracle_payload": "domain || 32-byte secret || rounds uint16 big endian || 8-byte nonce",
                "raw_axes": ["key", "cipher", "round", "nonce_mask", "base_nonce", "block512", "word32"]}
    _json(manifest_path, manifest)
    collected_a, collected_b = [], []
    counters: list[dict[str, int]] = []
    hashes: dict[str, str] = {}
    started = perf_counter()
    generated_count = 0
    for done, key_index in enumerate(indices, 1):
        path = checkpoints / f"key_{key_index}.npz"
        metadata = checkpoints / f"key_{key_index}.json"
        if metadata.exists():
            saved = json.loads(metadata.read_text())
            if saved["fingerprint"] != token or saved["key_index"] != key_index:
                raise AssertionError(f"Checkpoint specification differs: {key_index}")
            if sha256(path) != saved["raw_sha256"]:
                raise AssertionError(f"Checkpoint checksum differs: {key_index}")
            with np.load(path) as raw:
                a, b = raw["observed"], raw["oracle"]
            count = saved["direct_structural_checks"]
        else:
            a, b, count = generate_one(key_index)
            _save_raw(path, observed=a, oracle=b)
            _json(metadata, {"fingerprint": token, "key_index": key_index,
                             "raw_sha256": sha256(path), "direct_structural_checks": count})
            generated_count += 1
        if a.shape != PER_KEY_SHAPE or b.shape != PER_KEY_SHAPE or a.max() > 32 or b.max() > 32:
            raise AssertionError(f"Invalid output-word HW checkpoint: {key_index}")
        collected_a.append(a)
        collected_b.append(b)
        counters.append(count)
        hashes[path.name] = sha256(path)
        if done % 10 == 0 or done == len(indices):
            elapsed = perf_counter() - started
            print(f"Validation generation {done}/{len(indices)} keys; {elapsed:.1f}s; "
                  f"new keys {generated_count}", flush=True)
    if specification(indices) != spec:
        raise AssertionError("Source or protocol changed during generation")
    raw_path = directory / "arx_resolution_validation_raw.npz"
    _save_raw(raw_path, observed=np.stack(collected_a), oracle=np.stack(collected_b),
              key_indices=np.asarray(indices, dtype=np.int32))
    manifest.update(status="complete", raw_sha256=sha256(raw_path),
                    raw_shape=[len(indices), *PER_KEY_SHAPE],
                    checkpoint_sha256=hashes, generation_elapsed_seconds=perf_counter()-started,
                    direct_structural_checks={name: sum(c[name] for c in counters) for name in counters[0]})
    _json(manifest_path, manifest)
    return manifest


def analyze(directory: Path) -> dict[str, object]:
    generation = json.loads((directory / "generation_manifest.json").read_text())
    indices = tuple(generation["key_indices"])
    if generation["status"] != "complete" or fingerprint(specification(indices)) != generation["fingerprint"]:
        raise AssertionError("Analysis must use complete data generated with the same sources")
    raw_path = directory / "arx_resolution_validation_raw.npz"
    if sha256(raw_path) != generation["raw_sha256"]:
        raise AssertionError("Raw validation data checksum differs")
    with np.load(raw_path) as raw:
        actual, oracle, key_indices = raw["observed"], raw["oracle"], raw["key_indices"]
    if actual.shape != (len(indices), *PER_KEY_SHAPE) or oracle.shape != actual.shape:
        raise AssertionError("Wrong validation raw axes")
    if not np.array_equal(key_indices, indices):
        raise AssertionError("Key indices differ from the generation manifest")
    samples = np.random.default_rng(BOOTSTRAP_SEED).integers(
        0, len(indices), (BOOTSTRAPS, len(indices)), dtype=np.int16)
    per_key: list[dict[str, object]] = []
    summary: list[dict[str, object]] = []
    compact: list[dict[str, object]] = []
    planned_values: dict[tuple[str, int], np.ndarray] = {}
    for fi, family in enumerate(FAMILIES):
        for ri, rounds in enumerate(ROUNDS):
            for segment in SEGMENTS:
                for window, (start, stop) in WINDOWS.items():
                    measurements = [measure(aggregate_words(x[:, fi, ri], segment, start, stop), segment)
                                    for x in (actual, oracle)]
                    endpoints: dict[str, np.ndarray] = {}
                    for name in METRICS:
                        observed, control = measurements[0][name], measurements[1][name]
                        delta = observed - control
                        endpoints[f"actual_{name}"] = observed.mean(axis=-1)
                        endpoints[f"control_{name}"] = control.mean(axis=-1)
                        endpoints[f"delta_{name}"] = delta.mean(axis=-1)
                        endpoints[f"word_gap_delta_{name}"] = (delta[:, 32:] - delta[:, :32]).mean(axis=-1)
                    if rounds == 2 and window == "full8192":
                        planned_values[family, segment] = endpoints["word_gap_delta_hmp"]
                    axes = {"family": family, "rounds": rounds, "segment_bits": segment,
                            "window": window, "block_start": start, "block_stop_exclusive": stop,
                            "n_samples": (stop-start)*512//segment,
                            "samples_per_512bit_block": 512//segment}
                    for ki, key in enumerate(indices):
                        per_key.append({**axes, "key_index": key,
                                        **{name: float(value[ki]) for name, value in endpoints.items()}})
                    row: dict[str, object] = {**axes, "n_keys": len(indices)}
                    for name, value in endpoints.items():
                        low, high = np.quantile(value[samples].mean(axis=1), (0.025, 0.975))
                        row.update({f"{name}_mean": float(value.mean()),
                                    f"{name}_ci95_low": float(low), f"{name}_ci95_high": float(high)})
                    summary.append(row)
                    selected_names = ("word_gap_delta_hmp", "delta_hnodc",
                                      "delta_block_harmonic_share", "delta_block_fundamental_share",
                                      "delta_phase_range_fraction")
                    compact.append({**axes, "n_keys": len(indices),
                                    **{f"{name}_{suffix}": row[f"{name}_{suffix}"]
                                       for name in selected_names for suffix in ("mean", "ci95_low", "ci95_high")}})
            print(f"Validation analysis {family}/{rounds}: all resolutions and windows", flush=True)
    values = np.column_stack([planned_values[family, segment] for family, segment, _ in PLANNED])
    pvalues, extremes = sign_flip_pvalues(values)
    corrected = holm(pvalues)
    planned = []
    for column, (family, segment, prediction) in enumerate(PLANNED):
        estimate = float(values[:, column].mean())
        low, high = np.quantile(values[samples, column].mean(axis=1), (0.025, 0.975))
        sign = "positive" if estimate > 0 else "negative" if estimate < 0 else "zero"
        planned.append({"family": family, "rounds": 2, "segment_bits": segment,
                        "window": "full8192", "endpoint": "word_gap_delta_hmp",
                        "n_keys": len(indices), "mean": estimate,
                        "ci95_low": float(low), "ci95_high": float(high),
                        "predicted_sign": prediction, "observed_sign": sign,
                        "prediction_matches": sign == prediction,
                        "sign_flip_extremes": int(extremes[column]), "replicates": SIGN_FLIPS,
                        "p_two_sided_plus_one": float(pvalues[column]),
                        "p_holm_five": float(corrected[column]),
                        "cohort": "smoke_only" if generation["smoke"] else "independent_validation"})
    checks = structural_checks(actual)
    direct = generation["direct_structural_checks"]
    checks["salsa2_emitted_counter_independence"] = {
        "comparisons": direct["salsa2_emitted_counter_independence_comparisons"],
        "violations": direct["salsa2_emitted_counter_independence_violations"]}
    _csv(directory / "arx_resolution_validation_per_key.csv", per_key)
    _csv(directory / "arx_resolution_validation_summary.csv", summary)
    _csv(directory / "arx_resolution_validation_compact.csv", compact)
    _csv(directory / "arx_resolution_validation_planned_tests.csv", planned)
    _json(directory / "arx_resolution_validation_structural_checks.json", checks)
    manifest = {"status": "smoke_complete" if generation["smoke"] else "completed_independent_validation",
                "protocol_sha256": PROTOCOL_SHA256, "source_sha256": source_hashes(),
                "generation_manifest_sha256": sha256(directory / "generation_manifest.json"),
                "raw_sha256": sha256(raw_path), "raw_shape": list(actual.shape),
                "key_indices": list(indices), "seed": SEED,
                "raw_axes": generation["raw_axes"], "families": FAMILIES, "rounds": ROUNDS,
                "segment_bits": SEGMENTS, "windows_blocks_start_stop_exclusive": WINDOWS,
                "power_averaging": "Q=4 base-nonce DFT powers averaged per mask before normalization",
                "gap": "mean_b[(observed-control)(32+b)-(observed-control)(b)], b=0..31",
                "resampling_unit": "entire key pair; same resamples/signs across endpoints",
                "sign_flip_test": {"replicates": SIGN_FLIPS, "seed": SIGN_SEED,
                                   "statistic": "absolute whole-key mean",
                                   "pvalue": "(1+count(abs(permuted_mean)>=abs(observed_mean)))/(B+1)",
                                   "roundoff_tolerance": "1e-12 * max(1,abs(observed_mean))",
                                   "multiplicity": "Holm across exactly five planned two-sided endpoints"},
                "bootstrap": {"replicates": BOOTSTRAPS, "seed": BOOTSTRAP_SEED,
                              "interval": "pointwise whole-key percentile 95%"},
                "planned_endpoints": [list(x) for x in PLANNED],
                "descriptive": "all other endpoints, rounds and windows; no significance tests",
                "structural_checks": checks,
                "numpy_version": np.__version__, "python_version": platform.python_version(),
                "output_rows": {"per_key": len(per_key), "summary": len(summary), "planned_tests": len(planned)},
                "output_sha256": {path.name: sha256(path) for path in sorted(directory.glob("arx_resolution_validation_*.csv"))}}
    _json(directory / "arx_resolution_validation_manifest.json", manifest)
    if any(check["violations"] for check in checks.values()):
        raise AssertionError(f"Structural prediction failed; raw data and all counts retained: {checks}")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="separate indices 920--921, written to /tmp")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--analyze-only", action="store_true")
    args = parser.parse_args()
    directory = args.output or (Path("/tmp/arx_resolution_validation_smoke") if args.smoke else OUT)
    if args.smoke and not directory.resolve().is_relative_to(Path("/tmp")):
        parser.error("Smoke data must be written under /tmp")
    if not args.analyze_only:
        generate(directory, SMOKE_INDICES if args.smoke else INDICES)
    result = analyze(directory)
    print(json.dumps({"status": result["status"], "rows": result["output_rows"],
                      "structural_checks": result["structural_checks"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
