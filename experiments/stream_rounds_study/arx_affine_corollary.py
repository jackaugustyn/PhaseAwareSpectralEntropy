#!/usr/bin/env python3
"""Deterministic rank and singleton-HW audit of the conditional Salsa word map.

Reads the completed feed-forward archive. The default verifies saved results
against a temporary recomputation; --write explicitly regenerates them. No new
cipher keys, observations, confidence intervals, or significance tests are
generated. Rank is computed by GF(2) elimination on columns obtained directly
from modular arithmetic, independently of the closed-form formulas.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import tempfile

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "doc_stream_ciphers/data/arx_feedforward_results"
OUTPUT = ROOT / "doc_stream_ciphers/data/arx_affine_corollary"
PROTOCOL = ROOT / "doc_stream_ciphers/ARX_FEEDFORWARD_PROTOCOL.txt"
PROTOCOL_HASH = "b416c7fb7b6697e26c4707b9e6c70981245f22eaecd243c480319ea393090ef8"


def word_mask(width: int) -> int:
    if not 1 <= width <= 32:
        raise ValueError("Word width must be between 1 and 32")
    return (1 << width) - 1


def f_c(u: int, c: int, width: int = 32) -> int:
    """Direct modular definition, without the affine or carry formulas."""
    mask = word_mask(width)
    return ((int(u) ^ int(c)) + int(u)) & mask


def direct_columns(c: int, width: int = 32) -> tuple[int, ...]:
    """Columns f_C(e_b) XOR f_C(0) computed from modular addition."""
    constant = f_c(0, c, width)
    return tuple(f_c(1 << bit, c, width) ^ constant for bit in range(width))


def gf2_rank(columns) -> int:
    """Column elimination over GF(2), independent of the structure of f_C."""
    pivots: dict[int, int] = {}
    for column in columns:
        value = int(column)
        if value < 0:
            raise ValueError("GF(2) columns must be nonnegative bit vectors")
        while value:
            pivot = value.bit_length() - 1
            if pivot in pivots:
                value ^= pivots[pivot]
            else:
                pivots[pivot] = value
                break
    return len(pivots)


def rank_formula(c: int, width: int = 32) -> int:
    word_mask(width)
    return width - 1 - (int(c) & ((1 << (width - 1)) - 1)).bit_count()


def trailing_ones(c: int, width: int = 32) -> int:
    word_mask(width)
    count = 0
    while count < width and int(c) & (1 << count):
        count += 1
    return count


def weight_sum_formula(c: int, width: int = 32) -> int:
    return max(width - 1 - trailing_ones(c, width), 0)


def exhaustive_small_words(max_width: int = 8) -> dict:
    """Check every C,u; verify rank additionally through image cardinality."""
    if not 1 <= max_width <= 8:
        raise ValueError("Exhaustive checks are intentionally limited to 1--8 bits")
    total_inputs = total_constants = 0
    for width in range(1, max_width + 1):
        for c in range(1 << width):
            columns = direct_columns(c, width)
            rank = gf2_rank(columns)
            assert rank == rank_formula(c, width)
            assert sum(value.bit_count() for value in columns) == weight_sum_formula(c, width)
            occupied = 0
            for column in columns:
                assert not occupied & column
                occupied |= column
            image = set()
            for u in range(1 << width):
                predicted = c
                for bit, column in enumerate(columns):
                    if u & (1 << bit):
                        predicted ^= column
                actual = f_c(u, c, width)
                assert actual == predicted
                image.add(actual)
                total_inputs += 1
            assert len(image) == 1 << rank
            total_constants += 1
    return {"widths": list(range(1, max_width + 1)),
            "constants_checked": total_constants,
            "input_constant_pairs_checked": total_inputs,
            "image_cardinalities_checked": total_constants,
            "violations": 0}


def check_base_observations(c_values: np.ndarray, columns: np.ndarray) -> list[dict]:
    """Audit uint32 singleton differences in LSB-first column order.

    The final axis of columns contains the 32 response columns; the other
    axes must equal c_values.shape. This helper also supports corruption tests.
    """
    if columns.shape != (*c_values.shape, 32):
        raise ValueError("Expected one 32-column derivative matrix for each C")
    records = []
    for position, (c, observed) in enumerate(zip(c_values.flat, columns.reshape(-1, 32))):
        c = int(c)
        expected = np.asarray(direct_columns(c), dtype=np.uint32)
        if not np.array_equal(observed, expected):
            raise AssertionError(f"Stored singleton column mismatch in context {position}")
        rank = gf2_rank(observed)
        predicted_rank = rank_formula(c)
        if rank != predicted_rank:
            raise AssertionError(f"Stored singleton rank mismatch in context {position}")
        observed_sum = sum(int(value).bit_count() for value in observed)
        predicted_sum = weight_sum_formula(c)
        if observed_sum != predicted_sum:
            raise AssertionError(f"Stored singleton HW-sum mismatch in context {position}")
        assert observed_sum <= 31
        records.append({"c_hex": f"{c:08x}", "rank_elimination": rank,
                        "rank_formula": predicted_rank, "trailing_ones": trailing_ones(c),
                        "singleton_hw_sum_observed": observed_sum,
                        "singleton_hw_sum_formula": predicted_sum,
                        "mean_singleton_hw_observed": observed_sum / 32,
                        "mean_singleton_hw_formula": predicted_sum / 32})
    return records


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def verify_archive() -> tuple[dict[str, str], dict]:
    """Verify the existing raw, protocol, generator, and processed hashes."""
    manifest_path = INPUT / "arx_feedforward_manifest.json"
    generation_path = INPUT / "generation_manifest.json"
    raw_path = INPUT / "arx_feedforward_raw.npz"
    manifest = json.loads(manifest_path.read_text())
    generation = json.loads(generation_path.read_text())
    paths = (raw_path, manifest_path, generation_path, PROTOCOL)
    hashes = {str(path.relative_to(ROOT)): sha256(path) for path in paths}
    assert hashes[str(raw_path.relative_to(ROOT))] == manifest["raw_sha256"] == generation["raw_sha256"]
    assert hashes[str(generation_path.relative_to(ROOT))] == manifest["generation_manifest_sha256"]
    assert hashes[str(PROTOCOL.relative_to(ROOT))] == PROTOCOL_HASH == manifest["protocol_sha256"]
    assert generation["protocol_sha256"] == PROTOCOL_HASH
    assert generation["status"] == "complete" and not generation["smoke"]
    checked = len(paths)
    for relative, expected in manifest["source_sha256"].items():
        assert sha256(ROOT / relative) == expected, relative
        checked += 1
    for name, expected in manifest["output_sha256"].items():
        assert sha256(INPUT / name) == expected, name
        checked += 1
    return hashes, {"existing_hashes_verified": checked,
                    "raw_sha256": manifest["raw_sha256"],
                    "existing_cohort_indices": [1000, 1079]}


def regenerate(output: Path) -> dict:
    hashes_before, provenance = verify_archive()
    with np.load(INPUT / "arx_feedforward_raw.npz") as archive:
        all_c = archive["salsa2_c"]
        all_singletons = archive["salsa2_singleton_word7"]
        keys = archive["key_indices"]
    assert all_c.shape == (80, 33, 4, 16) and all_c.dtype == np.uint32
    assert all_singletons.shape == (80, 3, 64, 4, 16) and all_singletons.dtype == np.uint32
    np.testing.assert_array_equal(keys, np.arange(1000, 1080))

    small_words = exhaustive_small_words()
    unique_c, counts = np.unique(all_c, return_counts=True)
    c_rows = []
    for c, multiplicity in zip(unique_c, counts):
        columns = direct_columns(int(c))
        eliminated = gf2_rank(columns)
        assert eliminated == rank_formula(int(c))
        response_sum = sum(column.bit_count() for column in columns)
        assert response_sum == weight_sum_formula(int(c))
        c_rows.append({"c_hex": f"{int(c):08x}", "retained_context_count": int(multiplicity),
                       "rank_elimination": eliminated, "rank_formula": rank_formula(int(c)),
                       "trailing_ones": trailing_ones(int(c)),
                       "singleton_hw_sum_direct": response_sum,
                       "singleton_hw_sum_formula": weight_sum_formula(int(c)),
                       "mean_singleton_hw": response_sum / 32})

    # Stored mask order is MSB-first in bytes; columns for elimination use
    # the LSB-first numbering of the little-endian second nonce word x7.
    mask_order = [32 + 8 * (bit // 8) + 7 - bit % 8 for bit in range(32)]
    c_base = all_c[:, 0]
    observed_columns = np.moveaxis(all_singletons[:, 0, mask_order], 1, -1)
    base_records = check_base_observations(c_base, observed_columns)
    base_rows = []
    for i, record in enumerate(base_records):
        key_position, remainder = divmod(i, 4 * 16)
        base, block = divmod(remainder, 16)
        base_rows.append({"key_index": int(keys[key_position]), "base_nonce": base,
                          "block_counter": block, **record})
    per_key = []
    for i, key in enumerate(keys):
        rows = base_records[64 * i:64 * (i + 1)]
        per_key.append({"key_index": int(key), "base_block_contexts": 64,
                        "mean_singleton_hw_observed": float(np.mean([row["mean_singleton_hw_observed"] for row in rows])),
                        "mean_singleton_hw_formula": float(np.mean([row["mean_singleton_hw_formula"] for row in rows])),
                        "mean_conditional_rank": float(np.mean([row["rank_elimination"] for row in rows])),
                        "minimum_conditional_rank": min(row["rank_elimination"] for row in rows),
                        "maximum_conditional_rank": max(row["rank_elimination"] for row in rows)})

    examples = []
    for c in (0, 0xFFFFFFFE):
        examples.append({"c_hex": f"{c:08x}", "rank": gf2_rank(direct_columns(c)),
                         "mean_singleton_hw": weight_sum_formula(c) / 32,
                         "status": "Algebraic illustration, not a reported cipher observation"})
    assert [row["rank"] for row in examples] == [31, 1]
    assert all(row["mean_singleton_hw"] == 31 / 32 for row in examples)

    summary = {"status": "passed", "analysis_type": "deterministic corollary audit of existing observations",
               "new_cipher_cohort_generated": False, "new_significance_tests": False,
               "scope": "Rank of the linear part of the conditional 32-bit map u -> ((u XOR C)+u), not the full cipher",
               "provenance": provenance, "small_word_exhaustive_audit": small_words,
               "retained_c_contexts": int(all_c.size), "unique_c_elimination_checks": len(c_rows),
               "base_nonce_block_contexts": len(base_records),
               "stored_singleton_columns_checked": int(observed_columns.size),
               "stored_singleton_rank_elimination_checks": len(base_records),
               "stored_singleton_mean_hw_checks": len(base_records),
               "violations": 0,
               "observed_mean_singleton_hw": float(np.mean([row["mean_singleton_hw_observed"] for row in base_records])),
               "formula_mean_singleton_hw": float(np.mean([row["mean_singleton_hw_formula"] for row in base_records])),
               "conditional_rank_range_base_contexts": [min(row["rank_elimination"] for row in base_records),
                                                        max(row["rank_elimination"] for row in base_records)],
               "universal_mean_singleton_hw_upper_bound": 31 / 32,
               "algebraic_examples": examples,
               "interpretation": "No distribution for C or u is assumed. Repeated C values and nonce/block contexts are deterministic checks, not independent statistical replicates."}
    output.mkdir(parents=True, exist_ok=True)
    write_csv(output / "retained_c_corollary.csv", c_rows)
    write_csv(output / "base_context_checks.csv", base_rows)
    write_csv(output / "per_key_summary.csv", per_key)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    readme = f"""# Conditional affine-rank and singleton-HW corollary

Status: **passed**. This is a deterministic audit of the completed feed-forward
cohort (80 existing key pairs, indices 1000--1079). It generates no new cipher
observations, confidence intervals, or p values and assumes no distribution
for C or u.

Audit the saved results from the repository root (read-only):

```bash
python experiments/stream_rounds_study/arx_affine_corollary.py
python -m pytest -q tests/test_arx_affine_corollary.py
```

The default checks stored input, source, documentation and output hashes,
then recomputes in a temporary directory and compares all generated bytes.
Explicitly regenerate this new result directory only when intended:

```bash
python experiments/stream_rounds_study/arx_affine_corollary.py --write
```

Python and NumPy versions in the saved manifest describe the producing
runtime. The read-only audit reports its current versions separately; it
requires the outputs and all other manifest fields to match exactly.

For f_C(u)=((u XOR C)+u) modulo 2^32, the rank refers to the GF(2)-linear part
f_C(u) XOR C of this one conditional output-word map. It does not describe
the rank or security of the complete cipher. Its exact rank is the number
of zero bits of C at positions 0--30. Its mean HW over all 32 singleton
input changes is max(31-t(C),0)/32, where t(C) counts trailing ones from the
least significant bit, and is at most 31/32.

The audit uses all {all_c.size:,} retained C contexts (base and 32 first-word
variants) and performs independent elimination for {len(c_rows):,} distinct
constants. It checks all {observed_columns.size:,} stored second-word
singleton uint32 differences in {len(base_records):,} base/nonce/block contexts,
including rank by elimination on the observed columns. Exhaustive widths
1--8 check {small_words['input_constant_pairs_checked']:,} input/constant pairs
and image cardinalities. No violations occur.

- `retained_c_corollary.csv`: one row per distinct stored C, with multiplicity,
  independently eliminated rank, and direct/formula HW sums.
- `base_context_checks.csv`: all observed singleton-column checks, preserving
  key, base, and block identifiers; the rank and HW formulas agree exactly.
- `per_key_summary.csv`: descriptive summaries retaining whole keys, without
  inferential tests.
- `summary.json`: audit counts, bounds, and explicitly algebraic examples.
- `manifest.json`: source, input, documentation, and generated-file hashes.

The mean observed singleton HW is {summary['observed_mean_singleton_hw']:.10f},
equal to the conditional formula averaged over the same stored contexts.
This exact reconstruction is an algebraic implementation check, not an
independent empirical prediction. The C=0 and C=0xfffffffe examples have
equal mean HW but ranks 31 and 1; they are not presented as observed states.
Repeated contexts are not additional independent replicates.
"""
    (output / "README.md").write_text(readme)
    hashes_after, _ = verify_archive()
    assert hashes_after == hashes_before, "An existing input changed during the audit"
    sources = [Path(__file__), ROOT / "tests/test_arx_affine_corollary.py"]
    documents = [ROOT / "doc_stream_ciphers/arx_affine_corollary.tex",
                 ROOT / "doc_stream_ciphers/arx_affine_proof.tex"]
    manifest = {"analysis": summary["analysis_type"], "status": "passed",
                "input_sha256": hashes_before,
                "source_sha256": {str(path.relative_to(ROOT)): sha256(path) for path in sources},
                "documentation_sha256": {str(path.relative_to(ROOT)): sha256(path) for path in documents},
                "output_sha256": {path.name: sha256(path) for path in sorted(output.iterdir()) if path.name != "manifest.json"},
                "python_version": platform.python_version(), "numpy_version": np.__version__,
                "key_indices": keys.tolist(), "preexisting_inputs_unchanged_after_audit": True,
                "new_cipher_cohort_generated": False, "new_significance_tests": False}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return summary


def verify(output: Path = OUTPUT) -> dict:
    """Validate hashes and deterministic reconstruction without writes to output."""
    manifest_path = output / "manifest.json"
    stored = json.loads(manifest_path.read_text())
    for group in ("input_sha256", "source_sha256", "documentation_sha256"):
        for relative, expected in stored[group].items():
            if sha256(ROOT / relative) != expected:
                raise AssertionError(f"Saved {group} mismatch: {relative}")
    for name, expected in stored["output_sha256"].items():
        if sha256(output / name) != expected:
            raise AssertionError(f"Saved output hash mismatch: {name}")
    with tempfile.TemporaryDirectory(prefix="arx-affine-corollary-audit-") as temporary:
        scratch = Path(temporary)
        summary = regenerate(scratch)
        recomputed = json.loads((scratch / "manifest.json").read_text())
        for name in stored["output_sha256"]:
            if (scratch / name).read_bytes() != (output / name).read_bytes():
                raise AssertionError(f"Deterministic output differs: {name}")
        runtime_fields = {"python_version", "numpy_version"}
        archived_fields = {key: value for key, value in stored.items() if key not in runtime_fields}
        current_fields = {key: value for key, value in recomputed.items() if key not in runtime_fields}
        if archived_fields != current_fields:
            raise AssertionError("Recomputed manifest fields differ from the saved audit")
    return {"status": "passed", "mode": "read_only",
            "stored_runtime": {name: stored[name] for name in sorted(runtime_fields)},
            "audit_runtime": {"python_version": platform.python_version(), "numpy_version": np.__version__},
            "runtime_qualification": "Saved versions identify the producing runtime; all outputs and non-runtime manifest fields match the current recomputation exactly.",
            "summary": summary}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT)
    parser.add_argument("--write", action="store_true", help="Explicitly regenerate the new result directory")
    args = parser.parse_args()
    result = regenerate(args.output_dir) if args.write else verify(args.output_dir)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
