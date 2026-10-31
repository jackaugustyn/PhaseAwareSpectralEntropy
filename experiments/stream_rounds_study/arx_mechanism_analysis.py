#!/usr/bin/env python3
"""Audit two-round ARX data-flow predictions against archived output words.

No new key cohort is generated. Word-level dependency union proves absence of
paths; presence is only a reachability bound, not a differential probability.
An independently instrumented numeric evaluator checks archived inputs and
feed-forward identities against the production implementations.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from extension_stream_cores import _salsa20_block_reduced
from literature_mask_followup import SEED, _digest, _word_hw, _xor_nonce
from publication_study import _key_material
from spectral_crypto_analyzer.primitives import _chacha20_block_reduced


MASK32 = (1 << 32) - 1
FAMILIES = ("ChaCha20", "Salsa20")
NONCE_WORDS = {"ChaCha20": (14, 15), "Salsa20": (6, 7)}
SCHEDULES = {
    "ChaCha20": (
        ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)),
        ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)),
    ),
    "Salsa20": (
        ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11)),
        ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)),
    ),
}
RAW = ROOT / "doc_stream_ciphers/data/literature_mask_followup/arx_raw.npz"
OUT = ROOT / "doc_stream_ciphers/data/arx_mechanism_results"


def evaluate(initial: list[int], family: str, dependency: bool = False) -> list[list[int]]:
    """Return state after each round and after the final feed-forward.

    In dependency mode, each integer is a set of source-word labels. Union is
    conservative for addition and XOR; rotations preserve word labels.
    """
    if dependency:
        add = xor = lambda a, b: a | b
        rot = lambda a, n: a
    else:
        add = lambda a, b: (a + b) & MASK32
        xor = lambda a, b: a ^ b
        rot = lambda a, n: ((a << n) | (a >> (32 - n))) & MASK32
    state = initial.copy()
    history = []
    for schedule in SCHEDULES[family]:
        for a, b, c, d in schedule:
            if family == "ChaCha20":
                state[a] = add(state[a], state[b])
                state[d] = rot(xor(state[d], state[a]), 16)
                state[c] = add(state[c], state[d])
                state[b] = rot(xor(state[b], state[c]), 12)
                state[a] = add(state[a], state[b])
                state[d] = rot(xor(state[d], state[a]), 8)
                state[c] = add(state[c], state[d])
                state[b] = rot(xor(state[b], state[c]), 7)
            else:
                state[b] = xor(state[b], rot(add(state[a], state[d]), 7))
                state[c] = xor(state[c], rot(add(state[b], state[a]), 9))
                state[d] = xor(state[d], rot(add(state[c], state[b]), 13))
                state[a] = xor(state[a], rot(add(state[d], state[c]), 18))
        history.append(state.copy())
    history.append([add(a, b) for a, b in zip(state, initial)])
    return history


def initial_state(key: bytes, nonce: bytes, counter: int, family: str) -> list[int]:
    constants = list(struct.unpack("<4I", b"expand 32-byte k"))
    words = list(struct.unpack("<8I", key))
    n0, n1 = struct.unpack("<2I", nonce)
    if family == "ChaCha20":
        return constants + words + [counter, 0, n0, n1]
    return [constants[0], *words[:4], constants[1], n0, n1,
            counter, 0, constants[2], *words[4:], constants[3]]


def numeric_stream(key: bytes, nonce: bytes, family: str) -> tuple[bytes, list[list[int]]]:
    states = [evaluate(initial_state(key, nonce, counter, family), family)[-1]
              for counter in range(8)]
    return b"".join(struct.pack("<16I", *state) for state in states), states


def row_shift(state: list[int]) -> list[int]:
    return [state[4 * row + (col - 1) % 4] for row in range(4) for col in range(4)]


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def numeric_archive_audit(observed: np.ndarray, key_indices: np.ndarray) -> dict:
    """Reuse first and last archived keys; no fresh observational cohort."""
    pair_checks = block_checks = msb_checks = symmetry_checks = 0
    for key_pos in (0, len(key_indices) - 1):
        master, _ = _key_material(SEED, int(key_indices[key_pos]))
        material = hashlib.shake_256(b"litmask-common-nonce-v1:" + master).digest(32)
        # One of the four archived bases, every bit and all eight counters.
        base = material[:8]
        for family_idx, family in enumerate(FAMILIES):
            key = _digest(b"litmask-arx-key-v1:" + family.encode() + b":", master, 32)
            left, _ = numeric_stream(key, base, family)
            for bit in range(64):
                other = _xor_nonce(base, bit)
                right, right_states = numeric_stream(key, other, family)
                assert np.array_equal(_word_hw(left, right), observed[key_pos, family_idx, 0, bit, 0])
                pair_checks += 1
                for counter, output in enumerate(right_states):
                    expected = (_chacha20_block_reduced(key, b"\0" * 4 + other, counter, 2)
                                if family == "ChaCha20" else
                                _salsa20_block_reduced(key, other, counter, 2))
                    assert struct.pack("<16I", *output) == expected
                    block_checks += 1
                state = initial_state(key, other, 0, family)
                if family == "ChaCha20":
                    assert evaluate(row_shift(state), family)[-1] == row_shift(evaluate(state, family)[-1])
                    symmetry_checks += 1
                else:
                    before = evaluate(state, family)[1]
                    changed = state.copy()
                    changed[7] ^= 1 << 31
                    after = evaluate(changed, family)[1]
                    assert before[7] ^ state[7] == after[7] ^ changed[7]
                    assert evaluate(state, family)[-1][7] == evaluate(changed, family)[-1][7]
                    msb_checks += 1
    return {"archived_nonce_pair_trajectories_checked": pair_checks,
            "instrumented_blocks_equal_production": block_checks,
            "chacha_state_rotation_identity_checks": symmetry_checks,
            "salsa_feedforward_msb_identity_checks": msb_checks}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUT)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with np.load(RAW) as archive:
        observed = archive["observed"]
        oracle = archive["oracle"]
        key_indices = archive["key_indices"]
    assert observed.shape == (80, 2, 5, 64, 4, 8, 16)
    checks = numeric_archive_audit(observed, key_indices)
    profiles, supports, summary = [], [], {}
    for family_idx, family in enumerate(FAMILIES):
        dep = evaluate([1 << word for word in range(16)], family, dependency=True)
        summary[family] = {}
        for group, source in enumerate(NONCE_WORDS[family]):
            values = observed[:, family_idx, 0, 32 * group:32 * (group + 1)]
            null = oracle[:, family_idx, 0, 32 * group:32 * (group + 1)]
            key_means = values.mean(axis=(1, 2, 3))
            for stage_idx, stage in enumerate(("column_round", "second_round", "feed_forward")):
                reached = [word for word, mask in enumerate(dep[stage_idx]) if mask & (1 << source)]
                supports.append({"family": family, "input_state_word": source, "stage": stage,
                                 "reachable_output_words": " ".join(map(str, reached)),
                                 "reachable_word_count": len(reached)})
            absent = [word for word, mask in enumerate(dep[-1]) if not mask & (1 << source)]
            assert not values[..., absent].any()
            exactly_zero = np.flatnonzero(values.max(axis=(0, 1, 2, 3)) == 0).tolist()
            assert exactly_zero == absent
            summary[family][f"nonce_word_{group + 1}"] = {
                "input_state_word": source,
                "absent_paths_after_two_rounds": absent,
                "all_zero_words_in_archive": exactly_zero,
                "observations_per_output_word": int(np.prod(values.shape[:-1])),
                "mean_output_word_hw": key_means.mean(axis=0).tolist(),
                "mean_128bit_position_hw": key_means.reshape(80, 4, 4).sum(axis=-1).mean(axis=0).tolist(),
            }
            for word in range(16):
                profiles.append({"family": family, "input_nonce_word": group + 1,
                                 "input_state_word": source, "output_word": word,
                                 "path_present": word not in absent,
                                 "mean_observed_hw": float(key_means[:, word].mean()),
                                 "mean_control_hw": float(null[..., word].mean()),
                                 "max_observed_hw": int(values[..., word].max()),
                                 "nonzero_observations": int(np.count_nonzero(values[..., word]))})

    # With fixed high counter, the five listed Salsa words are independent of
    # low counter x8. This is stronger than an equality of average profiles.
    salsa_dep = evaluate([1 << word for word in range(16)], "Salsa20", dependency=True)[-1]
    counter_independent = [word for word, mask in enumerate(salsa_dep) if not mask & (1 << 8)]
    assert counter_independent == [4, 5, 6, 7, 11]
    salsa = observed[:, 1, 0]
    assert np.array_equal(salsa[..., counter_independent],
                          np.broadcast_to(salsa[:, :, :, 0:1, counter_independent],
                                          salsa[..., counter_independent].shape))
    msb = observed[:, 1, 0, 56, :, :, 7]
    assert not msb.any()
    summary["Salsa20"]["low_counter_independent_output_words"] = counter_independent
    summary["Salsa20"]["counter_invariance_checked_word_values"] = int(salsa[..., counter_independent].size)
    summary["Salsa20"]["input_x7_msb_output_x7_zero_observations"] = int(msb.size)
    summary["Salsa20"]["input_x7_mean_output_x7_hw"] = float(salsa[:, 32:, :, :, 7].mean())

    # Descriptive comparison: mean profiles with and without the column shift
    # induced by the core's permutation symmetry. Valid states are not invariant
    # under this shift, so no equality of real response distributions is claimed.
    chacha = observed[:, 0, 0]
    first = chacha[:, :32].mean(axis=(1, 2, 3)).reshape(80, 4, 4)
    second = chacha[:, 32:].mean(axis=(1, 2, 3)).reshape(80, 4, 4)
    shifts = []
    for shift in range(4):
        diff = (second - np.roll(first, shift, axis=-1)).mean(axis=0)
        shifts.append({"column_shift": shift,
                       "mean_profile_rms_word_hw": float(np.sqrt(np.mean(diff ** 2))),
                       "mean_profile_mean_absolute_word_hw": float(np.mean(np.abs(diff)))})
    summary["ChaCha20"]["descriptive_column_shift_comparison"] = shifts
    summary["ChaCha20"]["second_minus_first_128bit_hw"] = (second - first).sum(axis=-1).mean(axis=0).tolist()
    summary["status"] = "Descriptive mechanism audit of archived data; no new key cohort and no inferential test."
    summary["checks"] = checks
    write_csv(args.output_dir / "dependency_support.csv", supports)
    write_csv(args.output_dir / "word_response_mechanism.csv", profiles)
    write_csv(args.output_dir / "chacha_column_shift.csv", shifts)
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    files = [RAW, Path(__file__), ROOT / "experiments/stream_rounds_study/extension_stream_cores.py",
             ROOT / "src/spectral_crypto_analyzer/primitives.py"]
    manifest = {"analysis_status": summary["status"],
                "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in files},
                "output_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in sorted(args.output_dir.iterdir()) if path.name != "manifest.json"}}
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"checks": checks, "Salsa20_zero_words": [summary["Salsa20"][f"nonce_word_{n}"]["all_zero_words_in_archive"] for n in (1, 2)],
                      "ChaCha20_shift_rms": shifts}, indent=2))


if __name__ == "__main__":
    main()
