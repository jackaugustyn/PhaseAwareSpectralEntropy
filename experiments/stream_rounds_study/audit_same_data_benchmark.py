#!/usr/bin/env python3
"""Independently audit same-stream bit counts, comparator rows, and intervals."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import numpy as np

from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream
from publication_study import _key_material
from standard_iv_validation import MASTER_SEED, _mask_sets
from unified_six_cipher_iv_study import _pairs_by_scenario


ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "doc_stream_ciphers"
DATA = PAPER / "data" / "same_data_benchmark_results"
SOURCE = PAPER / "data" / "matched_nonce_phase_results"
PROTOCOL = PAPER / "SAME_DATA_DIAGNOSTIC_BENCHMARK.txt"
FAMILIES = ("ChaCha20", "Salsa20")
CONFIGS = (2, 4, 20)
KEY_INDICES = tuple(range(440, 520))
METRICS = ("mean_hw", "sac_rms", "lag4", "phase_range", "hmp", "p0", "hnodc")


def _csv(name: str) -> list[dict[str, str]]:
    with (DATA / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _scores(hw: np.ndarray, counts: np.ndarray) -> dict[str, float]:
    x = hw.astype(np.float64)
    mean = float(x.mean())
    if int(counts.sum()) != int(hw.sum()):
        raise AssertionError("Bit counts and HW total differ")
    sac = float(np.mean(np.square(counts.astype(np.float64) / 128 - 0.5)) ** 0.5)
    centered = x - x.mean(axis=1, keepdims=True)
    lag = float(np.einsum("ij,ij->", centered[:, :-4], centered[:, 4:]) /
                np.einsum("ij,ij->", centered, centered))
    positions = x.reshape(16, 8, 4).mean(axis=(0, 1))
    phase = float(positions.max() - positions.min())
    spectrum = np.fft.fft(x, axis=1)
    power = np.mean(spectrum.real ** 2 + spectrum.imag ** 2, axis=0)
    probabilities = power / power.sum()
    positive = probabilities[probabilities > 0]
    hmp = float(-np.sum(positive * np.log2(positive)))
    ac = power[1:] / power[1:].sum()
    positive_ac = ac[ac > 0]
    hnodc = float(-np.sum(positive_ac * np.log2(positive_ac)) / np.log2(31))
    return {"mean_hw": mean, "sac_rms": sac, "lag4": lag,
            "phase_range": phase, "hmp": hmp, "p0": float(probabilities[0]),
            "hnodc": hnodc}


def _independent_counts(master: bytes, family: str, config: int) -> tuple[np.ndarray, np.ndarray]:
    bases_bytes = hashlib.shake_256(b"matched-phase-common-nonces-v1:" + master).digest(32)
    bases = tuple(bases_bytes[i:i + 8] for i in range(0, 32, 8))
    pairs = _pairs_by_scenario(bases, _mask_sets(8))["single_bit"]
    unique = {nonce for pair in pairs for nonce in pair}
    key = hashlib.blake2b(b"matched-phase-key-v1:" + family.encode() + b":" + master,
                          digest_size=32).digest()
    secret = hashlib.blake2b(b"matched-phase-oracle-secret-v1:" + family.encode() + b":" + master,
                             digest_size=32).digest()
    observed = {
        nonce: (chacha20_iv_stream(key, bytes(4) + nonce, config, 512)
                if family == "ChaCha20" else salsa20_iv_stream(key, nonce, config, 512))
        for nonce in unique
    }
    control = {
        nonce: hashlib.shake_256(b"matched-phase-oracle-v1:" + family.encode() + b":" +
                                   config.to_bytes(2, "big") + secret + nonce).digest(512)
        for nonce in unique
    }
    output = []
    for streams in (observed, control):
        tally = np.zeros(512, dtype=np.uint16)
        for base, other in pairs:
            xor = bytes(a ^ b for a, b in zip(streams[base], streams[other], strict=True))
            tally += np.unpackbits(np.frombuffer(xor, dtype=np.uint8), bitorder="big").reshape(8, 512).sum(
                axis=0, dtype=np.uint16)
        output.append(tally.astype(np.uint8))
    return output[0], output[1]


def _close(given: str, computed: float, name: str) -> None:
    if abs(float(given) - computed) > 1e-10:
        raise AssertionError((name, given, computed))


def main() -> None:
    manifest = json.loads((DATA / "same_data_benchmark_manifest.json").read_text())
    assert manifest["status"] == "descriptive_secondary_analysis_of_known_matched_nonce_cohort"
    assert manifest["protocol_sha256"] == hashlib.sha256(PROTOCOL.read_bytes()).hexdigest()
    assert manifest["master_key_indices"] == list(KEY_INDICES)
    assert manifest["families"] == list(FAMILIES)
    assert manifest["configurations"] == list(CONFIGS)
    per_key = _csv("same_data_benchmark_per_key.csv")
    summaries = _csv("same_data_benchmark_summary.csv")
    assert len(per_key) == 480 and len(summaries) == 6
    index = {(row["family"], int(row["configuration"]), int(row["key_index"])): row for row in per_key}
    assert len(index) == 480
    with np.load(DATA / "same_data_benchmark_bit_counts.npz") as bits:
        actual_counts = bits["actual"]
        control_counts = bits["control"]
        assert actual_counts.shape == control_counts.shape == (80, 2, 3, 512)
        assert bits["key_indices"].tolist() == list(KEY_INDICES)
        assert bits["families"].tolist() == list(FAMILIES)
        assert bits["configurations"].tolist() == list(CONFIGS)
        for family_index, family in enumerate(FAMILIES):
            source = SOURCE / f"matched_phase_{family.lower()}_raw.npz"
            assert manifest["input_raw_sha256"][source.name] == hashlib.sha256(source.read_bytes()).hexdigest()
            with np.load(source) as raw:
                for key_offset, key_index in enumerate(KEY_INDICES):
                    master, _ = _key_material(MASTER_SEED, key_index)
                    for config_offset, config in enumerate(CONFIGS):
                        expected_a, expected_c = _independent_counts(master, family, config)
                        counts_a = actual_counts[key_offset, family_index, config_offset]
                        counts_c = control_counts[key_offset, family_index, config_offset]
                        assert np.array_equal(expected_a, counts_a)
                        assert np.array_equal(expected_c, counts_c)
                        row = index[family, config, key_index]
                        for label, counts in (("actual", counts_a), ("control", counts_c)):
                            hw = raw[label][key_offset, config_offset, 0]
                            values = _scores(hw, counts)
                            for metric, value in values.items():
                                _close(row[f"{label}_{metric}"], value,
                                       f"{family}/{config}/{key_index}/{label}_{metric}")
                        for metric in METRICS:
                            delta = float(row[f"actual_{metric}"]) - float(row[f"control_{metric}"])
                            _close(row[f"delta_{metric}"], delta,
                                   f"{family}/{config}/{key_index}/delta_{metric}")
    for family_index, family in enumerate(FAMILIES):
        for config_offset, config in enumerate(CONFIGS):
            summary = next(row for row in summaries if row["family"] == family and
                           int(row["configuration"]) == config)
            samples = np.random.default_rng(20261028 + family_index * 3 + config_offset).integers(
                0, 80, size=(5000, 80))
            for metric in METRICS:
                values = np.asarray([float(index[family, config, key][f"delta_{metric}"]) for key in KEY_INDICES])
                boot = values[samples].mean(axis=1)
                _close(summary[f"delta_{metric}_mean"], float(values.mean()), f"summary/{family}/{config}/{metric}")
                _close(summary[f"delta_{metric}_ci95_low"], float(np.quantile(boot, 0.025)),
                       f"low/{family}/{config}/{metric}")
                _close(summary[f"delta_{metric}_ci95_high"], float(np.quantile(boot, 0.975)),
                       f"high/{family}/{config}/{metric}")
    print("Audited all 480 key-setting records, regenerated both bit-count arrays, seven metrics, "
          "six summary cells, and all 95% bootstrap intervals")


if __name__ == "__main__":
    main()
