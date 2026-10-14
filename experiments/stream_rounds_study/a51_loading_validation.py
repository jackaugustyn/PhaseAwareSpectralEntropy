#!/usr/bin/env python3
"""Independent fresh-key validation of the selected A5/1 loading gradient."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

import a51_frame_followup as study
from analyze_a51_frame_followup import _ci, _sign_p

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "doc_stream_ciphers" / "data" / "a51_frame_followup"
PROTOCOL = ROOT / "doc_stream_ciphers" / "A51_LOADING_VALIDATION_PROTOCOL.txt"
INDICES = tuple(range(760, 840))


def main() -> None:
    """Test the chosen zero-clock bit-21-minus-bit-0 contrast on fresh keys."""
    study._published_vector()
    records = []
    with ProcessPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(study._one, index): index for index in INDICES}
        for future in as_completed(futures):
            records.append(future.result())
    records.sort(key=lambda row: row[0])
    keys = np.asarray([np.frombuffer(row[1], dtype=np.uint8) for row in records])
    bases = np.asarray([row[2] for row in records], dtype=np.uint32)
    observed = np.stack([row[3][np.ix_([0, 5], [0, 21])] for row in records])
    control = np.stack([row[4][np.ix_([0, 5], [0, 21])] for row in records])
    if observed.shape != (80, 2, 2, 4, 15):
        raise AssertionError("Unexpected validation shape")
    OUT.mkdir(parents=True, exist_ok=True)
    raw = OUT / "a51_loading_validation_raw.npz"
    np.savez_compressed(raw, key_indices=np.asarray(INDICES, dtype=np.int32),
                        keys=keys, bases=bases, depths=np.asarray([0, 100], dtype=np.int16),
                        masks=np.asarray([1, 1 << 21], dtype=np.uint32),
                        observed=observed, control=control)
    obs_bits = np.unpackbits(observed, axis=-1, bitorder="big")[..., :114]
    ctrl_bits = np.unpackbits(control, axis=-1, bitorder="big")[..., :114]
    observed_fraction = obs_bits.mean(axis=(-1, -2))
    control_fraction = ctrl_bits.mean(axis=(-1, -2))
    delta = observed_fraction - control_fraction
    planned = delta[:, 0, 1] - delta[:, 0, 0]
    standard = delta[:, 1, 1] - delta[:, 1, 0]
    rng = np.random.default_rng(20261015)
    low, high = _ci(planned, rng)
    standard_low, standard_high = _ci(standard, rng)
    p_value = _sign_p(planned, rng)
    per_key = OUT / "a51_loading_validation_per_key.csv"
    with per_key.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["key_index", "zero_clock_bit21_minus_bit0",
                                                   "standard_bit21_minus_bit0"])
        writer.writeheader()
        for index, x, y in zip(INDICES, planned, standard):
            writer.writerow({"key_index": index, "zero_clock_bit21_minus_bit0": float(x),
                             "standard_bit21_minus_bit0": float(y)})
    summary = {"n_keys": len(INDICES),
               "planned_zero_clock_bit21_minus_bit0": {"mean": float(planned.mean()),
                                                         "ci_low": low, "ci_high": high,
                                                         "sign_flip_p_two_sided": p_value,
                                                         "reps": 100000},
               "descriptive_standard_bit21_minus_bit0": {"mean": float(standard.mean()),
                                                            "ci_low": standard_low,
                                                            "ci_high": standard_high},
               "observed_flip_by_depth_and_bit": observed_fraction.mean(axis=0).tolist(),
               "control_flip_by_depth_and_bit": control_fraction.mean(axis=0).tolist()}
    (OUT / "a51_loading_validation_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    manifest = {"protocol": str(PROTOCOL.relative_to(ROOT)),
                "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
                "source": str(Path(__file__).relative_to(ROOT)),
                "indices": [INDICES[0], INDICES[-1]],
                "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
                "per_key_sha256": hashlib.sha256(per_key.read_bytes()).hexdigest()}
    (OUT / "a51_loading_validation_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
