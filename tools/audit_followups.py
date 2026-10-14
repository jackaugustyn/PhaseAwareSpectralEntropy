#!/usr/bin/env python3
"""Read-only hash and shape audit of the mask and A5/1 follow-up cohorts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "doc_stream_ciphers" / "data"


def read_json(path: Path) -> dict:
    """Load one cohort manifest, preserving its archived field names."""
    return json.loads(path.read_text(encoding="utf-8"))


def check_hash(path: Path, expected: str) -> None:
    """Verify one archived SHA-256 value and raise on a changed file."""
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    if value != expected:
        raise AssertionError(f"SHA-256 mismatch: {path.relative_to(ROOT)}")


def check_array(path: Path, shape: tuple[int, ...], first_index: int) -> None:
    """Verify observed/control dimensions and the independent key cohort."""
    with np.load(path) as raw:
        observed = raw["observed"]
        control = raw["oracle"] if "oracle" in raw else raw["control"]
        indices = raw["key_indices"]
        if observed.shape != shape or control.shape != shape:
            raise AssertionError(f"Unexpected array shape: {path.relative_to(ROOT)}")
        if not np.array_equal(indices, np.arange(first_index, first_index + shape[0])):
            raise AssertionError(f"Unexpected key indices: {path.relative_to(ROOT)}")


def main() -> None:
    """Check fixed protocols, raw arrays, and immutable processed outputs."""
    literature = DATA / "literature_mask_followup"
    lit_manifest = read_json(literature / "manifest.json")
    check_hash(ROOT / lit_manifest["protocol"], lit_manifest["protocol_sha256"])
    for name, expected in lit_manifest["raw_sha256"].items():
        check_hash(literature / f"{name}_raw.npz", expected)
    check_array(literature / "arx_raw.npz", (80, 2, 5, 64, 4, 8, 16), 520)
    check_array(literature / "trivium_raw.npz", (80, 4, 3, 4, 64), 600)
    check_array(literature / "grain_raw.npz", (80, 4, 6, 4, 32), 600)

    lit_analysis = read_json(literature / "analysis_manifest.json")
    data_count = 0
    for relative, expected in lit_analysis["analysis_files_sha256"].items():
        check_hash(ROOT / relative, expected)
        data_count += 1

    a51 = DATA / "a51_frame_followup"
    screen = read_json(a51 / "manifest.json")
    check_hash(ROOT / screen["protocol"], screen["protocol_sha256"])
    check_hash(a51 / "a51_frame_raw.npz", screen["raw_sha256"])
    check_array(a51 / "a51_frame_raw.npz", (80, 6, 22, 4, 15), 680)
    validation = read_json(a51 / "a51_loading_validation_manifest.json")
    check_hash(ROOT / validation["protocol"], validation["protocol_sha256"])
    check_hash(a51 / "a51_loading_validation_raw.npz", validation["raw_sha256"])
    check_hash(a51 / "a51_loading_validation_per_key.csv", validation["per_key_sha256"])
    check_array(a51 / "a51_loading_validation_raw.npz", (80, 2, 2, 4, 15), 760)
    analysis = read_json(a51 / "analysis_manifest.json")
    for name, expected in analysis["file_sha256"].items():
        check_hash(a51 / name, expected)
    print(f"Audited 3 mask raw arrays, {data_count} mask analysis files, "
          "2 A5/1 raw arrays, and their fixed protocol/processed-file hashes")


if __name__ == "__main__":
    main()
