#!/usr/bin/env python3
"""Build and verify the allowlisted reviewer data/code archive."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "doc_stream_ciphers"
RELEASE = "stream_spectral_entropy_review_v0.13.1"
ARCHIVE = PAPER / f"{RELEASE}.zip"
OUTSIDE_MANIFEST = PAPER / f"{RELEASE}_manifest.json"

SINGLES = (
    "requirements.txt", "README.md", "run.py", "verify_package.py",
    "tools/check_vectors.py", "tools/audit_followups.py",
    "doc_stream_ciphers/main.tex", "doc_stream_ciphers/main.pdf",
    "doc_stream_ciphers/biblio.bib",
    "doc_stream_ciphers/SIX_CIPHER_UNIFIED_PROTOCOL.txt",
    "doc_stream_ciphers/SALSA20_TRANSFER_PROTOCOL.txt",
    "doc_stream_ciphers/MATCHED_NONCE_PHASE_PROTOCOL.txt",
    "doc_stream_ciphers/MASK_LITERATURE_FOLLOWUP_PROTOCOL.txt",
    "doc_stream_ciphers/A51_KNOWN_WEAKNESS_PROTOCOL.txt",
    "doc_stream_ciphers/A51_LOADING_VALIDATION_PROTOCOL.txt",
    "doc_stream_ciphers/SAME_DATA_DIAGNOSTIC_BENCHMARK.txt",
    "doc_stream_ciphers/DEPOSIT_METADATA_DRAFT.json",
    "doc_stream_ciphers/build_research_release.py",
    "doc_stream_ciphers/build_submission_package.py",
    "doc_stream_ciphers/make_integrated_mask_figure.py",
    "doc_stream_ciphers/publication_unified_mask_followup.pdf",
    "tests/test_stream_cipher_vectors.py",
    "tests/test_grain128_independent_reference.py",
    "tests/test_extension_stream_vectors.py",
    "tests/test_mickey20_independent_reference.py",
    "tests/test_salsa20_vectors.py",
    "tests/test_matched_nonce_phase.py",
)
DIRECTORIES = (
    "src/spectral_crypto_analyzer",
    "doc_stream_ciphers/data/unified_six_results",
    "doc_stream_ciphers/data/salsa20_transfer_results",
    "doc_stream_ciphers/data/matched_nonce_phase_results",
    "doc_stream_ciphers/data/same_data_benchmark_results",
    "doc_stream_ciphers/data/literature_mask_followup",
    "doc_stream_ciphers/data/a51_frame_followup",
    "doc_stream_ciphers/analysis/mask_scan_results",
    "doc_stream_ciphers/Definitions",
    "tests/vectors/extension",
)
STUDY_SCRIPTS = (
    "publication_study.py", "analyze_spectral_added_value.py",
    "standard_iv_validation.py", "extension_stream_cores.py",
    "unified_six_cipher_iv_study.py", "audit_unified_six_results.py",
    "salsa20_transfer_study.py", "audit_salsa20_transfer.py",
    "matched_nonce_phase_study.py", "audit_matched_nonce_phase.py",
    "same_data_diagnostic_benchmark.py", "audit_same_data_benchmark.py",
    "explore_mask_spectral_entropy.py", "analyze_mask_profiles.py",
    "audit_mask_profiles.py",
    "literature_mask_followup.py", "analyze_literature_mask_followup.py",
    "a51_frame_followup.py", "analyze_a51_frame_followup.py",
    "a51_loading_validation.py",
)


def _version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _files() -> list[Path]:
    files = {ROOT / name for name in SINGLES}
    files.update(ROOT / "experiments" / "stream_rounds_study" / name for name in STUDY_SCRIPTS)
    for dirname in DIRECTORIES:
        directory = ROOT / dirname
        files.update(path for path in directory.rglob("*") if path.is_file() and (
            dirname != "src/spectral_crypto_analyzer" or path.suffix == ".py"
        ) and (
            dirname != "doc_stream_ciphers/Definitions" or path.suffix in {".cls", ".tex", ".bst", ".eps", ".pdf", ".sty"}
        ))
    if not all(path.exists() and path.is_file() for path in files):
        raise FileNotFoundError("Allowlisted release file is missing")
    raw = [p for p in files if p.parent == PAPER / "data" / "unified_six_results" and p.name.endswith("_raw.npz")]
    if len(raw) != 6:
        raise AssertionError("Expected one unified raw trajectory array per cipher")
    salsa_raw = [p for p in files if p.parent == PAPER / "data" / "salsa20_transfer_results" and
                 p.name == "salsa20_transfer_raw.npz"]
    if len(salsa_raw) != 1:
        raise AssertionError("Expected one Salsa20 transfer raw trajectory array")
    phase_raw = [p for p in files if p.parent == PAPER / "data" / "matched_nonce_phase_results" and
                 p.name in {"matched_phase_chacha20_raw.npz", "matched_phase_salsa20_raw.npz"}]
    if len(phase_raw) != 2:
        raise AssertionError("Expected two matched-nonce phase raw trajectory arrays")
    benchmark_bits = [p for p in files if p.parent == PAPER / "data" / "same_data_benchmark_results" and
                      p.name == "same_data_benchmark_bit_counts.npz"]
    if len(benchmark_bits) != 1:
        raise AssertionError("Expected same-stream bitwise benchmark counts")
    followup_raw = [p.name for p in files if p.parent == PAPER / "data" / "literature_mask_followup"
                    and p.name.endswith("_raw.npz")]
    if sorted(followup_raw) != ["arx_raw.npz", "grain_raw.npz", "trivium_raw.npz"]:
        raise AssertionError("Expected ARX, Grain, and Trivium follow-up raw arrays")
    a51_raw = [p.name for p in files if p.parent == PAPER / "data" / "a51_frame_followup"
               and p.name.endswith("_raw.npz")]
    if sorted(a51_raw) != ["a51_frame_raw.npz", "a51_loading_validation_raw.npz"]:
        raise AssertionError("Expected A5/1 screen and validation raw arrays")
    return sorted(files, key=lambda path: str(path.relative_to(ROOT)))


def main() -> None:
    files = _files()
    records = []
    for path in files:
        content = path.read_bytes()
        records.append({
            "path": path.relative_to(ROOT).as_posix(),
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    manifest = {
        "release": RELEASE,
        "status": "local_reviewer_candidate_no_public_doi",
        "primary_dataset": "seven-cipher ordinary-IV/nonce protocol, Salsa20 transfer, matched-nonce phase cohort, same-stream benchmark, retrospective per-mask profiles, independent ARX/Grain/Trivium follow-up, and auxiliary A5/1 frame-difference stress test",
        "inference_status": "original six standard HMP and three replication tests locked before indices 280--359; Salsa20 three-test transfer locked before indices 360--439; two matched-nonce phase tests locked before indices 440--519; two matched 64-mask ARX tests locked before indices 520--599; one Grain validation and a 12-cell Trivium maxT pilot locked before indices 600--679; A5/1 20-clock endpoint and 44-cell standard search locked before indices 680--759; selected zero-clock A5/1 bit contrast locked before independent indices 760--839; same-stream comparison, older mask scan, output-word profiles, and zero-prefix lengths are descriptive",
        "python": platform.python_version(),
        "packages": {name: _version(name) for name in
                     ("numpy", "matplotlib", "cryptography")},
        "file_count": len(records),
        "files": records,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with zipfile.ZipFile(ARCHIVE, "w", allowZip64=True) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"{RELEASE}/{relative}", date_time=(2026, 10, 13, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if path.suffix == ".npz" else zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
        info = zipfile.ZipInfo(f"{RELEASE}/SHA256SUMS.json", date_time=(2026, 10, 13, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, manifest_bytes)
    with zipfile.ZipFile(ARCHIVE) as archive:
        failed = archive.testzip()
        if failed is not None:
            raise AssertionError(f"ZIP CRC failure: {failed}")
        expected = {f"{RELEASE}/{record['path']}" for record in records}
        expected.add(f"{RELEASE}/SHA256SUMS.json")
        if set(archive.namelist()) != expected:
            raise AssertionError("ZIP members differ from the allowlist")
        for record in records:
            content = archive.read(f"{RELEASE}/{record['path']}")
            if hashlib.sha256(content).hexdigest() != record["sha256"]:
                raise AssertionError(f"SHA-256 mismatch: {record['path']}")
    outside = dict(manifest)
    outside["archive_path"] = ARCHIVE.name
    outside["archive_bytes"] = ARCHIVE.stat().st_size
    outside["archive_sha256"] = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    OUTSIDE_MANIFEST.write_text(json.dumps(outside, indent=2, ensure_ascii=False) + "\n")
    print(f"Verified {len(records)} files in {ARCHIVE.name}; {ARCHIVE.stat().st_size} archive bytes")
    print(f"Archive SHA-256: {outside['archive_sha256']}")


if __name__ == "__main__":
    main()
