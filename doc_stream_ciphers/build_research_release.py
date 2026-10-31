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
RELEASE = "iv_diffusion_research_review_v0.20.0"
ARCHIVE = PAPER / f"{RELEASE}.zip"
OUTSIDE_MANIFEST = PAPER / f"{RELEASE}_manifest.json"

SINGLES = (
    "requirements.txt", "README.md", "run.py", "verify_package.py",
    "tools/check_vectors.py", "tools/audit_followups.py", "tools/audit_arx_extensions.py",
    "tools/audit_arx_feedforward.py",
    "tools/audit_arx_spectral_prediction.py", "tools/audit_arx_round_transition.py",
    "doc_stream_ciphers/main.tex", "doc_stream_ciphers/main.pdf",
    "doc_stream_ciphers/related_work_comparison.tex",
    "doc_stream_ciphers/arx_mechanism_compact.tex",
    # Preserve these exact documentation inputs for the existing corollary audit.
    "doc_stream_ciphers/arx_affine_corollary.tex",
    "doc_stream_ciphers/arx_affine_proof.tex",
    "doc_stream_ciphers/biblio.bib",
    "doc_stream_ciphers/SIX_CIPHER_UNIFIED_PROTOCOL.txt",
    "doc_stream_ciphers/SALSA20_TRANSFER_PROTOCOL.txt",
    "doc_stream_ciphers/MATCHED_NONCE_PHASE_PROTOCOL.txt",
    "doc_stream_ciphers/MASK_LITERATURE_FOLLOWUP_PROTOCOL.txt",
    "doc_stream_ciphers/A51_KNOWN_WEAKNESS_PROTOCOL.txt",
    "doc_stream_ciphers/A51_LOADING_VALIDATION_PROTOCOL.txt",
    "doc_stream_ciphers/SAME_DATA_DIAGNOSTIC_BENCHMARK.txt",
    "doc_stream_ciphers/ARX_RESOLUTION_VALIDATION_PROTOCOL.txt",
    "doc_stream_ciphers/ARX_FEEDFORWARD_PROTOCOL.txt",
    "doc_stream_ciphers/ARX_SPECTRAL_PREDICTION_PROTOCOL.txt",
    "doc_stream_ciphers/ARX_ROUND_TRANSITION_PROTOCOL.txt",
    "doc_stream_ciphers/FEEDFORWARD_EXTENSION_STATUS.md",
    "doc_stream_ciphers/CONDENSATION_NOTES.md",
    "doc_stream_ciphers/MECHANISTIC_EXTENSIONS_STATUS.md",
    "doc_stream_ciphers/SINGLE_ARTICLE_REVISION.md",
    "doc_stream_ciphers/REVIEW_RESPONSE_V020.md",
    "doc_stream_ciphers/DEPOSIT_METADATA_DRAFT.json",
    "doc_stream_ciphers/COVER_LETTER.md",
    "doc_stream_ciphers/ELECTRONICS_REVISION.md",
    "doc_stream_ciphers/RELATED_WORK_NOTES.md",
    "doc_stream_ciphers/ARX_MECHANISM_NOTES.md",
    "doc_stream_ciphers/RESEARCH_EXTENSION_STATUS.md",
    "doc_stream_ciphers/build_research_release.py",
    "doc_stream_ciphers/build_submission_package.py",
    "doc_stream_ciphers/make_integrated_mask_figure.py",
    "doc_stream_ciphers/publication_unified_mask_followup.pdf",
    "doc_stream_ciphers/make_feedforward_figure.py",
    "doc_stream_ciphers/publication_feedforward_derivatives.pdf",
    "doc_stream_ciphers/make_mechanistic_extensions_figure.py",
    "doc_stream_ciphers/publication_mechanistic_extensions.pdf",
    "doc_stream_ciphers/make_reviewed_spectrum_figure.py",
    "doc_stream_ciphers/publication_reviewed_spectrum.pdf",
    "doc_stream_ciphers/analysis/reviewed_spectrum_figure_manifest.json",
    "tests/test_stream_cipher_vectors.py",
    "tests/test_grain128_independent_reference.py",
    "tests/test_extension_stream_vectors.py",
    "tests/test_mickey20_independent_reference.py",
    "tests/test_salsa20_vectors.py",
    "tests/test_matched_nonce_phase.py",
    "tests/test_arx_resolution.py",
    "tests/test_arx_resolution_validation.py",
    "tests/test_arx_feedforward.py",
    "tests/test_arx_affine_corollary.py",
    "tests/test_arx_spectral_prediction.py",
    "tests/test_arx_round_transition.py",
)
DIRECTORIES = (
    "src/spectral_crypto_analyzer",
    "doc_stream_ciphers/data/unified_six_results",
    "doc_stream_ciphers/data/salsa20_transfer_results",
    "doc_stream_ciphers/data/matched_nonce_phase_results",
    "doc_stream_ciphers/data/same_data_benchmark_results",
    "doc_stream_ciphers/data/literature_mask_followup",
    "doc_stream_ciphers/data/a51_frame_followup",
    "doc_stream_ciphers/data/arx_mechanism_results",
    "doc_stream_ciphers/data/arx_resolution_results",
    "doc_stream_ciphers/data/arx_resolution_validation",
    "doc_stream_ciphers/data/arx_feedforward_results",
    "doc_stream_ciphers/data/arx_affine_corollary",
    "doc_stream_ciphers/data/arx_spectral_prediction",
    "doc_stream_ciphers/data/arx_round_transition",
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
    "arx_mechanism_analysis.py", "analyze_arx_resolution.py",
    "arx_resolution_validation.py",
    "arx_feedforward_study.py",
    "arx_affine_corollary.py", "arx_spectral_prediction.py", "arx_round_transition.py",
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
        if not directory.is_dir():
            raise FileNotFoundError(f"Allowlisted release directory is missing: {dirname}")
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
    validation = PAPER / "data" / "arx_resolution_validation"
    if validation / "arx_resolution_validation_raw.npz" not in files:
        raise AssertionError("Expected the completed independent ARX validation raw array")
    for suffix in (".npz", ".json"):
        checkpoint_names = {p.name for p in files if p.parent == validation / "checkpoints"
                            and p.suffix == suffix}
        expected = {f"key_{index}{suffix}" for index in range(840, 920)}
        if checkpoint_names != expected:
            raise AssertionError(f"Expected all 80 fixed-cohort validation checkpoints: {suffix}")
    feedforward = PAPER / "data" / "arx_feedforward_results"
    for suffix in (".npz", ".json"):
        actual = {p.name for p in files if p.parent == feedforward / "checkpoints"
                  and p.suffix == suffix}
        expected = {f"key_{index}{suffix}" for index in range(1000, 1080)}
        if actual != expected:
            raise AssertionError(f"Expected all 80 feed-forward checkpoints: {suffix}")
    for name, start, raw_name in (("arx_spectral_prediction", 1200, "evaluation_raw.npz"),
                                  ("arx_round_transition", 1400, "arx_round_transition_raw.npz")):
        study = PAPER / "data" / name
        if study / raw_name not in files:
            raise AssertionError(f"Missing completed raw observations: {name}")
        for suffix in (".npz", ".json"):
            actual = {p.name for p in files if p.parent == study / "checkpoints" and p.suffix == suffix}
            expected = {f"key_{index}{suffix}" for index in range(start, start + 80)}
            if actual != expected:
                raise AssertionError(f"Expected all 80 {name} checkpoints: {suffix}")
    prediction = json.loads((PAPER / "data/arx_spectral_prediction/prediction_manifest.json").read_text())
    if prediction["mc_replicates"] != 4096 or prediction["status"] != "frozen_predictions_before_evaluation":
        raise AssertionError("Expected the complete frozen prediction models")
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
        "primary_dataset": "experimental IV-diffusion diagnostics centered on reduced ChaCha20 and Salsa20, organized around core rounds, feed-forward construction, and the resulting measured response: matched-nonce phase intervention, same-stream benchmark, independent 64-mask ARX follow-up, operation-graph and feed-forward analysis, archived 32/64/128-bit resolution reanalysis, completed independent 8192-bit validation on 80 fresh key pairs, and a further paired feed-forward intervention with 38 fixed second-order nonce-mask pairs; conditional affine-rank and mean-response identities; frozen empirical spectrum models trained on keys 840--919 and evaluated on 80 new key pairs 1200--1279; and a separate 80-key-pair 2/3/4-single-round study with named Salsa20 operation witnesses; the research archive also preserves the wider seven-cipher ordinary-IV/nonce comparison, Grain/Trivium follow-ups, auxiliary A5/1 frame-difference tests, and all archived data and retrospective per-mask profiles",
        "inference_status": "original six standard HMP and three replication tests locked before indices 280--359; Salsa20 three-test transfer locked before indices 360--439; two matched-nonce phase tests locked before indices 440--519; two matched 64-mask ARX tests locked before indices 520--599; one Grain validation and a 12-cell Trivium maxT pilot locked before indices 600--679; A5/1 20-clock endpoint and 44-cell standard search locked before indices 680--759; selected zero-clock A5/1 bit contrast locked before independent indices 760--839; five two-sided ARX resolution endpoints fixed before new indices 840--919 and jointly Holm-corrected; four feed-forward and mixed-derivative endpoints fixed before new indices 1000--1079 in a separate Holm family; same-stream comparison, older mask scan, output-word profiles, archived resolution/window reanalysis, nonprimary validation endpoints, and zero-prefix lengths are descriptive; exact structural checks have no p values; the conditional-rank corollary uses preserved data with no new tests; spectral models M0/M1 are frozen before new evaluation keys 1200--1279 and report conditional mean-error intervals and Monte Carlo errors without hypothesis tests or model selection; two round-transition endpoints are fixed before new keys 1400--1479 and jointly Holm-corrected",
        "extension_status": "v0.20.0 implements targeted manuscript clarifications after an advisory review while retaining one self-contained article without Supplementary Materials. It distinguishes the loss of conditional affinity in the unfinalized word-7 map from persistent block structure in the standard additive output; clarifies sign-flip assumptions and spectrum averaging; and replaces scalar prediction panels with actual observed and frozen-model mean AC spectra. The revised plot uses existing data without new cipher cohorts or model simulations. All previous raw observations, fixed protocols, numerical results, scientific code, figures and source hashes remain preserved. The research archive also retains the exact arx_affine_corollary.tex and arx_affine_proof.tex documentation inputs required by the existing audit. REVIEW_RESPONSE_V020.md records the changes and remaining source-access limitation. Earlier manuscripts remain in the historical v0.18.0 and v0.19.0 archives.",
        "literature_scope": "the author's bibliography through October 2026 is preserved; the revised framing distinguishes local identities, paired finalization effects and empirical spectral reconstruction. It makes no priority claim for weak low-round diffusion or higher-order differences. Exact priority relative to the closest cited two-round criteria remains unresolved without reading those source passages; REVIEW_RESPONSE_V020.md records this boundary.",
        "python": platform.python_version(),
        "packages": {name: _version(name) for name in
                     ("numpy", "matplotlib", "cryptography", "pytest")},
        "file_count": len(records),
        "files": records,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with zipfile.ZipFile(ARCHIVE, "w", allowZip64=True) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"{RELEASE}/{relative}", date_time=(2026, 10, 31, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if path.suffix == ".npz" else zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
        info = zipfile.ZipInfo(f"{RELEASE}/SHA256SUMS.json", date_time=(2026, 10, 31, 0, 0, 0))
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
