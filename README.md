# Phase-Aware Spectral Entropy: Entropy article and reproducibility package

This folder contains the complete manuscript, the figure used in it, the
processed tables and raw arrays behind its results, fixed study protocols,
source code, and cipher-vector checks. The manuscript studies IV/nonce
diffusion in seven stream ciphers and a separate A5/1 frame experiment. It is
ready for author review and DOI deposition; no public DOI is assigned yet.

## Start here

Run these commands **from this folder**:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run.py verify
.venv/bin/python run.py build
```

`verify` checks published cipher vectors, the nonce mapping and rotation
invariants, archived raw arrays, statistical summaries, and SHA-256 digests.
It does not regenerate the computationally expensive cohorts. `build`
regenerates the article figure and compiles `doc_stream_ciphers/main.pdf`.
Building the PDF requires `latexmk`, `pdflatex`, and `bibtex` in addition to
Python. The MDPI class and bibliography inputs are included in this folder.

The code requires Python 3.10 or newer. `run.py` sets `PYTHONPATH` for child
scripts, so the commands above work without installing this repository as a
package. On systems without `venv`, use a Python environment with the packages
listed in `requirements.txt`. The release was checked with Python 3.12.3,
NumPy 1.26.4, Matplotlib 3.6.3, and cryptography 41.0.7.

## What's inside

| Path | Purpose |
| --- | --- |
| `doc_stream_ciphers/main.tex`, `main.pdf`, `biblio.bib`, `Definitions/` | Single-file MDPI manuscript, compiled copy, references, and template. |
| `doc_stream_ciphers/publication_unified_mask_followup.pdf` | Figure included in the article. |
| `doc_stream_ciphers/data/`, `doc_stream_ciphers/analysis/mask_scan_results/` | Raw `.npz` arrays, per-key values, summary tables, planned tests, and manifests. |
| `doc_stream_ciphers/*PROTOCOL.txt`, `SAME_DATA_DIAGNOSTIC_BENCHMARK.txt` | Unchanged text of the locked designs and same-stream comparison plan. |
| `experiments/stream_rounds_study/` | Cipher generation, measurement, statistical analyses, and read-only audits. |
| `src/spectral_crypto_analyzer/` | Reused cipher cores required by the study. |
| `tests/`, `tools/check_vectors.py` | Published vectors and invariants, runnable without pytest. |
| `PACKAGE_MANIFEST.json`, `verify_package.py` | SHA-256 inventory of this folder. |

The article's common measurement definition is 32 consecutive 128-bit HW
values from 4096 output bits per fixed-key IV pair. The six-cipher and Salsa20
cohorts use the same estimator but have separate planned-test families. The
matched-nonce phase intervention, 64-mask study, Grain/Trivium follow-ups,
and A5/1 frame screen each have their own protocol and inference limits.

## Cohorts and data

| Cohort | Keys | Main files and inference |
| --- | --- | --- |
| Six-cipher ordinary IV/nonce | 80 per cipher | `data/unified_six_results/`: six raw HW arrays, per-key/summary CSVs, six standard and three fresh-key planned endpoints. |
| Salsa20 transfer | 80 new keys | `data/salsa20_transfer_results/`: one raw array, phase rows, and a separate three-test family. |
| Matched-nonce phase rotation | 80 paired key indices | `data/matched_nonce_phase_results/`: two raw HW arrays, 128 paired rotation schedules per cell, and two planned alignment tests. |
| Same-stream comparison | Same matched-nonce keys | `data/same_data_benchmark_results/`: bitwise counts and direct/spectral scores on identical output streams; descriptive. |
| Full-mask and locality follow-up | 80 fresh ARX keys plus 80 Grain/Trivium keys | `data/literature_mask_followup/`: all 64 nonce bits, 32-bit output-word HW, Grain IV positions, Trivium subcubes; two planned ARX tests, one Grain validation, and a 12-cell Trivium pilot. |
| A5/1 frame screen and validation | 80 + 80 separate keys | `data/a51_frame_followup/`: raw 114-bit frame XORs, corrected 44-cell standard-depth search, and independent zero-clock gradient validation. |
| Earlier exploratory mask scan | Earlier keys | `analysis/mask_scan_results/`: retrospective per-mask profiles and descriptive comparisons. |

The raw experiment `.npz` files contain `observed`/`actual` and matched
`control`/`oracle` arrays plus cohort indices. The six-cipher and Salsa20
common arrays have axes
key × configuration × mask family × 16 IV pairs × 32 output segments. The
full-mask ARX array retains key × cipher × rounds × 64 nonce bits × four
base nonces × eight output blocks × 16 output words. The A5/1 screen stores
key × warm-up depth × 22 frame masks × four bases × 15 packed bytes; only the
first 114 bits are used. The full-mask per-mask estimator averages four
trajectories and is numerically distinct from the common 16-pair estimator.

The data manifests record cohort ranges, fixed protocols, raw-array hashes,
and planned-test families. Whole keys, not individual masks or output blocks,
are the uncertainty unit. Pointwise intervals are not simultaneous bands.

## Reading the source code

```text
fixed key index + protocol -> cipher/control streams -> paired-IV XORs
-> 128-bit Hamming weights -> per-key spectral/direct scores
-> whole-key intervals and corrected tests -> tables -> figure -> article
```

Start with these functions; their docstrings explain inputs and outputs:

| Function | What it does |
| --- | --- |
| `unified_six_cipher_iv_study._pairs_by_scenario` | Builds the shared IV-pair graph and rejects collisions. |
| `unified_six_cipher_iv_study._oracle_stream` | Assigns one SHAKE256 control stream to each IV vertex, preserving reuse across masks. |
| `unified_six_cipher_iv_study._one_key` | Measures all settings and masks for one independent cipher key. |
| `unified_six_cipher_iv_study._attribution` | Splits an `H_MP` difference into exact symmetric DC and AC contributions. |
| `salsa20_transfer_study._one_key` | Repeats the common estimator for the separate Salsa20 key cohort. |
| `matched_nonce_phase_study._rotated`, `_measure` | Rotates positions inside 512-bit blocks and compares spectra while preserving DC share. |
| `same_data_diagnostic_benchmark._scores` | Compares spectral entropy with direct HW, avalanche, lag-four, and phase scores on the same streams. |
| `literature_mask_followup._arx_one`, `_trivium_one`, `_grain_one` | Generate the independent nonce-mask and IV-locality raw arrays. |
| `analyze_literature_mask_followup._arx`, `_trivium`, `_grain` | Rebuild the corrected planned tests and descriptive profiles. |
| `a51_frame_followup._one`, `analyze_a51_frame_followup._metrics` | Generate frame XORs and measure 114-bit frame responses. |

The common `_key_material` helper lives in `publication_study.py`; the
`_mask_sets`, `_metrics`, and `_block_hamming_weights` helpers live in
`standard_iv_validation.py`. The main cipher cores are in
`extension_stream_cores.py` and `src/spectral_crypto_analyzer/primitives.py`.
These two helper modules and the primitive library also contain historical
experiments outside this article. The published vector checks cover Grain-128,
Trivium, MICKEY 2.0, HC-128, Rabbit, ChaCha20, Salsa20, and A5/1, including
independent reference translations and the ChaCha nonce-layout mapping.

`H_MP` is full-spectrum entropy in bits. In the 32-segment main study,
`H_noDC` is normalized after DC removal. The separate 19-sample A5/1 frame
analogue has another scale. DC/AC attribution returns contributions in bits
to an `H_MP` contrast; it does not convert normalized `H_noDC` to bits.

## Run individual analyses

Set imports once in a shell started from this folder:

```bash
export PYTHONPATH="$PWD/src:$PWD/experiments/stream_rounds_study"
```

The following commands inspect archived results without replacing raw data:

```bash
python3 run.py vectors
python3 run.py audits
python3 verify_package.py
```

To regenerate processed tables from archived raw arrays, run:

```bash
python3 experiments/stream_rounds_study/analyze_literature_mask_followup.py
python3 experiments/stream_rounds_study/analyze_a51_frame_followup.py
python3 experiments/stream_rounds_study/analyze_mask_profiles.py
```

These analysis commands write their CSV/JSON outputs in the corresponding
`doc_stream_ciphers/data/` or `analysis/` directory. Their random resampling
seeds are fixed in source. After an intentional rebuild, refresh the folder
manifest with `python3 verify_package.py --write`.

To regenerate the **raw experiments**, use the commands below in the listed
order. They overwrite archived outputs and may require substantial CPU time
and memory; the included raw arrays already support all article results.

```bash
python3 experiments/stream_rounds_study/unified_six_cipher_iv_study.py
python3 experiments/stream_rounds_study/salsa20_transfer_study.py
python3 experiments/stream_rounds_study/matched_nonce_phase_study.py
python3 experiments/stream_rounds_study/same_data_diagnostic_benchmark.py
python3 experiments/stream_rounds_study/literature_mask_followup.py
python3 experiments/stream_rounds_study/analyze_literature_mask_followup.py
python3 experiments/stream_rounds_study/a51_frame_followup.py
python3 experiments/stream_rounds_study/analyze_a51_frame_followup.py
python3 experiments/stream_rounds_study/a51_loading_validation.py
```

The mask and A5/1 generators support quick two-key trials that write to `/tmp`:

```bash
python3 experiments/stream_rounds_study/literature_mask_followup.py --section grain --smoke --workers 2
python3 experiments/stream_rounds_study/a51_frame_followup.py --smoke --workers 2
```

These trials check execution, not the article's statistical results. For the
figure alone, run `python3 doc_stream_ciphers/make_integrated_mask_figure.py`.
For the paper alone, run `cd doc_stream_ciphers && latexmk -pdf main.tex`.

## Submission and integrity

`python3 run.py package` creates a compact MDPI submission ZIP and a separate
reviewer data/code ZIP under `doc_stream_ciphers/`, verifies their contents,
and refreshes `PACKAGE_MANIFEST.json`. The reviewer ZIP contains protocols,
raw arrays, code, tests, and checksums. The submission ZIP contains the
manuscript source, compiled PDF, bibliography, MDPI template, and article
figure. Both are convenience outputs; this folder is the readable source.

This v0.13.1 package consolidates the source guidance into this README and
provides simpler checks. The study calculations are unchanged; protocol
paths now use `.txt` without changing their bytes. The data manifests record
raw-array and protocol hashes, and `PACKAGE_MANIFEST.json` records the
current release files.

Before public submission, the author should verify the title, affiliation,
funding, declarations, figures, citations, and page order in `main.pdf`;
choose a public code/data license; deposit the reviewer ZIP with the draft
metadata in `doc_stream_ciphers/DEPOSIT_METADATA_DRAFT.json`; then insert the
assigned DOI in `main.tex` and rebuild the PDF and ZIPs. The compact
submission ZIP is the file to upload to *Entropy*; the reviewer ZIP is the
data/code record for Zenodo. No DOI or license has been inserted on the
author's behalf.
