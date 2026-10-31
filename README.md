# IV-Diffusion Diagnostics: Electronics article and reproducibility package

This repository contains **Block-Position Structure in Reduced ChaCha20 and
Salsa20: Experimental Diagnostics of IV Diffusion**, prepared for MDPI
*Electronics*, together with its data and code. Version **0.20.0** presents one
self-contained 11-page article, including all 40 references, in
`doc_stream_ciphers/main.tex` and `main.pdf`.
There is no separate supplementary manuscript in this release.

The working `main.tex` and `main.pdf` also include the 31 October 2026 ARS
corrections to Table 2's sign-flip calibration and the percentile-bootstrap
descriptions. The archived v0.20.0 ZIPs precede these reporting clarifications;
see the [revision record](reviews/electronics_v020_revision_r1w1_r1w2_20261031/REVISION_LOG.md).

The article connects the round function, feed-forward, and measured nonce
response in reduced ChaCha20 and Salsa20. It combines conditional algebra,
paired interventions, direct and spectral diagnostics, and independent key
cohorts. The recurring block-position structure, Salsa20 nonce-word asymmetry,
rotation and resolution controls, conditional word-7 result, frozen spectrum
models, and single-round transition experiments provide complementary evidence.
The results do not establish detector superiority, a full-round weakness, or
attack advantage.

This is a targeted revision of the single-article v0.19.0 draft after an
advisory review. It distinguishes the unfinalized word-7 affinity transition
from the standard-output spectrum, clarifies sign-flip assumptions and spectral
averaging, and shows observed and frozen-model mean AC spectra. The new figure
uses retained observations and predictions; no cipher cohorts or simulations
are regenerated. Previous raw data, fixed protocols, numerical results,
scientific code and the bibliography are unchanged.
The research archive retains the detailed results from every completed cohort,
including the wider cipher studies. Public deposition is pending; no DOI or
public data/code license has been assigned.

## Start here

For a checksum-only check, run `python3 verify_package.py` from this folder.
For the Python analyses, use Python 3.10 or newer and install the dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

| Command | Purpose |
| --- | --- |
| `python3 verify_package.py` | Verify file sizes and SHA-256 digests without recomputing scientific results. |
| `.venv/bin/python run.py vectors` | Check published cipher vectors and implementation invariants. |
| `.venv/bin/python run.py audits` | Audit archived results, including the full independent spectral-model Monte Carlo replay. |
| `.venv/bin/python run.py verify` | Run vectors and scientific audits, then verify the package manifest. |
| `.venv/bin/python run.py build` | Compile only `doc_stream_ciphers/main.pdf`, using the included figure PDFs. |
| `.venv/bin/python run.py package` | Build and verify the current submission and research ZIPs, then refresh the folder manifest. |

The scientific audits are read-only by default; the full Monte Carlo replay can
take several minutes. They do not regenerate the experimental key cohorts.
The PDF build requires `latexmk`, `pdflatex`, and `bibtex`. It does not regenerate
figures or compile a supplement. `run.py` supplies local module paths and a
temporary Matplotlib cache. Generation manifests record the original Python
and NumPy versions; the release manifest records the packaging environment.

## Current article and research record

| Path | Contents |
| --- | --- |
| `doc_stream_ciphers/main.tex`, `main.pdf` | The single article source and compiled PDF. |
| `doc_stream_ciphers/related_work_comparison.tex`, `arx_mechanism_compact.tex` | The article's two source includes. |
| `doc_stream_ciphers/publication_unified_mask_followup.pdf`, `publication_reviewed_spectrum.pdf` | The article's two figures. |
| `doc_stream_ciphers/biblio.bib`, `Definitions/` | Preserved reference database and MDPI template. |
| `doc_stream_ciphers/data/`, `analysis/mask_scan_results/` | Raw arrays, per-key values, summaries, fixed tests, checkpoints, and provenance. |
| `doc_stream_ciphers/*PROTOCOL.txt`, `SAME_DATA_DIAGNOSTIC_BENCHMARK.txt` | Original fixed study designs and same-stream comparison plan. |
| `experiments/stream_rounds_study/`, `src/spectral_crypto_analyzer/` | Scientific analyses and cipher implementations. |
| `tests/`, `tools/` | Published vectors, invariants, and independent audits. |
| `doc_stream_ciphers/COVER_LETTER.md`, `REVIEW_RESPONSE_V020.md` | Draft submission letter and response to the advisory review for v0.20.0. |
| `doc_stream_ciphers/make_reviewed_spectrum_figure.py`, `analysis/reviewed_spectrum_figure_manifest.json` | New spectrum figure generator and its input/output provenance. |
| `doc_stream_ciphers/arx_affine_corollary.tex`, `arx_affine_proof.tex` | Preserved documentation inputs whose exact hashes are checked by the existing corollary audit; retained in the research archive. |

The earlier figures `publication_feedforward_derivatives.pdf` and
`publication_mechanistic_extensions.pdf`, and all previous figure-generation
scripts, remain in the research archive for reproducibility. The current
submission uses only the two figures listed above. `SINGLE_ARTICLE_REVISION.md`
records the historical v0.19.0 condensation; `REVIEW_RESPONSE_V020.md` records
the current revision and its validation status. The advisory review did not
complete the formal ARS panel validation. Exact priority relative to the
closest cited two-round criteria remains unresolved without access to their
full source passages; the revision does not add an unverified priority claim.

## Scientific data retained

All paths in this table are under `doc_stream_ciphers/`.

| Study | Data and inference scope |
| --- | --- |
| Ordinary IV/nonce comparison | `data/unified_six_results/` and `data/salsa20_transfer_results/`: seven cipher cohorts, a common 4096-bit estimator, and separately fixed test families. |
| Matched-nonce rotation and direct diagnostics | `data/matched_nonce_phase_results/` and `data/same_data_benchmark_results/`: 80 paired key indices, paired rotations, and direct/spectral scores on identical streams. |
| All-mask and wider-cipher follow-ups | `data/literature_mask_followup/`, `data/a51_frame_followup/`, and `analysis/mask_scan_results/`: independent ARX, Grain, Trivium and A5/1 results, plus descriptive earlier mask profiles. |
| Mechanism and resolution | `data/arx_mechanism_results/`, `data/arx_resolution_results/`, and `data/arx_resolution_validation/`: operation checks, descriptive reanalysis, and the completed fixed cohort 840–919 with five jointly corrected endpoints. |
| Feed-forward and second derivatives | `data/arx_feedforward_results/`: cohort 1000–1079, three paired finalizations, 64 singleton masks, 38 fixed second-order pairs, and four jointly corrected endpoints. |
| Conditional affine corollary | `data/arx_affine_corollary/`: exact rank/mean-response checks using preserved data; no new cipher cohort or significance tests. |
| Frozen spectrum models | `data/arx_spectral_prediction/`: training cohort 840–919, 4096 Monte Carlo key pairs per model, fixed predictions, and evaluation cohort 1200–1279; conditional intervals and Monte Carlo errors are reported separately. |
| Single-round transition | `data/arx_round_transition/`: cohort 1400–1479 at two, three and four genuine single rounds, named operation witnesses, and two jointly corrected endpoints. |

Whole keys are the uncertainty unit. Planned tests, descriptive profiles and
exact structural checks have different inferential roles. The finite averaged
power entropy is not keystream Shannon entropy. The main 32-segment estimator,
per-mask four-trajectory estimator, and 19-sample A5/1 analogue have different
scales; DC/AC attribution is expressed in bits of the corresponding
full-spectrum entropy contrast.

The newer data directories have their own README files explaining axes,
outputs, and commands. To run an individual archived-data audit, set imports:

```bash
export PYTHONPATH="$PWD/src:$PWD/experiments/stream_rounds_study"
python3 tools/audit_arx_extensions.py
python3 tools/audit_arx_feedforward.py
python3 experiments/stream_rounds_study/arx_affine_corollary.py
python3 tools/audit_arx_spectral_prediction.py
python3 tools/audit_arx_round_transition.py
```

Raw generators, processed-table rebuilds and figure generators are preserved
for intentional reproduction. They write scientific outputs and are not part
of the single-article build. The included checkpoints support resumption of
fixed cohorts; dedicated smoke modes use separate indices under `/tmp`.

## Submission and version history

Build the article before packaging. The following packages are prepared for
reviewers; their existence is not a submission or public-deposition record:

- `doc_stream_ciphers/electronics_iv_diffusion_submission_v0.20.0.zip`:
  article source and PDF, its two includes and two figures, bibliography,
  MDPI template, and draft cover letter.
- `doc_stream_ciphers/iv_diffusion_research_review_v0.20.0.zip`:
  article plus all retained scientific data, protocols, code, tests, audits,
  checkpoints and provenance documentation.
- `doc_stream_ciphers/iv_diffusion_research_review_v0.20.0_manifest.json`:
  the research archive's file inventory and archive checksum.

Each ZIP builder checks member names, CRC and SHA-256 digests. The extracted
research archive uses its included `SHA256SUMS.json` when running
`verify_package.py`; the working folder uses `PACKAGE_MANIFEST.json`.

Historical archives remain unchanged. In particular, v0.18.0 preserves the
previous 20-page article and 7-page supplement, including the former manuscript
inputs. The v0.19.0 archives preserve the first 11-page, single-article version.
Earlier v0.13.1–v0.17.0 packages also remain historical records. They are not
the current submission package.

Before public submission, review `main.pdf`, author details and declarations;
choose a public code/data license and deposit the research archive using
`doc_stream_ciphers/DEPOSIT_METADATA_DRAFT.json`. Insert the actual assigned DOI
only after deposition, then rebuild the article and archives. The metadata
records the final article pagination after its build has been checked.
