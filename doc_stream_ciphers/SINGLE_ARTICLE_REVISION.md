# Single-article revision: v0.19.0

Version 0.19.0 condenses the v0.18.0 manuscript into one self-contained article
for MDPI *Electronics*. The submission has no separate supplementary manuscript.
This is an editorial revision; it adds no experiments or numerical results.

## Current submission

The article source is `main.tex`, with two includes:

- `related_work_comparison.tex`
- `arx_mechanism_compact.tex`

Its two figures are `publication_unified_mask_followup.pdf` and
`publication_mechanistic_extensions.pdf`. The submission archive also contains
`main.pdf`, `biblio.bib`, the MDPI template and `COVER_LETTER.md`.
Unused earlier manuscript includes and `supplementary.tex`/`supplementary.pdf`
are not packaged in v0.19.0.

## Preserved scientific record

All completed experiments, raw arrays, fixed protocols, model fits, exact
witnesses, per-key tables, numerical summaries, tests and independent audits
remain in the research archive. The scientific code and its recorded hashes
are unchanged. The archive also retains all three historical figure PDFs and
their generation scripts.

`arx_affine_corollary.tex` and `arx_affine_proof.tex` remain in the research
archive because the existing corollary manifest checks their exact hashes.
They are provenance inputs for that audit, not a supplementary manuscript for
the current submission. The current article contains its own compact argument.

The historical v0.18.0 submission and research archives preserve the full
previous version, including its 20-page article, 7-page supplement and former
source includes. Earlier revision and extension status files describe those
historical stages; this note records the current packaging scope.

## Build and validation

`python3 run.py build` compiles only `main.tex` with the included figure PDFs.
It does not regenerate figures, data or analyses. `python3 run.py package`
creates the v0.19.0 archives and checks their members, CRC and SHA-256 digests.
The scientific audit commands remain available separately.

The compiled article has 11 pages including 40 references, two figures and two
tables. Its LaTeX log has no warnings or overfull/underfull boxes. A SHA-256
comparison against v0.18.0 confirmed that 863 scientific data, code, protocol,
figure, bibliography and audit-documentation files are unchanged.
The compact proof and ancillary conclusions are included in the article.
An independent clean build from exactly the 13 submission files produced an
11-page PDF with 40 references and no LaTeX or BibTeX warnings. Its extracted
text is identical to the working PDF; no supplement was supplied or required.
The release builders verify archive members, CRC and SHA-256 manifests.
Public deposition, DOI assignment and a public data/code license remain pending.
