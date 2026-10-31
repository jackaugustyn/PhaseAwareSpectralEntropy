# Targeted manuscript revision — 31 October 2026

The author requested points 1 and 2 from the preceding review summary: REV-R1-W1 and REV-R1-W2. Both have been implemented in the working `doc_stream_ciphers/main.tex` and compiled `main.pdf`.

| Review item | Implemented response | Location |
|---|---|---|
| REV-R1-W1 | Table 2 now labels its inference column “Holm-adjusted sign-flip p.” The caption states that these are assumption-dependent calibrations requiring null sign-invariance and retains the finite-simulation-floor qualification. | main.tex:143 and main.tex:147; PDF p. 7 |
| REV-R1-W2 | Methods explicitly identifies pointwise 95% percentile-bootstrap intervals as the 0.025 and 0.975 quantiles of resampled whole-key means, retaining the existing 5000/10,000 resample counts. The spectrum-model section covers resampled means or recomputed distances, conditional on the fixed fit and Monte Carlo estimate. | main.tex:105 and main.tex:123; PDF pp. 4–5 |

The descriptions were compared with the existing implementation. In particular, spectral-distance intervals recompute the distance from each resampled mean spectrum to the fixed model mean; they do not include model refitting uncertainty. See `validation/code_evidence.json`.

The revision was applied through three authorized block replacements. The deterministic apply report preserves 101 of 104 review-copy blocks byte-for-byte. Its output was projected exactly onto the original LaTeX source, preserving the source includes. Table data rows and citation commands are unchanged. The abstract was not regenerated and remains consistent with the reporting clarifications. The before/after source and exact diff are retained here.

Validation: `python3 run.py build` succeeded; the final LaTeX log has no warnings, overfull boxes or underfull boxes. PDF preflight passed with 11 pages. Pages 4, 5 and 7 were visually inspected: the methods text and two-line table header render correctly, without clipping. The article still contains 40 references and no supplementary manuscript.

The acronym check retains partial coverage and the same 31 advisory findings as before the changes. Its output is [acronyms_after.txt](validation/acronyms_after.txt); it generated no extra revision items. No experiments were rerun. These are local implementation and rendering checks, not a new reviewer-panel decision or a Stage 4.5 integrity certification.

The original six-item review roadmap and all earlier review artifacts remain historical records. The two-item `roadmap.json` here is an explicitly documented selection for this round; the other four review items remain unselected and unresolved, with no author rejection inferred. Existing release ZIPs retain their original contents; the revised article is the working `main.tex`/`main.pdf` linked from the repository README.
