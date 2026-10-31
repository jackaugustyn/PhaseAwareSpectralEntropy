# Validation record

Review mode: `reviewer_full`; manuscript v0.20.0; contract `reviewer/reviewer_full/v2`.

| Check | Result | Evidence |
|---|---|---|
| PDF preflight | PASS; 11 pages | artifacts/pdf_preflight.json |
| Contract and prompt synchronization | PASS; advisory single-judge mandatory gates D1/D2/D6 | validation/checkpoint.json |
| Phase 1 plans | 5/5 PASS | validation/*_phase1.log |
| Phase 2 cards | 5/5 PASS | validation/*_phase2.log |
| Panel decision derivation | PASS; F5 only; Minor Revision | validation/panel_synthesis.log |
| Roadmap schema and exact base/block binding | PASS | validation/revision_roadmap.log |
| Schema 6 provenance carrier and replay | PASS | validation/schema6_provenance.log |
| Source transport and cross-artifact consistency | PASS | validation/source_fidelity.json |
| Manuscript input and committed card hashes | PASS | validation/immutability.json |
| Previously manifested project files | 954 checked; no changes or missing files | validation/preexisting_integrity.json |

The Schema 6 provenance checker validates the closed carrier, not every scientific assertion or every semantic field in the review report. The separate source-transport check compared categorical scores, finding counts, severity/confidence, typed anchors, empty-list coverage receipts, the embedded roadmap, and the exact provenance disclosure. Neither check is an independent reviewer-claim audit.

One bounded synthesis correction was made after the first automatic checks passed: the synthesis had incorrectly called the source's 0.025/0.975 quantiles “percentiles.” The final artifacts use the correct quantiles, equivalent to the 2.5th/97.5th percentiles. Attempt 1 and its diagnostic are preserved under validation/synthesis_attempt1. The final synthesis, roadmap, and provenance gates were rerun and passed. No reviewer card, score, finding severity, obligation count, or decision changed.

The six roadmap items are all Minor and SINGLE-VERIFIER: 3 must_fix and 3 should_fix. The global CONSENSUS-4 label concerns the bounded contribution only; it does not corroborate the six requested changes. No DA Critical finding exists. Reviewer confidence remains uncalibrated metadata.

Advisory attachments were appended only after the decision passed, in the required order. Suggested-reference checking did not run; the isolated reviewer-claim audit was unavailable; acronym checking ran with `partial` coverage. The exact acronym report is the decision letter's last appended section. It did not affect the decision or roadmap. See validation/attachments.json.

This run does not certify current Electronics criteria, source-backed novelty, journal acceptance, full simulation reproducibility, or independent human review. The run-local manifest binds the completed review artifacts; the project package manifest is refreshed separately after these artifacts are finalized.
