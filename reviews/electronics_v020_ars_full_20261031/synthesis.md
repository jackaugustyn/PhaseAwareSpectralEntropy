# Editorial Decision Letter

**Manuscript:** Block-Position Structure in Reduced ChaCha20 and Salsa20: Experimental Diagnostics of IV Diffusion  
**Review:** electronics-v020-ars-full-20261031; reviewer/reviewer_full/v2; 31 October 2026  
**Decision:** Minor Revision  
**Calibration:** `NOT_CALIBRATED`

Dear Author,

The five completed role-separated cards support a focused diagnostic contribution, with six localized Minor findings. The configured contract mechanically yields **Minor Revision**. The required changes concern inferential reporting and durable access; the remaining suggestions improve presentation and accessibility. None of the cards requires a replacement study, additional simulation, or a supplementary manuscript.

`criteria_binding_unavailable` is disclosed by all five cards. This is an unbound assessment: D6 evaluates the contribution as developed in the manuscript, and does not certify alignment with current Electronics criteria. Full cited-source texts were unavailable; literature completeness, source-content accuracy, and novelty priority have not been independently confirmed. These are scope limits, not additional findings.

## Contract audit

Only eligible assessed seats enter the matrix; every other score is `not_assessed` and excluded. Confidence supplies no weight.

| Dimension | Priority | Eligible assessed values | Audit verdict |
|---|---|---|---|
| D1 methodology_rigor | mandatory | R1: warn | warn |
| D2 domain_accuracy | mandatory | R2: pass | pass |
| D3 argumentative_coherence | mandatory | R1: pass; DA: pass | pass |
| D4 cross_disciplinary_relevance | high | R3: warn | warn |
| D5 writing_and_structure | normal | EIC: warn | warn |
| D6 venue_fit_and_contribution | mandatory | EIC: pass | pass |

| Condition | Fired | Contract basis |
|---|---|---|
| F1 | false | No eligible mandatory fatal block. |
| F2 | false | No eligible mandatory block. |
| F3 | false | Only D1 among mandatory dimensions reaches warn or worse; its single-owner majority is satisfied, but two qualifying dimensions are required. D3 has two assessed pass seats. |
| F4 | false | D4 is warn, not block. |
| F5 | true | D1, D4, and D5 each have an eligible warn score. |
| F0 | false | Not every dimension is pass. |

F5 is the only fired condition (severity 40); its action is applied unchanged.

dimension_verdicts: [D1=warn, D2=pass, D3=pass, D4=warn, D5=warn, D6=pass]
fired_conditions: [F5]
da_critical_adjudications: []
editorial_decision=minor_revision

## Consensus, arbitration, and review limits

**[CONSENSUS-4: contribution scope only]** EIC S1-S2, R1 S3-S5, R2 S1/S6, and R3 S2-S3 agree that the conditional identities, paired interventions, and measurement controls support local diagnostic conclusions with explicit limits. This is the meaning of the package's global consensus label; it does not claim four-reviewer endorsement of any requested change.

Every weakness remains **SINGLE-VERIFIER**: EIC W1-W2, R1 W1-W3, and R3 W1. Other reviewers' silence supplies neither agreement nor opposition. No incompatible remedy or severity was identified. The DA's acceptance of the Methods calibration caveat does not contradict R1 W1, which concerns the standalone Table 2 caption. Likewise, the positive appraisal of the conditional proof does not contradict R3's request for an operational explanation. There is no unresolved split to arbitrate and no DA Critical ID to adjudicate.

The DA's five anchored challenges survived on the inspected evidence. R2 and DA explicitly supply coverage receipts for their empty weakness lists; their scoped passes do not certify unexamined dimensions. R1's arithmetic receipts record non-computability under the bounded procedures: the sign-flip probability is not a conventional parametric tail calculation, and two granularity checks lack a declared rounding convention. They establish no arithmetic mismatch and create no additional revision item. The scientific code and saved results received bounded read-only checks; no full simulation rerun or comprehensive implementation audit was performed.

## Blocking issues (immutable source order)

| Transport ref | Publication requirement | Source and typed evidence | Resolving item |
|---|---|---|---|
| R1 | State calibration assumptions in the central table. | R1 W1; table: Table 2, Holm p heading and caption | REV-R1-W1 |
| R2 | Identify the bootstrap interval construction. | R1 W2; absence: Methods §§3.3-3.4, checked Methods/Table 2/figure captions | REV-R1-W2 |
| R3 | Provide durable access to the specific existing package before publication. | R1 W3; text: Data Availability Statement, “The package has not been publicly deposited and has no public DOI.” | REV-R1-W3 |

## Revision roadmap

The following table stays in immutable source order. Transport references are identifiers, not a work ranking. All six items retain their source **Minor** severity and self-reported confidence. Obligation is assigned separately: R1 W1-W3 are required for interpretable reporting and reproducible access; the EIC and R3 items are suggested improvements because their cards find the contribution and central argument assessable.

| Item / transport | Source sub-claim | Severity; confidence and basis | Typed evidence anchor | Obligation | Cost scope; bounded consequence |
|---|---|---|---|---|---|
| REV-EIC-W1 / S1: The six-setting model comparison is overly compressed | SC-EIC-W1 | Minor; 5/5 — direct inspection of the result paragraph and Figure 2. | text: Section 4.4, final paragraph, "Both models predict all six entropy-gap signs." and "However, M0 is closer to all three ChaCha20 entropy gaps; M1 is closer to all three Salsa20 gaps." | should_fix | section: Section 4.4, final model-comparison paragraph; reader_traceability_reduced → section: Section 4.4, six-setting model comparison |
| REV-EIC-W2 / S2: Ancillary study details interrupt the focused discussion | SC-EIC-W2 | Minor; 4/5 — editorial assessment of the discussion's sequence and information density. | text: Section 5, ancillary-study paragraphs, "Ancillary studies delimit the diagnostic." and "A5/1 used 80 keys, four frames, 22 singleton masks and 114 output bits." | should_fix | section: Section 5, three ancillary-study paragraphs; reader_traceability_reduced → section: Scope and Discussion, ancillary studies |
| REV-R1-W1 / R1: The main endpoint table should carry the calibration qualification | SC-R1-W1 | Minor; 5/5 — direct comparison of the table with the stated random-sign null assumptions. | table: Table 2, Planned scan, feed-forward, and round-transition endpoints, Holm p column and caption. | must_fix | sentence: Table 2, calibration column heading and caption; interpretive_ambiguity_remains → table: Table 2, Holm calibration heading and caption |
| REV-R1-W2 / R2: The bootstrap interval construction is omitted from the article | SC-R1-W2 | Minor; 5/5 — the manuscript names the resampling unit and counts while the inspected code supplies the omitted interval rule. | absence: Materials and Methods, Paired Interventions and Inference and Frozen Empirical Spectrum Models | must_fix | sentence: Sections 3.3 and 3.4, bootstrap interval descriptions; method_reproducibility_unresolved → section: Materials and Methods, bootstrap interval construction |
| REV-R1-W3 / R3: Durable access to the existing research package remains unresolved | SC-R1-W3 | Minor; 5/5 — explicit availability statement and successful inspection of the supplied local scientific files. | text: Data Availability Statement; “The package has not been publicly deposited and has no public DOI.” | must_fix | other: Existing version 0.20.0 code/data package and Data Availability Statement; method_reproducibility_unresolved → dataset: iv_diffusion_research_review_v0.20.0.zip |
| REV-R3-W1 / S3: Add a plain-language interpretation of conditional affinity and rank | SC-R3-W1 | Minor; 4/5 — interpretation of finite-field linear maps for mathematically trained adjacent-field readers. | equation: Section 4.1, Equations (7)–(8) and their accompanying explanation, manuscript p. 6. | should_fix | sentence: Section 4.1, conditional rank explanation; interpretive_ambiguity_remains → section: Section 4.1, conditional affinity and rank |

### Required Item Details

**R1: The main endpoint table should carry the calibration qualification**

- **Source**: R1 W1 / REV-R1-W1; proposed block(s): B0043.
- **Requirement**: Relabel the Holm p column as Holm-adjusted sign-flip calibration and add a short caption qualification referring to null sign-invariance and its assumption-dependent interpretation. Preserve the existing endpoints and values. Editorial obligation basis: Required because the central table must communicate the assumptions needed to interpret its inferential values when read on its own.
- **Acceptance criteria**: Table 2 identifies the values as Holm-adjusted sign-flip calibrations and explicitly states their dependence on null sign-invariance, consistently with Methods.

**R2: The bootstrap interval construction is omitted from the article**

- **Source**: R1 W2 / REV-R1-W2; proposed block(s): B0024, B0030.
- **Requirement**: State that the bootstrap limits use the 0.025 and 0.975 quantiles (the 2.5th and 97.5th percentiles) of whole-key resampled means, including spectral-distance intervals. Retain the prediction intervals' conditioning on the fixed fit and Monte Carlo estimate. Editorial obligation basis: Required so the article identifies the interval construction used by the existing analysis, without requiring readers to infer it from code.
- **Acceptance criteria**: Methods explicitly identifies the 95% percentile-bootstrap limits as the 0.025 and 0.975 quantiles (the 2.5th and 97.5th percentiles) of the bootstrap distributions for the reported whole-key means and spectral distances, while retaining the existing conditional-uncertainty qualification.

**R3: Durable access to the existing research package remains unresolved**

- **Source**: R1 W3 / REV-R1-W3; proposed block(s): B0062.
- **Requirement**: Before publication, deposit the existing versioned package at a stable public location or state a durable access arrangement and its terms; update only the dataavailability declaration within B0062. Preserve the version, hashes, and reproduction-command linkage. A DOI is an option, not a verified venue requirement. Editorial obligation basis: Required before publication because review-stage local access does not supply later readers with a durable route to the research package.
- **Acceptance criteria**: The Data Availability Statement supplies a durable route and any access terms for the specific versioned code/data package, retaining its version and integrity/reproduction references; an author assertion of a deposit alone is not evidence of access.

### Suggested item details

- **S1 / REV-EIC-W1**: Replace part of the numerical paragraph with a compact cipher-by-width comparison or clearly labelled triples of the existing observed/M0/M1 entropy gaps and spectrum errors. Preserve the reported model tradeoff; use existing results without new simulation or testing. Editorial obligation basis: Suggested for inspectability of the six-setting comparison; the source finding does not undermine the stated contribution. Proposed block(s): B0053.
- **S2 / REV-EIC-W2**: Condense the three ancillary-study paragraphs around initialization transients versus recurring block structure and the fact that quiet diagnostics do not establish security; retain the minimum numerical evidence and citations for those lessons. Editorial obligation basis: Suggested to improve the discussion's focus and information density; no new experiment or supplementary manuscript is required. Proposed block(s): B0056, B0057, B0058.
- **S3 / REV-R3-W1**: Insert a brief explanation after the rank/mean equations: with the other inputs fixed, XOR-affinity is a constant output offset plus a binary-linear combination, rank counts independent output-change directions generated by input bits, and mean changed-bit count measures a different property. Preserve the equations, proof, and conditional scope. Editorial obligation basis: Suggested to make the central rank-versus-mean example accessible across disciplines; the proof and central argument remain assessable in the source review. Proposed block(s): B0037.

The machine core is [revision_roadmap.json](revision_roadmap.json), with six items (3 must_fix, 3 should_fix, 0 consider). Its exact review base is [artifacts/review_base.md](artifacts/review_base.md), SHA-256 `9cf702dd74ac412e5d2bb8fc88999960fae5087b05e072e3172e690f3bbd02e6`; the [block manifest](artifacts/block_manifest.json) SHA-256 is `385998f2360012cf9d212f5ed82f89cccb3fb6e74fd4cf8fb7129fde4321ddc7`. [base_binding.json](artifacts/base_binding.json) binds this marked review copy to the complete expanded LaTeX. The targets are proposals, not manuscript edit authority. In particular, B0062 contains multiple declarations; the proposed action concerns only its Data Availability Statement. No author triage, claim-strength permission, collateral authorization, or work order is inferred.

Respond to every item using the revision-response format, identifying the adopted change or the reason for declining it and its location. The separate author-adjudication step records those choices; an unresolved required item remains visible. No journal-supplied deadline was available.

## Review Panel Provenance (#540/#740)

Typed artifact: [artifacts/panel_provenance.json](artifacts/panel_provenance.json); panel ID `electronics-v020-ars-full-20261031`. The Schema 6 package copies [panel_carrier.json](artifacts/panel_carrier.json) unchanged.

- Artifact SHA-256: `7520da8e593b7ee946bf59974d9f29dc38b14d0e986c2363e659e46fe7342872`
- Normalized manifest SHA-256: `47d987ff83c8174c554b98cd553cb213da95dfe330d3c0568bbbb9a818be48b6`
- Execution topology SHA-256: `6f0fb039379f2b635cf4b3036c3e5ec02fdd1b2235c546e8b27cae4ffac9b5ac`
- Fresh-context scope: `within_panel_attempt_only`; this does not compare retries, earlier attempts, or prior rounds.

| Seat | Role | Actor | Context | Peer outputs visible | Model family | Provider | Human reviewer |
|---|---|---|---|---|---|---|---|
| EIC | eic | model | `/root/ars020_eic` | unknown | unknown | unknown | none |
| R1 | methodology | model | `/root/ars020_methodology` | unknown | unknown | unknown | none |
| R2 | domain | model | `/root/ars020_domain` | unknown | unknown | unknown | none |
| R3 | perspective | model | `/root/ars020_perspective` | unknown | unknown | unknown | none |
| DA | da | model | `/root/ars020_da` | unknown | unknown | unknown | none |

| Provenance axis | Status |
|---|---|
| role_separated | true |
| fresh_context | true |
| blind_to_peer_outputs | unknown |
| model_family_distinct | unknown |
| provider_distinct | unknown |
| human_distinct | false |

Native dispatch used five distinct seat contexts. Peer reports were not supplied before commitment, but shared-filesystem visibility was not instrumented, so blinding remains unknown. The requested model configuration is not served-model/provider attestation. There are no accountable human panel members, and no external cross-model decision check was configured or executed. Binary independence is not computed from role labels or these axes.

Model-family provenance is incomplete; cross-family separation is unknown, so correlated-error risk cannot be ruled out.

Calibration remains NOT_CALIBRATED for the package and every seat; the confidence labels are scope metadata, not measured accuracy or decision weights. The complete transported cards, categorical criterion judgements, typed anchors, and coverage receipts are in [review_report.json](review_report.json).

Sincerely,  
Editorial Synthesizer, ARS reviewer_full

## Attachment: Suggested-Reference Check (advisory, #1001)

Suggested-reference check did not run: no programmatic bibliographic check was requested for this run.

## Attachment: Reviewer Claim Check (advisory, #1002)

Reviewer claim check did not run: this host cannot enforce the required worker isolation without tools, browsing, file access, or inherited context.

## Attachment: Acronym Check (advisory, #849)

### Acronym check (advisory; no reply needed)
Coverage: body (partial)
Not in this input: English abstract, Chinese abstract.
Not checked:
- Body, line 57: XOR (the initials before its parentheses do not spell it)
- Body, line 171: MSB (the initials before its parentheses do not spell it)
- Body, line 173: LSB (the initials before its parentheses do not spell it)

| Scope | Line | Rule | Acronym | Uses |
|---|---|---|---|---|
| Body | 4 | Defined after first use | IV | 8 |
| Body | 57 | Not defined | OR | 1 |
| Body | 59 | Not defined | ARX | 6 |
| Body | 83 | Not defined | BY | 1 |
| Body | 83 | Not defined | CC | 1 |
| Body | 119 | Not defined | NIST | 3 |
| Body | 184 | Not defined | ZK | 2 |
| Body | 208 | Not defined | HMP | 6 |
| Body | 215 | Not defined | AC | 11 |
| Body | 215 | Not defined | DC | 3 |
| Body | 219 | Not defined | HnoDC | 5 |
| Body | 237 | Not defined | PB | 1 |
| Body | 237 | Not defined | PT | 1 |
| Body | 815 | Not defined | HC | 1 |
| Body | 815 | Not defined | MICKEY | 1 |
| Body | 903 | Not defined | README | 1 |
| Body | 915 | Not defined | IETF | 1 |
| Body | 915 | Not defined | RFC | 2 |
| Body | 937 | Not defined | ID | 1 |
| Body | 937 | Not defined | SASC | 1 |
| Body | 945 | Not defined | DES | 1 |
| Body | 947 | Not defined | CRYPTO | 3 |
| Body | 951 | Not defined | FSE | 2 |
| Body | 955 | Not defined | IACR | 2 |
| Body | 975 | Not defined | IEICE | 1 |
| Body | 979 | Not defined | IEEE | 5 |
| Body | 1029 | Not defined | SP | 1 |
| Body | 1035 | Not defined | EEG | 1 |
| Body | 1061 | Not defined | BLAKE2 | 1 |
| Body | 1065 | Not defined | SHA | 1 |
| Body | 1067 | Not defined | FIPS | 1 |
| Body | 1067 | Not defined | PUB | 1 |
| Body | 1087 | Not defined | KATAN | 1 |
| Body | 1089 | Not defined | SAC | 1 |
| Body | 1093 | Not defined | PC | 1 |
