contract_role: methodology
## Dimension Scores

### D1: methodology_rigor
score: warn
trigger: "A localized reporting omission or limited sensitivity check reduces precision or ease of reproduction while leaving the central design and inference assessable and credible."

### D2: domain_accuracy
score: not_assessed

### D3: argumentative_coherence
score: pass

### D4: cross_disciplinary_relevance
score: not_assessed

### D5: writing_and_structure
score: not_assessed

### D6: venue_fit_and_contribution
score: not_assessed

## Review Body

criteria_binding_unavailable

The central methodological argument is supported: paired construction interventions, explicit spectral estimators, conditional algebra, and evaluation on new keys address distinguishable questions. I found no defect requiring replacement of the design or substantial reanalysis. D1 is qualified by the localized reporting issues below; D3 passes because the conclusions consistently distinguish the observed diagnostics from detector superiority, equivalence, and security claims.

This assessment used the complete supplied manuscript and bounded, read-only inspection of the permitted scientific code and stored data. Checks included the planned scan, feed-forward and transition endpoints; the model sampling and analysis functions; and the corresponding scalar and spectral CSV summaries. I did not regenerate cohorts, run full simulations, independently establish the historical timing of the protocol freezes, or certify the entire implementation. The arithmetic receipts distinguish a conventional statistical recomputation from a boundary check; none reports an arithmetic mismatch.

### S1: The independent unit matches the design and resampling

**Evidence Anchor**: table: Table 1, Principal cohorts, together with the key-pair resampling specification in Materials and Methods, Paired Interventions and Inference.

Each principal analysis retains 80 key pairs as independent replicates and keeps masks, bases, blocks, and interventions within those pairs. The paper distinguishes fresh-key cohorts from repeated analysis of existing trajectories and explicitly identifies reuse of the resolution cohort for model training. The inspected analysis code resamples whole rows of key-level endpoints, preserving the relevant within-key dependencies. This avoids treating the many masks, blocks, deterministic checkpoints, or simulated pseudo-keys as additional experimental key replicates.

### S2: The measurement definitions support interpretable comparisons

**Evidence Anchor**: equation: Equations labeled eq:entropy, eq:identity, and eq:gapfundamental in Direct and Spectral Measurements.

The order of power averaging, normalization, and entropy calculation is explicit, as are changes in pooling between alignment and complete scans. The DC/AC decomposition explains why entropy is not monotonic in mean diffusion strength. Defining the fundamental fraction separately from the sum of block harmonics also makes the round-transition endpoint interpretable. The rotation control preserves the HW multiset and DC share, providing a useful intervention on the measurement while leaving the cipher unchanged.

### S3: The algebra and transition experiment support appropriately local conclusions

**Evidence Anchor**: equation: Equations labeled eq:compactfC and eq:affinecorollary, with the conditional-rank proof and Third Round: Affinity Loss with Persistent Block Structure.

The proof identifies disjoint active column supports and explains both the rank formula and the bounded mean singleton response. Its assumptions concern a fixed remaining state and one output-word map; the prose explicitly prevents extrapolation to joint affinity or full-cipher rank. The third-round experiment then checks nonzero within-word second derivatives of the unfinalized map, while the persistent block-scale observable comes from standard output. These are distinct measurements, and the conclusion preserves that distinction. As a stored-data consistency check, the 80 Salsa20 round-three, unfinalized key-level rows average to the reported raw response at the displayed precision; this does not turn 10,240 repeated evaluations into 10,240 independent keys.

### S4: The predictive comparison uses the actual nonlinear estimator and reports counterexamples to uniform improvement

**Evidence Anchor**: dataset: doc_stream_ciphers/data/arx_spectral_prediction/compact_summary.csv and spectral_errors.csv, M0/M1 rows for both ciphers at 32, 64, and 128 bits.

The model implementation samples the stated M0 marginals and M1 key/base-conditional distributions, then applies the same finite-sample estimator used for evaluation. It does not replace expected entropy by the entropy of expected power. The inspected summaries agree with the manuscript's six-cell sign agreement, smaller M1 mean-spectrum errors, and the opposing entropy-gap rankings for ChaCha20 and Salsa20. Separate Monte Carlo errors and the explicit conditioning of evaluation intervals on the fixed fit prevent simulated sample size from being presented as training-cohort precision. The manuscript also acknowledges that mean spectra can conceal mask-level errors and does not present these intervals as model-rejection tests.

### S5: The strength of the conclusions tracks the strength of the evidence

**Evidence Anchor**: text: Scope and Discussion, "no calibrated detector-power advantage was established."; Frozen Empirical Spectrum Models, "these comparisons are not model-rejection tests or calibrated prediction intervals."

The direct benchmark is identified as following the original spectral findings, rather than as a prospective power comparison. Pointwise intervals that include zero are not treated as equivalence, and small higher-round departures are not converted into a security conclusion. The feed-forward and conditional-affinity results are likewise restricted to the tested constructions and observables. These limitations leave a coherent, narrower mechanistic contribution.

### W1: The main endpoint table should carry the calibration qualification

**Severity**: Minor
**Evidence Anchor**: table: Table 2, Planned scan, feed-forward, and round-transition endpoints, Holm p column and caption.
**Confidence**: 5 — direct comparison of the table with the stated random-sign null assumptions.

The Methods correctly state that zero mean does not imply sign-invariance and that Holm adjustment is conditional on valid endpoint calibration. The central table labels its column simply as Holm p and mentions the simulation floor, but omits the assumption-dependent interpretation. A reader using the table alone could therefore mistake these values for established distribution-free tests of the stated mean-zero null. Relabel the column as a Holm-adjusted sign-flip calibration and add a short caption qualification referring to the sign-invariance assumption. This is a presentation repair: the large reported effects, whole-key intervals, deterministic identities, and explicit Methods caveat do not warrant a major methodological penalty. Stronger unconditional testing claims would require their own justification or analysis, but the present article need not make those claims.

### W2: The bootstrap interval construction is omitted from the article

**Severity**: Minor
**Evidence Anchor**: absence: Materials and Methods, Paired Interventions and Inference and Frozen Empirical Spectrum Models — expected the bootstrap interval construction; checked the complete Methods text, Table 2 caption, and both figure captions.
**Confidence**: 5 — the manuscript names the resampling unit and counts while the inspected code supplies the omitted interval rule.

The text specifies whole-key resampling and the number of draws, but does not say whether the displayed limits are percentile, basic, studentized, or bias-corrected intervals. The relevant analysis functions use the 0.025 and 0.975 quantiles of resampled key means, and the spectral-distance limits use the same percentile construction. Add percentile to the bootstrap description and retain the existing conditional-uncertainty qualification for prediction comparisons. This small addition makes the interval calculation reproducible from the article without requiring another manuscript or a rerun.

### W3: Durable access to the existing research package remains unresolved

**Severity**: Minor
**Evidence Anchor**: text: Data Availability Statement, "The package has not been publicly deposited and has no public DOI."
**Confidence**: 5 — explicit availability statement and successful inspection of the supplied local scientific files.

The named archive, version, hashes, and reproduction commands provide useful review-stage traceability. However, the article does not yet identify a durable route by which later readers can obtain that specific package. Before publication, archive the existing code and data at a stable public location, or state a durable access arrangement and its terms, and update the availability statement. A DOI is one solution rather than an independently established venue requirement. The existing code/data archive is the appropriate artifact for this step.

## Arithmetic Receipts

### AR1
procedure_id: p_from_test_statistic
evidence_anchor: table: Table 2, feed-forward endpoint ChaCha20 G_add minus G_none, mean -0.00293 and Holm p 0.108.
reported_inputs: Endpoint mean -0.00293 bits; n=80 key pairs; reported Holm p=0.108; four-test Holm family; R=100000 random-sign draws; the statistic is the absolute endpoint mean, with no conventional test-family statistic or df reported.
assumptions: The Methods specify comparison of absolute observed and sign-flipped means; no Student t, normal, F, or chi-square null distribution is assumed.
derivation: A conventional tail probability cannot be recovered from the mean and n; this result instead depends on the key-level random-sign distribution and subsequent Holm adjustment, which cannot be replaced by a t distribution with 79 df.
derived_value_or_range: No p value is derived by the bounded conventional test-statistic procedure.
comparison_rule: Do not compare an invented parametric p value with an adjusted random-sign calibration.
status: not_computable
not_computable_reason: nonstandard_p_procedure
tail_convention: two-tailed

### AR2
procedure_id: grim
evidence_anchor: text: Third Round: Affinity Loss with Persistent Block Structure, "a raw mean of 15.84033 bits at three rounds"; Paired Interventions and Inference defines the two within-word pairs, four bases, and 16 blocks.
reported_inputs: Raw mean M=15.84033 changed bits per 32-bit word, displayed to five decimal places; 80 equally weighted keys, two within-word pairs, four bases, and 16 blocks give 10240 equally weighted integer HW evaluations; independent key count remains 80.
assumptions: The stated equal averaging determines a grid of 1/10240 for the grand raw mean; dependence within keys does not alter arithmetic reachability; the manuscript does not explicitly state its decimal rounding rule.
derivation: M times 10240=162204.97920; adjacent attainable means are 162204/10240=15.840234375 and 162205/10240=15.84033203125. Under the candidate round-to-nearest rule the interval would be [15.840325,15.840335), containing the latter value, but this rule is not declared in the manuscript.
derived_value_or_range: Adjacent grid values 40551/2560 and 32441/2048; a round-to-nearest reachability check would be consistent, with no unconditional rounding-rule verdict asserted.
comparison_rule: A completed GRIM verdict requires the manuscript's rounding convention; do not promote a candidate convention to a reported assumption.
status: not_computable
not_computable_reason: rounding_rule_ambiguous

### AR3
procedure_id: grim
evidence_anchor: text: Feed-Forward: Existing Asymmetry and New Interaction, "Its raw mean HW rises to 0.72419"; Paired Interventions and Inference defines A over 31 aligned offsets, four bases, and 16 blocks.
reported_inputs: Raw add-finalized mean M=0.72419 changed bits per 32-bit word, displayed to five decimal places; 80 equally weighted keys, 31 aligned offsets, four bases, and 16 blocks give 158720 equally weighted integer HW evaluations; independent key count remains 80.
assumptions: The specified equal averaging determines a grid of 1/158720 for this raw mean; no granularity is imputed to the entropy or normalized-power endpoints; the manuscript does not explicitly state its decimal rounding rule.
derivation: M times 158720=114943.43680; adjacent attainable values are 114943/158720=0.7241872479838709677 and 114944/158720=0.7241935483870967742. Under the candidate round-to-nearest rule the interval would be [0.724185,0.724195), containing both values, but this rule is not declared in the manuscript.
derived_value_or_range: Adjacent grid values 114943/158720 and 449/620; a round-to-nearest reachability check would be consistent, with no unconditional rounding-rule verdict asserted.
comparison_rule: A completed GRIM verdict requires the manuscript's rounding convention; this boundary check does not establish an arithmetic mismatch.
status: not_computable
not_computable_reason: rounding_rule_ambiguous
