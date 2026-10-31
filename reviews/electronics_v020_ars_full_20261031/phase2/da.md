contract_role: da
## Dimension Scores

### D1: methodology_rigor
score: not_assessed

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

The central argument survives the adversarial challenges examined here. It connects a conditional algebraic property, paired changes of finalization, and empirical spectral reconstruction without claiming that these establish an attack or explain every component of the entropy gap. The assessment concerns D3; it does not certify the other dimensions or establish alignment with a publication target. Inspection included the supplied manuscript and bibliography, plus read-only checks of the two prediction summaries named below. No external sources were verified and no experiments or model simulations were rerun.

The most consequential possible counterexample would be a carry interaction that invalidates the claimed conditional affinity. The proof addresses this: each active input bit induces an interval ending at the next zero of the fixed constant, and successive active intervals are disjoint. Their independence supports the rank formula, while the union of their supports supports the singleton-HW formula. The manuscript also prevents an invalid extrapolation from this conditional map to joint affinity or full-cipher rank. The constants illustrating equal means with different ranks are explicitly presented as algebraic examples, so their use does not require demonstrating their occurrence among sampled cipher states.

Evidence Anchor: equation: §4.1, eq:compactfC and eq:affinecorollary, including the disjoint-support proof.
Confidence: 4/5 — direct algebraic inspection of the stated conditional map.

The finalization argument distinguishes an existing asymmetry from an added interaction. The positive working-output gap and the positive add-minus-none increment are different endpoints, and the manuscript does not infer that modular addition created the whole gap. Reusing the working state makes the intervention interpretable within these constructions. The mixed word-7 derivative is likewise distinguished from restoration of a reference-sized response, so a small nonzero interaction is not presented as adequate diffusion.

Evidence Anchor: table: Table 2 (tab:primary), Salsa20 working-output gap, add-minus-none gap, and mixed word-7 interaction rows.
Confidence: 4/5 — comparison of paired endpoints with the conclusions drawn from them.

The third-round result avoids another potentially invalid implication. A nonzero second derivative disproves affinity for the sampled unfinalized maps, but does not by itself establish the corresponding property after modular finalization or identify the first nonlinear operation in the entire state. Those restrictions appear in the manuscript itself. The simultaneous spectral observation is expressly taken from standard output; the conclusion reports coexistence of these two observations rather than claiming they are the same observable.

Evidence Anchor: text: §4.3, "Nonzero witnesses refute conditional affinity of the unfinalized word-7 map for those settings".
Confidence: 4/5 — logical scope of Boolean second-derivative witnesses.

The prediction claims also survive comparison with the supplied summaries. M1 has smaller mean-spectrum distances and smaller absolute fundamental-fraction errors in all six settings. M0 nevertheless has smaller absolute entropy-gap errors in all three ChaCha20 settings, as the manuscript states. Consequently, the argument does not silently turn improvement of a mean spectrum into improvement of every nonlinear summary. The reported Salsa20 128-bit residual also exceeds its simulation MCSE, and is disclosed rather than absorbed into a claim of exact reconstruction. These checks corroborate the reported comparisons; they do not independently validate the frozen fits or the complete data pipeline.

Evidence Anchor: dataset: doc_stream_ciphers/data/arx_spectral_prediction/compact_summary.csv and doc_stream_ciphers/data/arx_spectral_prediction/spectral_errors.csv, all six cipher-width settings.
Confidence: 5/5 — direct comparison of the reported claims with the supplied numerical summaries.

The sign-flip probabilities cannot be read as assumption-free tests of an unrestricted zero-mean null. The manuscript states that limitation and makes its calibration conditional. Within D3, the exact identities and reported effect sizes therefore carry argumentative weight independently of treating the smallest probabilities as unconditional guarantees. Similarly, unresolved higher-round results are not used to establish equivalence or security.

Evidence Anchor: text: §3.3, "Finite-sample validity requires null sign-invariance; zero mean and reference coupling alone do not guarantee it".
Confidence: 4/5 — distinction between a mean-null claim and sign-invariant calibration.

Coverage Receipt: No confirmed Critical or Major argumentative weakness was identified after challenging the conditional-affinity proof, the finalization contrast, the round-transition inference, the model-comparison claims, and the stated inferential scope. None of the Phase 1 D3 warning or blocking triggers is established by the inspected evidence.

#### CRITICAL

| # | Finding | Evidence Anchor | Confidence | Minimum remedy |
| --- | --- | --- | --- | --- |

#### MAJOR

| # | Finding | Evidence Anchor | Confidence | Minimum remedy |
| --- | --- | --- | --- | --- |
