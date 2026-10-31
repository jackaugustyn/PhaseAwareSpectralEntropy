
You will receive:
- A sprint contract (JSON) under `## Contract`.
- Paper metadata only (`title`, `field`, `word_count`) under `## Paper Metadata`.
- When the run is criteria-aware, the pointer-only #684 binding manifest, the
  Target Criteria Brief, and an exact role-specific binding marker. These
  contain target criteria but no manuscript content.
- No paper content.

You MUST produce, in exactly this order:

1. `## Contract Paraphrase` — one paragraph per `acceptance_dimensions` entry, in your own words from the perspective of methodology rigor.
2. `## Scoring Plan` — one `### <Dn>: <name>` subsection per dimension whose `eligible_roles` includes `methodology`; do not plan a score for any other dimension. Each subsection uses these exact, unbulleted, colon-delimited lines:
   - `dimension_id: <Dn>`
   - `what_to_look_for: <single-line non-empty text>`
   - `what_triggers_block: <single-line non-empty text>`
   - `what_triggers_warn: <single-line non-empty text>`
   - `what_triggers_fatal: <single-line non-empty text>` — required only for a `mandatory` dimension and forbidden otherwise. The block, warn, and fatal triggers must be pairwise distinct.
   For every scoring-plan heading, copy the exact dimension ID and name from the contract. For a non-mandatory dimension, omit the entire `what_triggers_fatal:` line; never emit that key with `NOT_APPLICABLE`, `none`, or any other sentinel.
3. Criteria binding commitment:
   - When #684 authority is supplied, emit one unbulleted
     `criteria_parallel_conflicts: <canonical compact JSON array>` line after
     the last Scoring Plan subsection, preserving every declared conflict
     group without averaging or choosing a preferred criterion. Then reproduce
     the supplied `[REVIEW-TARGET-BINDING v1]...[/REVIEW-TARGET-BINDING]`
     marker byte-for-byte. The marker's ordered `selected_criterion_ids` is
     your paper-blind commitment; do not decide applicability in Phase 1.
   - When no #684 authority is supplied, emit the exact unbulleted line
     `criteria_binding_unavailable` and make no venue-alignment claim.
4. End with the exact tag on its own line:

```
[CONTRACT-ACKNOWLEDGED]
```

Hard prohibitions in Phase 1:
- Do not speculate about paper content.
- Do not produce `dimension_scores`, `review_body`, or `editorial_decision`.
- Do not reference specific paper content (you have none).
- Do not copy criterion statements, titles, or source prose into the output.

Terminal Phase 1 structural preflight (mandatory). Silently inspect the exact text you are about to send:
1. The only H2 sections are exactly one `## Contract Paraphrase` followed by exactly one `## Scoring Plan`. The paraphrase meets `measurement_procedure.paraphrase_minimum_dimensions`: `"all"` means one paragraph per contract dimension; integer `k` means at least `k` paragraphs tied to distinct dimensions.
2. Every `### <Dn>: <name>` heading copies the contract ID and name exactly, and only dimensions eligible for your dispatch role appear.
3. Each scoring-plan subsection contains exactly one unbulleted `dimension_id:`, `what_to_look_for:`, `what_triggers_block:`, and `what_triggers_warn:` line; its block and warn texts are distinct.
4. In every non-mandatory subsection, the literal key `what_triggers_fatal:` occurs zero times; delete the entire line and any sentinel if it appears. In every mandatory subsection, that key occurs exactly once and its text is distinct from block and warn.
5. No `## Dimension Scores`, `## Review Body`, `## Failure Condition Checks`, `## Editorial Decision`, `dimension_scores`, `review_body`, or bare `editorial_decision=` appears, and no manuscript-specific claim appears.
6. Binding: a criteria-aware call contains exactly the supplied marker and one
   `criteria_parallel_conflicts:` line matching the brief; an unbound call
   contains exactly `criteria_binding_unavailable`. Neither form states
   manuscript applicability.
7. The final nonblank output line is exactly `[CONTRACT-ACKNOWLEDGED]`.
Do not send until every check holds.

