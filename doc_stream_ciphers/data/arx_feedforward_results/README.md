# Paired finalization and mixed-derivative follow-up

The 80-key-pair follow-up is complete. Its protocol is
`doc_stream_ciphers/ARX_FEEDFORWARD_PROTOCOL.txt`, fixed before this cohort
was generated, with SHA-256
`b416c7fb7b6697e26c4707b9e6c70981245f22eaecd243c480319ea393090ef8`.
This is a locally fixed prospective follow-up, not a public preregistration.

## Data and interventions

Master indices 1000–1079 use seed 20261030. Each key pair shares four
64-bit base nonces. Each base graph has 103 vertices: the base, all 64
singletons, and 38 two-bit changes. All four graphs are checked for
disjointness. Each cipher, round setting (2 or 4), and vertex emits 8192
bits, covering counters 0–15.

The standard output is `add = W + X` modulo 2^32. Recovering
`W = add - X` yields the same working state for experimental finalizations
`none = W` and `xor = W XOR X`. Established cipher source files were not
changed. Independent working-state checks cover both ciphers and both
round settings.

The reference uses one SHAKE256 working stream `R(v)` per nonce vertex and
applies all three finalizations with the same actual initial state `X`.
Thus the reference preserves coupling between interventions. It is a
computational random-function reference for working outputs, not a claim
that the real cipher permutation is a random function.

Every second derivative is computed by XORing its four emitted streams
before counting bits. The fixed panel contains 32 aligned cross-word
pairs, four offset cross-word pairs, and two within-second-word controls.
The manifest records the exact mapping between word-bit LSB numbering and
global nonce-mask MSB-first byte numbering.

## Planned results

All entropy endpoints use 128-bit segments over the complete 8192-bit
window. For each singleton mask, the four base-nonce Fourier powers are
averaged before normalization (`Q=4`). `G` is the second-minus-first
nonce-word difference of observed-minus-reference entropy contrasts.

| Endpoint | Mean | Pointwise 95% interval | Four-test Holm p |
|---|---:|---:|---:|
| E1: Salsa20/2 `G_none` | +0.729403 bits | [0.723915, 0.734931] | 0.0000399996 |
| E2: Salsa20/2 `G_add - G_none` | +0.058651 bits | [0.055348, 0.062016] | 0.0000399996 |
| E3: ChaCha20/2 `G_add - G_none` | −0.002929 bits | [−0.006516, 0.000679] | 0.107769 |
| E4: Salsa20/2 output-word-7 interaction `J` | +0.709671 changed bits | [0.682635, 0.736861] | 0.0000399996 |

Intervals use 5000 whole-key percentile bootstrap draws, seed 2026103002.
Two-sided mean tests use 100000 whole-key sign flips, seed 2026103001,
plus-one p values, and one Holm correction across E1–E4. The unit of
replication is the entire master-key pair. The three smallest p values
reach the finite-simulation floor after correction.

For E4, `A_variant` averages output-word-7 D2 HW over the 31 aligned pairs
with bit index 0–30, four bases, and 16 blocks. Then
`J = (A_add_observed - A_none_observed) - (A_add_control - A_none_control)`.
At two Salsa rounds, `A_add_observed = 0.724194`, whereas
`A_none_observed = A_xor_observed = 0`. The corresponding reference means
are 16.002722 and 15.988199. Bit 31 remains in the raw panel and exact
checks but is excluded from this planned average.

The results distinguish two effects: Salsa20's aggregate entropy gap
persists without feed-forward, while additive feed-forward changes the
gap and introduces the measured output-word-7 mixed derivative. The
128-bit ChaCha20 E3 result is not evidence of an absence of all
feed-forward effects: descriptive changes at 32- and 64-bit resolution
are negative with pointwise intervals excluding zero. Four-round
comparisons are descriptive; small estimates do not establish equivalence
to random output.

## Raw arrays

`arx_feedforward_raw.npz` stores:

- `observed_singleton`, `oracle_singleton`: key × cipher × round × variant
  × 64 masks × 4 bases × 16 blocks × 16 HW32 output words.
- `observed_d2`, `oracle_d2`: the same axes, replacing masks by 38 panel
  pairs.
- `observed_d2_word7`, `oracle_d2_word7`: uint32 second derivatives with
  the final output-word axis removed and output word 7 retained.
- `salsa2_singleton_word7`: key × variant × 64 masks × base × block,
  containing uint32 differences at Salsa20/2 output word 7.
- `salsa2_c`: key × 33 states × base × block. State 0 is the base value
  `C = W_7 XOR x_7`; states 1–32 correspond to first-word global nonce
  masks 0–31, respectively.
- `key_indices`: indices 1000–1079.

Cipher order is ChaCha20, Salsa20; round order is 2, 4; variant order is
add, none, xor. The manifest records these axes and all source hashes.

## Tables and checks

`arx_feedforward_per_key.csv` and `arx_feedforward_summary.csv` retain
singleton spectral/DC/AC/block-power measurements and nonce-word gaps at
32-, 64-, and 128-bit resolution. `arx_feedforward_paired_*` tables retain
paired changes in `G`. `arx_feedforward_planned_tests.csv` contains E1–E4.

`per_key_d2_profiles.csv` has fields
`key_index,family,rounds,variant,group,word,observed,control,delta`.
Groups are `aligned_all32`, `aligned_nonmsb31`, `offset4`, and `within2`.
Separate tables retain singleton profiles, per-pair word-7 HW, and the
interaction means. All summary intervals use the same whole-key draws.

All eleven deterministic check groups have zero violations. In particular,
none and xor D2 values agree bit-for-bit across all output words for both
cipher and reference (12,451,840 comparisons each), and all 184,320
applicable mixed ADD word-7 derivatives agree with the conditional
`L_b(C_changed) XOR L_b(C_base)` identity. These are exact implementation
checks, not additional statistical replicates or significance tests.

Generation and analysis commands, from the repository root:

```bash
python3 experiments/stream_rounds_study/arx_feedforward_study.py
python3 experiments/stream_rounds_study/arx_feedforward_study.py --analyze-only
python3 -m pytest -q tests/test_arx_feedforward.py tests/test_arx_resolution_validation.py
```

Generation resumes only from complete checkpoints with the same protocol,
source, cohort, and software fingerprint. The separate implementation
smoke used indices 1080–1081 under `/tmp`; its measurements are not included
in these results. Six dedicated finalization tests and five existing
aggregation/statistical tests passed before the final cohort was generated.

`generation_manifest.json` records raw and checkpoint hashes;
`arx_feedforward_manifest.json` records source, protocol, raw, and CSV
hashes plus analysis details. `structural_checks.json` retains exact
comparison counts. Previous cohorts, source files, and protocols remain
unchanged.
