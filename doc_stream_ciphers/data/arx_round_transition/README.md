# Single-round ARX transition: complete independent follow-up

All 80 fresh master-key pairs (indices 1400–1479, seed 20261031) have been
generated, analyzed and independently audited. The prospective protocol is
`doc_stream_ciphers/ARX_ROUND_TRANSITION_PROTOCOL.txt`, SHA-256
`88a8b1812f32af7904c6a5b656350a047bac87804ca7209a551ae99360a6f6b1`.
It was fixed locally before generation, not publicly preregistered.

## Design

Each cipher uses four shared 64-bit base nonces, 64 singleton masks and the
previous 38-pair D2 panel. Each base has 103 distinct vertices, and the four
sets are verified disjoint. The output has 8192 bits, counters 0–15, at
2, 3 and 4 **single** rounds. A new vectorized evaluator runs alternating
column/diagonal rounds for ChaCha and column/row rounds for Salsa. Round 3
is the next column round, never three double rounds or a rounded request.
Existing cipher sources and earlier cohorts were not modified.

Add, none and xor finalizations share the working states. The SHAKE256
reference has separate domains across rounds and a shared working stream
across finalizations within each round, with the actual initial states.
Cipher and reference streams are reused at repeated nonce vertices.

## Planned results

| Endpoint | Mean | Pointwise 95% interval | Holm(2) p |
|---|---:|---:|---:|
| T1: Salsa/none within-x7 word-7 control-adjusted D2 HW, round 3 minus 2 | +15.8193359375 changed bits | [15.7201147461, 15.9203149414] | 0.0000199998 |
| T2: Salsa/add control-adjusted F512, round 3 minus 2, 128-bit segments | −0.5228689904 | [−0.5255938705, −0.5202001170] | 0.0000199998 |

T1 averages the two within-second-word pairs (0,15) and (7,30), four
bases and 16 blocks. Its raw cipher mean is 0 at two rounds and
15.84033203125 at three. The three-round control-adjusted HW remains
−0.17060546875 [−0.2520556641, −0.0874975586], descriptively. Proximity
to 16 changed bits does not prove reference equivalence.

T2 averages reference-adjusted mask-level fundamental-power fractions over
all 64 singleton masks. Each mask pools Q=4 complete Fourier powers before
computing F512; 8192 bits at 128-bit resolution give T=64 samples. The
two-, three- and four-round Delta F512 means are 0.8005411962,
0.2776722058 and 0.0004063726. The three-round pointwise interval
[0.2751818267, 0.2801079719] retains a substantial block-pattern signal;
the four-round interval [−0.0001237010, 0.0009433863] includes zero.

Tests use 100000 two-sided whole-key sign flips, seed 2026103105,
plus-one p values and one two-endpoint Holm family. Both reach the Monte
Carlo floor. Pointwise percentile intervals use 5000 whole-key bootstrap
draws, seed 2026103106, with identical paired indices across settings.
The master-key pair is the replicate, not the block, mask or word.

Other comparisons are descriptive, including ChaCha, other widths and
finalizations, transitions and mixed J. Salsa J3−J2 is −0.1699911794
[−0.2157977886, −0.1234357674]. Spectra are computed only from singleton
HW trajectories, never from D2 in this study.

## Named operation witnesses

The two checkpoints are immediately before and after the c=w7 update of
QR(15,3,7,11) in overall round 3 (a column round). Other updates of that
round do not write word 7, so the checkpoints equal W2[7] and W3[7].
Both equalities pass on 527360 vertex/block comparisons each.

There are 10240 stored within-word D2 witnesses per checkpoint. All are
zero before the update and all are nonzero afterward. A nonzero witness
refutes affinity for its sampled setting; a zero would not prove general
affinity. This location is not claimed to be the first nonlinear operation
in the whole state. The two-round zeros follow algebraically.

None and xor D2 agree bit for bit in all 9338880 comparisons per core
for both cipher and reference. The 30720 two-round Salsa within-word
checks across three finalizations are zero. All eight deterministic
check groups have no violations; counts are not extra statistical
replicates.

## Raw arrays and tables

`arx_round_transition_raw.npz` contains:

- `observed_singleton`, `oracle_singleton`: key × cipher × round × variant
  × 64 masks × four bases × 16 blocks × 16 HW32 words, uint8.
- `observed_d2`, `oracle_d2`: identical axes with 38 pairs replacing masks.
  Four emitted vertices are XORed on uint32 outputs before HW calculation.
- `observed_d2_word7`, `oracle_d2_word7`: uint32 derivatives with the final
  word axis removed and word 7 retained.
- `salsa3_checkpoint_d2_word7`: key × two named checkpoints × two within-word
  pairs × four bases × 16 blocks, uint32.
- `key_indices`: master indices 1400–1479.

Orders are ChaCha20/Salsa20; rounds 2/3/4; variants add/none/xor. The
generation manifest records masks, operation names, domains, software and
source hashes. Per-key checkpoints permit fingerprint-checked resume.
Per-key and summary CSVs cover singleton metrics, D2 profiles, word-7
pairs, within-word responses, mixed J, paired transitions and operation
witnesses. The only planned table is
`arx_round_transition_planned_tests.csv`. The analysis manifest records
all CSV checksums and statistical seeds. Structural checks and observed
checkpoint zero counts are stored separately.

## Validation and commands

Sixteen relevant tests passed before final generation, including five new
tests of independent scalar/vector agreement at every single-round
boundary, even-round 2/4/20 agreement, a published ChaCha vector,
nonce/vertex mapping, operation checkpoints and HW counting. The smoke
indices 1480–1481 ran only under `/tmp` and are outside this cohort.

`independent_audit.json` reports PASS. The independent scalar audit
regenerates 26368 cipher blocks through four rounds and 79104 reference
blocks for keys 1400 and 1479. It verifies raw derivatives and checkpoints,
and independently reconstructs seven table families for all 80 keys,
including bootstrap intervals and both p values. The maximum discrepancy
is 1.78e−14. Auditor SHA-256:
`275ff6ef9719eacc89095691e97c2decf065e5d476d1f8f5f545ee62625febf5`.

From the repository root:

```bash
python3 experiments/stream_rounds_study/arx_round_transition.py
python3 experiments/stream_rounds_study/arx_round_transition.py --analyze-only
python3 -m pytest -q tests/test_arx_round_transition.py tests/test_arx_feedforward.py tests/test_arx_resolution_validation.py
python3 tools/audit_arx_round_transition.py --write
```

Generator source SHA-256:
`961f1ff5af5be164e5e8283e5333a943b385312a625b4a16bd6608d27082367e`.
Generation fingerprint:
`dcd854be67607baf44dee52dbbb2b622c7fe47075bfd60722a500adf4989c228`.
