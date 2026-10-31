# Two-round ARX mechanism audit

This analysis was added after inspecting the archived output-word profiles. It is a descriptive, algebraically guided audit of the existing complete nonce-bit scan, not a preregistered or independent empirical confirmation. No new key cohort was generated. The identities below follow from the specified round functions; they are not presented as new cryptanalytic weaknesses.

Reproduce with:

```bash
python experiments/stream_rounds_study/arx_mechanism_analysis.py
```

The script writes CSV summaries and a source/data checksum manifest to `data/arx_mechanism_results/`. The input archive is `data/literature_mask_followup/arx_raw.npz`, with dimensions `(80 keys, 2 ciphers, 5 round counts, 64 masks, 4 base nonces, 8 blocks, 16 words)`.

## Word-level reachability

Number state and output words from 0 to 15. For the shared 64-bit nonce, ChaCha places its words at `x14,x15`; Salsa places them at `x6,x7`. Two core rounds are one column round followed by one diagonal round (ChaCha) or one row round (Salsa). The emitted words then add the initial words modulo `2^32`.

The analysis propagates sets of source-word labels through the actual sequence of operations. Addition and XOR both take the union of operand labels; word rotations preserve labels. This is a conservative dependence bound: an absent path proves independence, while a present path does not guarantee a nonzero difference for each input and says nothing about its probability or HW.

| Cipher/input word | Reachable after first round | Output words with no path after two rounds and feed-forward |
| --- | --- | --- |
| ChaCha `x14` | 2, 6, 10, 14 | none |
| ChaCha `x15` | 3, 7, 11, 15 | none |
| Salsa `x6` | 2, 6, 10, 14 | 1 |
| Salsa `x7` | 7, 11, 15 | 0, 1, 2, 3, 6 |

Salsa's quarter round updates `b,c,d,a`, in that order. `x6` enters as `d` in `(10,14,2,6)`, so its change can reach all four words. `x7` enters as `c` in `(15,3,7,11)`. Its value has not been used when `b=x3` is updated, so `x3` remains independent of it. The subsequent row round has the following input roles for the affected words:

| Changed nonce | Row 0 (words 0--3) | Row 1 (4--7) | Row 2 (8--11) | Row 3 (12--15) |
| --- | --- | --- | --- | --- |
| `x6` | `c` | `b` | `a` | `d` |
| `x7` | no affected word | `c` | `b` | `a` |

For an input difference entering at `c`, the row's `b` is already updated before the difference enters the calculation. This explains the additional unaffected word 6 for `x7` and word 1 for `x6`. Modular feed-forward only introduces a changed initial word at the changed nonce position itself, and neither position belongs to the respective absent-path sets. All predicted zeros survive feed-forward.

The archived scan has exactly the predicted all-zero words, with 81,920 HW observations per output word per nonce-word group (`80*32*4*8`). No probability estimate is needed to establish the independence identities.

## A feed-forward cancellation that reachability alone misses

For two-round Salsa, the working word at position 7 has the form `w7 = x7 XOR C`, with `C` independent of `x7`. In the column round and in the row round, this word occupies role `c`, so both updates XOR a quantity whose operands do not yet depend on `x7`. Consequently, the emitted word is

`y7 = ((x7 XOR C) + x7) mod 2^32`.

If bit `b` of `x7` is changed and bit `b` of `C` equals 1, the two summands change by opposite signed amounts and the output does not change. If that bit of `C` equals 0, both summands change by the same signed amount, so their arithmetic sum changes by `+/- 2^(b+1)` modulo `2^32`; the XOR HW then depends on carries in that sum. In particular, for `b=31` the emitted word is unchanged for either value of `C`.

This predicts an additional exact zero at output word 7 for the most significant state-word bit of `x7`. Under the archive's MSB-first byte-mask numbering and little-endian state packing, this is nonce mask **56**, not mask 63. All **2,560** archived HW values (`80*4*8`) are zero. Averaging all 32 `x7` bit positions gives HW **0.93418** for emitted word 7. The identity explains the cancellation mechanism; it does not predict this numerical average without a distributional analysis of `C` and the modular carries.

## Which repeated positions are also independent of the block counter

In Salsa, the low 32-bit counter occupies `x8`, which is also a role-`c` input in its column quarter round `(0,4,8,12)`. The same reachability analysis proves that two-round output words **4,5,6,7,11** are independent of this low counter. For blocks 0--7 the high counter remains zero, so those emitted words, and therefore their nonce-response HW values, repeat exactly across the eight blocks. The archived trajectories satisfy all **819,200** checked word-value equalities. Other words can change with the counter even though their average positional response remains similar.

## Why ChaCha can have compensating word profiles

Both ChaCha nonce words enter the first round in role `d`. Define `P` to shift every row of the 4-by-4 state one column to the right. Both the column and diagonal quarter-round schedules commute with `P`; componentwise feed-forward commutes with it as well. If `F` denotes the two-round state-to-output map on an arbitrary state, then `F(Px)=P F(x)` exactly.

This covariance maps a change at `x14` to a change at `x15` in the correspondingly rotated state. Actual sampled valid states are **not** invariant under `P`: the constants, counter, fixed zero word, and nonce/key locations are not all preserved. It therefore motivates an approximate profile correspondence, not an equality of the two empirical response distributions.

In the archived scan, the RMS difference between the two 16-word mean HW profiles is **4.66285 bits per word**. Shifting the `x14` profile one column to the right in every row reduces it to **0.32813**. The right shift was specified by the schedule identity, not selected by optimizing over shifts; the CSV nevertheless records all four shifts for transparency. Grouping each row into a 128-bit segment removes the within-row permutation. The second-minus-first differences in mean 128-bit HW are only **+0.16462, -0.09683, -0.13656, -0.19775** bits. These descriptive values explain how large local word contrasts can compensate under 128-bit aggregation. They do not prove a zero entropy gap or explain its value quantitatively.

## Checks and boundaries

- An independently instrumented numeric evaluator reproduced **2,048** production-core blocks and **256** archived pair trajectories, using the first and last existing keys, the first existing base nonce, all 64 masks, and counters 0--7.
- It checked the ChaCha state-rotation identity on **128** archived-derived states and the Salsa MSB feed-forward identity on **128** states.
- Exact zero and counter-invariance checks use the complete archived two-round cohort.
- Word-level path counts are not avalanche scores, probabilistic differential trails, or entropy predictions.
- The contribution is connecting elementary round-function consequences to emitted-output diagnostics and their aggregation. Establishing their novelty as cryptanalytic properties would require separate literature evidence.

The manuscript-ready text is in `arx_mechanism.tex`. It preserves these descriptive and structural qualifications. A new cohort is unnecessary to validate an algebraic identity; any new probabilistic endpoint should be locked before generating fresh keys.
