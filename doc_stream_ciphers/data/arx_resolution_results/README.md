# ARX resolution and output-window reanalysis

This completed **descriptive secondary analysis** reuses the 80 matched key
pairs indexed 520–599 in `../literature_mask_followup/arx_raw.npz`. It does not
generate new keys or constitute an independent replication. The existing
128-bit segmentation motivated the resolution comparison; this analysis was
not prespecified before inspection of that cohort.

Run from the repository root:

```bash
python experiments/stream_rounds_study/analyze_arx_resolution.py
python -m pytest -q tests/test_arx_resolution.py
```

## Measurements

The grid contains both ciphers, all five archived round settings (2, 4, 6, 8,
20), segment widths 32, 64, 128 bits, and windows covering bits [0,4096),
[0,2048), [2048,4096). Segments start at the beginning of a 512-bit block;
adjacent raw 32-bit HWs are summed without regenerating a stream. There are
16, 8, or 4 samples per output block, respectively.

For each key and nonce-bit mask, Fourier power is averaged over its four
base-nonce trajectories before normalization (`Q=4`). The mask-level metrics
are then averaged across all 64 masks within a key. All `delta_*` quantities
subtract the graph-matched control. `word_gap_delta_*` subtracts the mean
contrast over first-word masks 0–31 from the mean over second-word masks
32–63, pairing the same bit offsets. Thus `word_gap_delta_hmp` is the original
`G_r` definition evaluated at each new resolution and window.

For segment width `s`, write `L=512/s`, `B=window_bits/512`, `N=B*L`, and
`P[k]` for the four-pair averaged power. The added diagnostics are:

- **Block harmonic share:** `sum(P[j*B], j=1,...,L-1) / sum(P[1:])`.
  These are the nonzero frequencies compatible with a 512-bit repeated
  profile. Its raw null baseline changes with `L` and `N`; interpretation
  uses the matched-control contrast.
- **Block fundamental share:** `(P[B]+P[N-B]) / sum(P[1:])`. This isolates
  frequency 1/512 bits. Unlike the sum over all harmonics, it cannot be
  explained by a pattern with a period dividing 256 bits alone.
- **Phase range fraction:** within-block HW means are averaged over base
  nonces and blocks, and their maximum-minus-minimum is divided by `s`.

AC entropy is divided by `log2(N-1)`. Entropy and power-share values are
defined as zero if their relevant power denominator is zero. This convention
does not affect any reported cohort measurement.

## Results most relevant to the manuscript

Full 4096-bit window; means across 80 keys. The gap is in bits and the
remaining columns are unitless observed-minus-control contrasts.

| Cipher | Segment bits | `G_2` | Normalized AC entropy | Block harmonic share | Block fundamental share |
|---|---:|---:|---:|---:|---:|
| ChaCha20/2 | 32 | +0.03171 | -0.27549 | +0.66982 | +0.12946 |
| ChaCha20/2 | 64 | -0.06778 | -0.32542 | +0.67677 | +0.30934 |
| ChaCha20/2 | 128 | -0.00036 | -0.36525 | +0.67709 | +0.52740 |
| Salsa20/2 | 32 | +1.09099 | -0.48195 | +0.85085 | +0.35479 |
| Salsa20/2 | 64 | +0.95845 | -0.53409 | +0.86864 | +0.42781 |
| Salsa20/2 | 128 | +0.79059 | -0.65981 | +0.88908 | +0.77081 |

The positive Salsa20 gap persists at all three resolutions in both stream
halves. Its size is not invariant under aggregation. ChaCha20's near-zero
128-bit gap is specifically a property of that segmentation: at 32 bits the
full-window gap is +0.03171 [0.02099, 0.04185], and at 64 bits it is -0.06778
[-0.07447, -0.06131]. This refines the original interpretation of compensating
output-word responses and rules out treating the aggregate gap as an
intrinsic scalar ordering of diffusion quality.

Both ciphers show substantial excess 512-bit harmonic and fundamental power
at every resolution and in each half-window. The recurring signal therefore
survives replacement of the original four samples per block by eight or
sixteen samples. Calling the response “four-position” describes the original
128-bit observation scheme; the reanalysis locates recurring structure at
the cipher's 512-bit block scale.

At four rounds the maximum absolute mean harmonic-share contrast across
both ciphers and all nine measurement settings is 0.00422; at 20 rounds it
is 0.00284. Corresponding maxima for the fundamental share are 0.00229 and
0.00185. Some small pointwise intervals exclude zero. These descriptive
results support a large reduction in the measured effect; they do not
establish equivalence to random output or a simultaneous null conclusion.

## Files, uncertainty and checks

- `arx_resolution_per_key.csv`: 7200 rows; all observed, control, contrast,
  and nonce-word gap measurements retained for whole-key reanalysis.
- `arx_resolution_summary.csv`: 90 configurations; means and pointwise 95%
  percentile intervals for all endpoints.
- `arx_resolution_compact.csv`: a smaller selection of manuscript endpoints.
- `arx_resolution_manifest.json`: input/output/script SHA-256 hashes, axes,
  definitions, seed, resampling, and verification results.

Intervals use 5000 whole-key resamples, seed 20261029, sharing the same draws
across ciphers, settings and metrics. They are pointwise descriptive
intervals, with no simultaneous-coverage or newly corrected hypothesis-test
claim. The original confirmatory 128-bit result retains its original
10,000-resample interval and two-test Holm analysis; the slightly different
5000-resample interval here does not replace it.

The script reproduced the archived 128-bit/full-window nonce-word gaps in
full entropy, normalized AC entropy, and DC share for both ciphers at all
five round settings (maximum absolute difference `4.55365e-18`). Five focused
tests check additive aggregation, old-estimator reproduction, harmonic
frequency indexing, zero-power conventions, and separation of a 512-bit
fundamental from a shorter subperiod. Only block-aligned segment origins and
whole-block windows are examined; word-HW data cannot recover sub-word
segmentations.
