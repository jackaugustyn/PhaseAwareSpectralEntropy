# Frozen empirical spectrum prediction and independent evaluation

The two fixed models, 4096 Monte Carlo pseudo-key pairs per model, and the
independent 80-key-pair evaluation are complete. The protocol was frozen
before fitting or evaluation:
`doc_stream_ciphers/ARX_SPECTRAL_PREDICTION_PROTOCOL.txt`, SHA-256
`358fad464030014909e176064436f2bd4c1a3c2d3af72fd5e4d86f827921b186`.
No fit, MC budget, endpoint, or model was changed after observing evaluation
data. This is a locally fixed follow-up, not a public preregistration.

## Training and model laws

The only training input is the **two-round observed slice** of the earlier
resolution-validation archive: keys 840–919, both ciphers, 64 masks, four
base nonces, 16 blocks, and 16 HW32 words per block. No new evaluation
observation contributes to fitting.

- **M0** draws every word independently from the empirical marginal for
  its cipher, mask and output word, pooling all 5120 training key/base/block
  observations. It removes key/base variation in conditional profiles as
  well as residual dependencies.
- **M1** draws one training-key index per pseudo-key pair, shared by both
  ciphers and all masks. It retains all four base slots and independently
  samples each word/block residual from the selected key/mask/base/word
  layer's 16 observed blocks. Thus it retains conditional profiles and their
  pattern across masks, but removes residual word/block dependence.

The empirical distributions are unsmoothed and use population moments of
their finite support. Their zeros are preserved, including the known
Salsa20 structural zeros. The algebraic identities do not determine all
these empirical distributions. M1's 16-block layers include repeated values
and should not be viewed as 16 independent training replicates.

For a conditional trajectory, independent residuals imply
`E|DFT(h)[k]|^2 = |DFT(mu_repeat)[k]|^2 + sum_t variance[t]`.
For M1, average the four base-conditional powers within each training key,
then average training keys. Computing a Fourier transform of the pooled
mean would discard between-layer variation. `expected_power.npz` stores
these exact model expectations per mask. `analytic_spectrum.csv` normalizes
each mask's expected vector before averaging masks. These profiles remain
separate from finite Monte Carlo predictions.

**Entropy of normalized expected power is not expected finite-sample
entropy.** All reported finite scalar predictions use 4096 pseudo-key pairs
per model, four trajectories per mask (`Q=4`), and the exact power-before-
normalization estimator. One HW32 draw is aggregated into widths 32, 64 and
128 bits over 8192 output bits. Model-reference HW32 is independent
Binomial(32,1/2), using the same reference sequence for M0 and M1. It targets
finite mean metrics without claiming to reproduce joint nonce-vertex or
key covariance.

## Independent evaluation and uncertainty

The new evaluation has keys 1200–1279 and seed 20261031, with independent
per-family keys and reference secrets, four common base nonces, all 64
singleton masks, standard additive output, exactly two rounds, and counters
0–15. Its SHAKE256 reference reuses streams on the actual nonce-star graph.
`prediction_manifest.json` was written and hashed before the first new
evaluation key was generated. Per-key checkpoints pin that manifest hash.

`G` is the second-minus-first nonce-word difference in cipher-minus-reference
`H_MP`, pairing equal bit offsets and averaging the 32 pairs within a key.
`F512` in `compact_summary.csv` denotes **DeltaF512**, the observed-minus-
reference fraction of AC power at the frequency pair 1/512 bits. In a
trajectory of `T=8192/segment_bits` samples, these bins are 16 and `T-16`.
The ratio is computed per key/mask, after pooling its four powers, before
averaging masks.

Errors are evaluation mean minus frozen finite-MC prediction. Pointwise
95% intervals use 5000 whole-evaluation-key bootstrap draws, seed
2026103104, shared across models, widths and ciphers. Intervals are
conditional on the fixed training fit and MC estimate; they do not include
training uncertainty. MC standard errors are reported separately. No
hypothesis tests, success margins, equivalence declarations, or detector
power comparisons are performed.

The AC spectral error is the L1 distance between model and evaluation
**mean spectra normalized per mask before averaging**. Errors of individual
masks or keys can compensate. A positive lower bootstrap bound of this
nonnegative distance is not a model-rejection test.

## Results

Means for all six fixed cells:

| Cipher | Width | G evaluation | G M0 | G M1 | DeltaF512 evaluation | DeltaF512 M0 | DeltaF512 M1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| ChaCha20/2 | 32 | +0.02590 | +0.03322 | +0.03492 | 0.13293 | 0.11160 | 0.13838 |
| ChaCha20/2 | 64 | −0.06599 | −0.06808 | −0.05981 | 0.31514 | 0.26336 | 0.32452 |
| ChaCha20/2 | 128 | +0.00523 | +0.00526 | +0.00693 | 0.53850 | 0.42303 | 0.55252 |
| Salsa20/2 | 32 | +1.10639 | +1.20725 | +1.09859 | 0.36208 | 0.33270 | 0.36290 |
| Salsa20/2 | 64 | +0.97352 | +1.04531 | +0.96492 | 0.44285 | 0.41331 | 0.44356 |
| Salsa20/2 | 128 | +0.80132 | +0.85574 | +0.79465 | 0.80082 | 0.76860 | 0.80452 |

G is in entropy bits; DeltaF512 is dimensionless. Full pointwise intervals,
MCSEs and signed errors are in the compact and complete scalar CSVs.
Both models reproduce all observed signs; no sign was required for the
small 128-bit ChaCha20 gap.

| Cipher | Width | Mean AC-spectrum L1 error, M0 | Mean AC-spectrum L1 error, M1 |
|---|---:|---:|---:|
| ChaCha20/2 | 32 | 0.37932 | 0.07957 |
| ChaCha20/2 | 64 | 0.36070 | 0.07819 |
| ChaCha20/2 | 128 | 0.32199 | 0.08436 |
| Salsa20/2 | 32 | 0.26135 | 0.01766 |
| Salsa20/2 | 64 | 0.16139 | 0.01278 |
| Salsa20/2 | 128 | 0.10100 | 0.01043 |

M1 has smaller AC spectral and absolute DeltaF512 errors in all six cells,
and smaller absolute G errors in the three Salsa20 cells. **M0 has smaller
absolute G errors in the three ChaCha20 cells.** Thus retaining conditional
profiles improves the stated spectral predictions without uniformly
improving every scalar summary. Remaining differences do not distinguish
finite fitting error from omitted residual dependence.

## Files and reproduction

- `training_fit.npz`: raw training HW32 snapshot, M0 empirical counts and
  moments, M1 conditional moments, and training key indices.
- `expected_power.npz`: `s32`, `s64`, `s128`, each with axes model × cipher
  × mask × frequency bin. These are analytic expected unnormalized powers.
- `analytic_spectrum.csv`: per-cell normalized expected-power summaries.
- `monte_carlo_metrics.npz`: scalar values with axes model × pseudo-key ×
  cipher × width × scalar; `scalar_names` defines the last axis. It also
  stores the common M1 training-key positions.
- `monte_carlo_spectra.npz`: finite mean normalized full and AC spectra and
  MCSEs, with axes model × cipher × frequency for each width and data kind.
  AC arrays retain a zero DC entry for explicit frequency indexing.
- `prediction_manifest.json`: fixed protocol/source/training/prediction
  hashes, RNG seeds, axes, MC count and sampling details.
- `evaluation_raw.npz`: `observed` and `oracle` HW32 arrays with axes
  key × cipher × mask × base × block × word, plus `key_indices`.
- `evaluation_generation_manifest.json`, `checkpoints/`: provenance and
  resumable per-key data, each tied to the frozen prediction manifest.
- `evaluation_metrics.npz`, `evaluation_spectra.npz`,
  `evaluation_per_key.csv`: measurements retaining the whole-key unit.
- `compact_summary.csv`: 24 rows, two models × six cells × G/DeltaF512.
- `scalar_summary.csv`: all 228 finite scalar model/evaluation comparisons.
- `spectral_summary.csv`: all frequency-bin predictions, evaluation means,
  pointwise intervals and MCSEs for normalized full and AC spectra.
- `spectral_errors.csv`: all 12 model/cell AC L1 distances and intervals.
- `analysis_manifest.json`: evaluation and result hashes and reporting scope.

Commands from the repository root:

```bash
python3 -m pytest -q tests/test_arx_spectral_prediction.py
python3 experiments/stream_rounds_study/arx_spectral_prediction.py --smoke
python3 experiments/stream_rounds_study/arx_spectral_prediction.py --fit-only
python3 experiments/stream_rounds_study/arx_spectral_prediction.py
python3 experiments/stream_rounds_study/arx_spectral_prediction.py --analyze-only
```

Existing frozen predictions are verified and reused. Evaluation generation
cannot begin without a complete matching prediction manifest. The smoke
uses only indices 1280–1281 and 32 pseudo-key pairs under `/tmp`; smoke data
are excluded from the final fit, simulations and evaluation. The six unit
checks include exact enumeration of 65536 independent-residual outcomes,
layer-versus-pooled expected power, finite-entropy distinction, Q pooling,
sampling support/conditional profiles and whole-key bootstrap equivalence.
All six passed before the final run. Earlier raw arrays and scientific
source files were not modified.
