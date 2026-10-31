# Independent ARX resolution validation

Completed validation of predictions selected from the earlier 520–599 cohort.
The protocol was fixed before generating the 80 new key pairs 840–919:
`../../ARX_RESOLUTION_VALIDATION_PROTOCOL.txt`, SHA-256
`01421b276761aa61f8ab69b1339e83c8a5492615d5fa5f3d632e844295a7032b`.

Both ciphers use four shared base nonces and all 64 single-bit masks, at two
and four rounds. Streams have 8192 bits (16 blocks). Raw arrays retain
key × cipher × round × mask × base × block × 32-bit-word HW. Matched controls
reuse each nonce vertex across its comparisons.

The five planned two-round/full8192 tests confirm positive Salsa20 gaps at
32/64/128 bits and positive/negative ChaCha20 gaps at 32/64 bits, respectively.
All have Holm-adjusted p = 5/100001, the simulation floor. Other endpoints and
windows are descriptive. The small ChaCha20 128-bit gap is positive in this
cohort; its interval excludes zero. No equality of nonce-word diffusion is
claimed. Structural-check counts are deterministic checks, not sample sizes
for statistical inference.

From the repository root, run the read-only independent audit with:

```bash
python3 tools/audit_arx_extensions.py
```

To reproduce analysis under the original source and software fingerprint:

```bash
python3 experiments/stream_rounds_study/arx_resolution_validation.py --analyze-only
```

The command without `--analyze-only` resumes from the 80 complete checkpoints
when their protocol/source/software fingerprints match. Changed fingerprints
are rejected instead of mixing runs. Smoke mode uses separate keys 920–921
and writes only to `/tmp`.

The generation manifest records direct emitted-word counter-invariance
checks. Raw arrays retain HW only; the independent audit rechecks their
structural equalities, while the direct emitted-word counts are preserved
as generation metadata. `independent_audit.json` records the numerical audit
of all reported full-spectrum and AC/frequency endpoints and planned tests.
