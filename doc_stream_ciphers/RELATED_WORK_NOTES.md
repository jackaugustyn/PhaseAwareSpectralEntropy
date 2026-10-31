# Literature review: scope and verification

Revision date: 2026-10-30.

`related_work_comparison.tex` is now the literature-review section of the
manuscript (Section "Literature Review"). It covers specifications, avalanche
and randomness tests, chosen-IV statistics, the PNB and differential-linear
line on reduced Salsa20 and ChaCha from FSE 2008 through October 2026, and
spectral-entropy tests of sequences. It is a domain review of that chain. It
is not a protocol-registered systematic review, and it does not retabulate
every published attack complexity.

## What was checked

Publisher pages, Crossref records, or the authors' own abstracts were used for
the new bibliographic entries. Attack figures in the section are quoted as the
cited authors' claims. In particular:

- Bernstein, ChaCha, a variant of Salsa20, 28 January 2008, document ID
  `4027b5256e17b9796842e6d0f68b0b5e`. The design claim used in the text is the
  paper's own statement that the quarter-round changes increase diffusion per
  round.
- Aumasson et al., FSE 2008, DOI `10.1007/978-3-540-71039-4_30`. PNB
  introduction and the first reported 256-bit Salsa20/8 key recovery.
- Choudhuri and Maitra, ToSC 2016(2), DOI `10.46586/tosc.v2016.i2.261-287`.
- Maitra, Discrete Applied Mathematics 208 (2016), DOI
  `10.1016/j.dam.2016.02.020`.
- Dey and Sarkar, Discrete Applied Mathematics 227 (2017), DOI
  `10.1016/j.dam.2017.04.034`.
- Beierle, Leander, and Todo, CRYPTO 2020, LNCS 12172, DOI
  `10.1007/978-3-030-56877-1_12`.
- Coutinho et al., Journal of Cryptology 36 (2023), DOI
  `10.1007/s00145-023-09455-5`.
- Ghafoori and Miyaji, IEEE Access 12 (2024) 13386--13399, DOI
  `10.1109/ACCESS.2024.3356868`. Reported times \(2^{39.07}\) and
  \(2^{135.07}\) are taken from that paper's abstract.
- C. Dey, S. Dey, Girme, and Sarkar, IEEE Access 12 (2024) 31736--31744, DOI
  `10.1109/ACCESS.2024.3367797`. The reported 8-round complexity
  \(2^{210.38}\) and the dispute of an earlier single-bit bias are that
  paper's claims. The dispute targets an earlier Ghafoori attack, not the
  role of the three IEICE 2023 masks in this manuscript.
- S. Dey, IEEE Transactions on Information Theory 70 (2024) 6091--6106, DOI
  `10.1109/TIT.2024.3389874`. The \(2^{13.91}\)-fold gain and the first
  7.5-round ChaCha256 key-recovery claim are taken from that abstract.
- Dey, Maitra, Sarkar, and Sharma, ToSC 2025(1) 420--443, DOI
  `10.46586/tosc.v2025.i1.420-443`. The Salsa20/8.5 and Salsa20/8 figures, and
  the Coutinho et al. figures they identify as the previous record, are taken
  from that paper.
- Flórez-Gutiérrez and Todo, EUROCRYPT 2025, LNCS 15601, pp. 427--457, DOI
  `10.1007/978-3-031-91107-1_15`.
- Paul, Kundu, and Chakrabarti, IACR ePrint 2025/1830. Cited as a preprint.
  The manuscript does not treat it as a finished journal record.
- Liu, Ren, Sun, Yu, and Li, Cybersecurity 9 (2026), article 228, DOI
  `10.1186/s42400-026-00671-7`, published 9 October 2026. The path counts and
  distinguisher data complexities are taken from that abstract.
- Madarro-Capó et al., Computation 12 (2024), article 60, DOI
  `10.3390/computation12030060`.
- Kasyanov and Grishencev, Problems of Information Security. Computer Systems,
  2026, no. 3, pp. 25--48, DOI `10.66424/2071-8217-2026-3-2`, published
  13 October 2026. The English byline spells the second surname Grishencev.
  The ChaCha20 statement used in the text is the authors' report that
  unconditional ChaCha20 keystream met their spectral-entropy criterion.

The earlier local limitation still stands for one point. Ghafoori et al.,
IEICE 2023, Tables 9 and 17, remain a repository provenance record for the
three literature-guided masks. Those tables were not re-opened as a fresh
independent reading in this revision. The review therefore uses the masks as
already mapped in the manuscript and does not add new claims about the
numerical biases in those tables.

## What the review does not claim

- Priority for incomplete two-round diffusion, for PNBs, or for spectral
  entropy as a randomness statistic.
- That any quoted attack complexity is the best result after October 2026, or
  that this experiment improves an attack.
- That a pass of the Kasyanov--Grishencev keystream test describes the
  paired-nonce Hamming-weight spectrum.
- Equivalence between Bernstein's diffusion conjecture and the sign of a
  nonce-word entropy gap.
