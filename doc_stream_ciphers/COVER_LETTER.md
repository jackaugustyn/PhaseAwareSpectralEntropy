31 October 2026

Dear Editors of Electronics,

Please consider “Block-Position Structure in Reduced ChaCha20 and Salsa20: Experimental Diagnostics of IV Diffusion” for publication as an Article in Electronics.

The manuscript connects three stages of a nonce response: the round function, the feed-forward that forms the emitted block, and its measurement. Exact dependency and conditional-rank analysis, paired finalization interventions, and independently evaluated empirical spectrum models connect these stages experimentally.

A conditional corollary bounds the mean response of Salsa20/2 output word 7 to single-bit changes in the second nonce word by 31/32 changed bits with the remaining state fixed, and shows why equal mean responses can conceal different local ranks. A separate 80-key-pair experiment locates the observed loss of conditional affinity in the unfinalized word-7 map at a named third-round update, while substantial 512-bit response structure persists in the standard additive output. Local nonlinearity and block-scale mixing thus have distinct observed transitions. Earlier paired interventions show that the nonce-word asymmetry precedes feed-forward, with modular addition increasing its entropy gap by 0.05865 bits.

Frozen spectrum models and independent key cohorts test the explanatory reach of positional profiles. The revised figure displays observed and predicted mean AC spectra, while the methods state the assumptions of sign-flip calibration and the order of spectral normalization and averaging. Model discrepancies are reported alongside the unresolved planned ChaCha20 feed-forward endpoint. The work characterizes reduced-core diffusion without claiming an attack, a full-round weakness, or superior detector sensitivity.

The literature review positions the contribution as a connection between local conditional identities, paired finalization effects and empirical spectral reconstruction. The work makes no priority claim for weak low-round diffusion or higher-order differences. The submission is a single self-contained article, with its methods, conditional argument, principal results and limitations in the main text. The data/code archive iv_diffusion_research_review_v0.20.0.zip is prepared for reviewers and preserves fixed protocols, raw observations, code, detailed results, file-level hashes and independent audits from all completed studies. Public deposition is pending, as stated in the manuscript.

Sincerely,

Paweł Augustynowicz  
Faculty of Cybernetics, Military University of Technology  
Warsaw, Poland  
pawel.augustynowicz@wat.edu.pl

---

Draft for author review. Before using the letter, confirm the manuscript's publication and concurrent-submission status and add any declarations required by the current journal instructions. These statements have not been inferred on the author's behalf.
