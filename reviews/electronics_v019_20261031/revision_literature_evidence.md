# Evidence limit and proposed literature revision

Date: 2026-10-31. Scope: the author's authorized revision of the v0.19.0 article, with one article and no supplement. No manuscript, reference database, scientific data, or protocol was edited by this research task.

## Sources actually inspected

- `doc_stream_ciphers/RELATED_WORK_NOTES.md`, dated 2026-10-30. This records earlier bibliographic checks and general attack claims, including Dey et al. (2025); it does not preserve the relevant full text or a quoted theorem.
- `doc_stream_ciphers/biblio.bib`, entries `dey2025tosc`, `ghafoori2024hodl`, `dey2024tit`, and `florez2025`.
- Searches for PDF, HTML, text, and source caches in the project and `/tmp`. These found article copies, study data, and the earlier notes, but no full text of the cited Dey paper or the closest higher-order analysis.

The exact cited Dey version is *Significantly Improved Cryptanalysis of Salsa20 with Two-Round Criteria*, IACR Transactions on Symmetric Cryptology 2025(1), pp. 420–443, DOI `10.46586/tosc.v2025.i1.420-443`. This identification comes from the local bibliography and earlier provenance note; it is not a new external verification of the record or its contents.

No new network escalation was attempted. The prior DNS failure and failed automatic approval review (technical 404) provide no usable source access; they were not bypassed. No PDF page anchor is asserted for an unread paper.

## What can and cannot be concluded

The current article proves its conditional identity and explicitly defines its measured endpoints. That permits a precise statement of the work's contribution and a distinction between local identities, paired finalization effects, and empirical spectral prediction.

The available material does **not** establish whether Dey et al. already contain the same word-7 identity, an equivalent rank result, or a closely related lemma. It would be unsupported to write that earlier work lacks these results, that the local property is first discovered here, or that the paper establishes priority over those criteria. The review's substantive priority-comparison request therefore remains only partially resolved until the exact cited source is read.

## Conservative replacement paragraph

> Two-round Salsa20 criteria~\citep{dey2025tosc} and higher-order ChaCha analysis~\citep{ghafoori2024hodl} already place low-round structure in a cryptanalytic setting. We do not claim novelty for weak two-round diffusion or higher-order differences. Our contribution is an explicit connection between three testable objects: the conditional word-7 map and its exact rank and mean-singleton identities; paired changes in emitted responses under add/none/xor finalization; and the ability of frozen empirical positional models to reproduce spectra on new keys. The local identities predict zeros and interactions, not the entire entropy gap. The intervention isolates the contribution of finalization, while evaluation on new keys assesses spectral reconstruction. This scope makes no claim of improved attack complexity or universal detector superiority.

This paragraph intentionally states the contribution without asserting first publication of the algebraic identity. It does not replace a source-backed comparison with the exact Dey theorem. The manuscript can use a more compact version if space requires, while the revision record should retain the unresolved priority check.

## Source-backed comparison to perform when the cited version becomes accessible

Compare the actual Dey criteria with the present result by (i) state/input words held fixed or perturbed, (ii) number and convention of rounds, (iii) raw working state versus additive output, and (iv) exact conclusion—selected differential bias or key/IV condition, missing dependency, conditional affinity, rank, or singleton HW identity. If the algebraic property is already present, identify it as a reproduced premise and locate this article's incremental contribution in the paired interventions and measured-spectrum validation. None of those determinations should be inferred from the title alone.
