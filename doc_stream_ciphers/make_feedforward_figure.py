#!/usr/bin/env python3
"""Render the fixed non-MSB aligned-mask second-order output profiles."""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", tempfile.mkdtemp(prefix="arx-ff-figure-"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


HERE = Path(__file__).resolve().parent
DATA = HERE / "data" / "arx_feedforward_results"
SOURCE = DATA / "per_key_d2_profiles.csv"
OUTPUT = HERE / "publication_feedforward_derivatives.pdf"
FAMILIES = ("ChaCha20", "Salsa20")
VARIANTS = ("none", "add")
SEED = 2026103002
REPLICATES = 5000


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    with SOURCE.open(newline="", encoding="utf-8") as stream:
        rows = [r for r in csv.DictReader(stream)
                if int(r["rounds"]) == 2 and r["group"] == "aligned_nonmsb31"]
    keys = sorted({int(r["key_index"]) for r in rows})
    if keys != list(range(1000, 1080)):
        raise AssertionError("Figure requires the complete fixed 80-key cohort")
    lookup = {(int(r["key_index"]), r["family"], r["variant"], int(r["word"])): r
              for r in rows}
    if len(lookup) != len(rows) or len(rows) != 80 * 2 * 3 * 16:
        raise AssertionError("Incomplete or duplicated second-order profiles")
    samples = np.random.default_rng(SEED).integers(0, len(keys), (REPLICATES, len(keys)), dtype=np.int16)
    plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 9,
                         "axes.labelsize": 9, "axes.titlesize": 10,
                         "xtick.labelsize": 8, "ytick.labelsize": 8,
                         "pdf.fonttype": 42, "ps.fonttype": 42})
    figure, axes = plt.subplots(1, 2, figsize=(7.05, 3.05), sharey=True)
    colors = {"none": "#246a9b", "add": "#bd581c"}
    symbols = {"none": "o", "add": "s"}
    summaries: list[dict[str, object]] = []
    ymax = 18.0
    for fi, (family, ax) in enumerate(zip(FAMILIES, axes)):
        for variant in VARIANTS:
            values = np.asarray([[float(lookup[key, family, variant, word]["observed"])
                                  for word in range(16)] for key in keys])
            reference = np.asarray([[float(lookup[key, family, variant, word]["control"])
                                     for word in range(16)] for key in keys])
            if variant == "none":
                for key in keys:
                    for word in range(16):
                        left = lookup[key, family, "none", word]
                        right = lookup[key, family, "xor", word]
                        if any(left[name] != right[name] for name in ("observed", "control")):
                            raise AssertionError("None/XOR derivative profile identity failed")
            mean = values.mean(axis=0)
            low, high = np.quantile(values[samples].mean(axis=1), [0.025, 0.975], axis=0)
            ymax = max(ymax, float(high.max()) + 1)
            label = "No feed-forward = XOR" if variant == "none" else "Modular feed-forward"
            ax.plot(range(16), mean, marker=symbols[variant], markersize=3.5,
                    color=colors[variant], linewidth=1.3, label=label)
            ax.fill_between(range(16), low, high, color=colors[variant], alpha=0.18, linewidth=0)
            ref_label = "Reference: none = XOR" if variant == "none" else "Reference: modular"
            ax.plot(range(16), reference.mean(axis=0), color="#777777",
                    linewidth=0.85, linestyle="--" if variant == "none" else ":",
                    label=ref_label)
            for word in range(16):
                summaries.append({"family": family, "variant": variant, "word": word,
                                  "mean": float(mean[word]), "ci_low": float(low[word]),
                                  "ci_high": float(high[word]),
                                  "reference_mean": float(reference[:, word].mean())})
        ax.axvspan(6.7, 7.3, color="#777777", alpha=0.09, zorder=0)
        ax.set_title(f"({chr(97 + fi)}) {family}/2", loc="left")
        ax.set_xlabel("32-bit output word")
        ax.set_xticks([0, 3, 7, 11, 15])
        ax.set_xlim(-0.35, 15.35)
        ax.grid(axis="y", linewidth=0.5, alpha=0.25)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylabel("Mean second-order XOR HW, bits")
    axes[0].set_ylim(-0.4, np.ceil(ymax))
    handles, labels = axes[0].get_legend_handles_labels()
    order = [0, 2, 1, 3]
    figure.legend([handles[i] for i in order], [labels[i] for i in order],
                  loc="lower center", ncol=2, frameon=False, fontsize=8,
                  bbox_to_anchor=(0.52, 0.0))
    figure.subplots_adjust(left=0.075, right=0.985, top=0.9, bottom=0.3, wspace=0.12)
    figure.savefig(OUTPUT, metadata={"Title": "Feed-forward and mixed nonce derivatives",
                                    "CreationDate": None, "ModDate": None})
    plt.close(figure)
    manifest = {"source_sha256": digest(Path(__file__)), "input_sha256": digest(SOURCE),
                "pdf_sha256": digest(OUTPUT), "cohort_indices": keys,
                "mask_group": "aligned_nonmsb31", "rounds": 2,
                "bootstrap_seed": SEED, "bootstrap_replicates": REPLICATES,
                "intervals": "pointwise whole-key 95% percentile bootstrap",
                "profiles": summaries}
    (DATA / "figure_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {OUTPUT.name}: two cores, 31 fixed aligned masks, 80 paired keys")


if __name__ == "__main__":
    main()
