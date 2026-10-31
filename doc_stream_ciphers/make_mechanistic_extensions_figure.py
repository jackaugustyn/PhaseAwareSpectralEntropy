#!/usr/bin/env python3
"""Render frozen model predictions and the independent 2/3/4-round follow-up."""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", tempfile.mkdtemp(prefix="arx-extension-figure-"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
PREDICTION = HERE / "data/arx_spectral_prediction"
TRANSITION = HERE / "data/arx_round_transition"
OUTPUT = HERE / "publication_mechanistic_extensions.pdf"
FAMILIES = ("ChaCha20", "Salsa20")


def read(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    prediction_path = PREDICTION / "compact_summary.csv"
    within_path = TRANSITION / "within_word_summary.csv"
    power_path = TRANSITION / "singleton_summary.csv"
    predicted = read(prediction_path)
    lookup = {(r["model"], r["family"], int(r["segment_bits"]), r["metric"]): r for r in predicted}
    assert len(lookup) == len(predicted) == 24
    cells = [(family, width) for family in FAMILIES for width in (32, 64, 128)]
    within = {(r["family"], int(r["rounds"])): r for r in read(within_path) if r["variant"] == "none"}
    powers = {(r["family"], int(r["rounds"])): r for r in read(power_path)
              if r["variant"] == "add" and int(r["segment_bits"]) == 128}
    assert len(within) == len(powers) == 6
    assert all(int(r["n_keys"]) == 80 for r in list(within.values()) + list(powers.values()))

    plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 8,
                         "axes.labelsize": 8.5, "axes.titlesize": 9,
                         "xtick.labelsize": 7, "ytick.labelsize": 8,
                         "pdf.fonttype": 42, "ps.fonttype": 42})
    fig, axes = plt.subplots(2, 2, figsize=(7.05, 5.7))
    x = np.arange(6)
    for ax, metric, letter, ylabel in (
        (axes[0, 0], "G", "a", "Nonce-word entropy gap G (bits)"),
        (axes[0, 1], "F512", "b", r"Block-power contrast $\Delta F_{512}$"),
    ):
        observed = [lookup["M0", family, width, metric] for family, width in cells]
        means = np.array([float(r["observed"]) for r in observed])
        low = np.array([float(r["observed_ci95_low"]) for r in observed])
        high = np.array([float(r["observed_ci95_high"]) for r in observed])
        for row, (family, width) in zip(observed, cells):
            other = lookup["M1", family, width, metric]
            assert all(row[k] == other[k] for k in ("observed", "observed_ci95_low", "observed_ci95_high"))
        ax.errorbar(x, means, yerr=np.vstack((means - low, high - means)), fmt="o",
                    color="#252525", markersize=4, capsize=2, linewidth=0.8,
                    label="New keys: 95% CI", zorder=4)
        for model, offset, marker, color in (("M0", -0.18, "s", "#c56a21"), ("M1", 0.18, "^", "#286f9b")):
            values = [float(lookup[model, f, w, metric]["prediction"]) for f, w in cells]
            ax.plot(x + offset, values, linestyle="none", marker=marker, color=color,
                    markersize=4, label=f"{model}: frozen prediction", zorder=3)
        ax.axhline(0, color="#777777", linewidth=0.65, zorder=0)
        ax.axvline(2.5, color="#999999", linestyle=":", linewidth=0.7)
        ax.set_xticks(x, [f"{f.replace('ChaCha20', 'ChaCha').replace('Salsa20', 'Salsa')}\n{w}" for f, w in cells])
        ax.set_xlim(-0.5, 5.5)
        ax.set_xlabel("Cipher and HW segment width (bits)")
        ax.set_ylabel(ylabel)
        ax.set_title(f"({letter}) Prediction at two rounds", loc="left")
        ax.legend(loc="best", fontsize=6.8, frameon=False)

    colors = {"ChaCha20": "#286f9b", "Salsa20": "#bd581c"}
    symbols = {"ChaCha20": "o", "Salsa20": "s"}
    for ax, records, metric, letter, title, ylabel in (
        (axes[1, 0], within, "observed", "c", "Within-word derivative, no feed-forward", r"Mean $D^2$ HW in word 7 (bits)"),
        (axes[1, 1], powers, "delta_block_fundamental_share", "d", "Block structure, modular feed-forward", r"Block-power contrast $\Delta F_{512}$"),
    ):
        for family in FAMILIES:
            rows = [records[family, r] for r in (2, 3, 4)]
            mean = np.array([float(r[metric + "_mean"]) for r in rows])
            lo = np.array([float(r[metric + "_ci95_low"]) for r in rows])
            hi = np.array([float(r[metric + "_ci95_high"]) for r in rows])
            ax.errorbar((2, 3, 4), mean, yerr=np.vstack((mean - lo, hi - mean)),
                        marker=symbols[family], color=colors[family], markersize=4,
                        capsize=2, linewidth=1.1, label=family)
        if metric == "observed":
            ax.axhline(16, linestyle=":", linewidth=0.8, color="#777777", label="Uniform mean: 16")
            ax.set_ylim(-0.7, 17.5)
        else:
            ax.axhline(0, linewidth=0.65, color="#777777")
        ax.set_xticks((2, 3, 4))
        ax.set_xlim(1.8, 4.2)
        ax.set_xlabel("Single core rounds")
        ax.set_ylabel(ylabel)
        ax.set_title(f"({letter}) {title}", loc="left", fontsize=8.1)
        ax.legend(loc="best", frameon=False, fontsize=7)
    for ax in axes.flat:
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.22, linewidth=0.5)
    fig.subplots_adjust(left=0.092, right=0.985, top=0.95, bottom=0.09, hspace=0.55, wspace=0.31)
    fig.savefig(OUTPUT, metadata={"Title": "Frozen spectral prediction and single-round diffusion transition",
                                 "CreationDate": None, "ModDate": None})
    plt.close(fig)
    inputs = (prediction_path, within_path, power_path)
    manifest = {"source_sha256": sha(Path(__file__)), "pdf_sha256": sha(OUTPUT),
                "input_sha256": {str(p.relative_to(HERE.parent)): sha(p) for p in inputs},
                "prediction_training_indices": [840, 919], "prediction_evaluation_indices": [1200, 1279],
                "transition_indices": [1400, 1479], "model_intervals_shown": False,
                "observed_intervals": "pointwise 95% whole-key bootstrap",
                "panels": ["G: fixed M0/M1 and independent observations", "DeltaF512: fixed M0/M1 and independent observations",
                           "Raw within-x7 D2 word7 HW, none", "DeltaF512 of singleton HW, add, 128-bit segments"]}
    (TRANSITION / "figure_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {OUTPUT.name}: frozen predictions and separate 80-key transition cohort")


if __name__ == "__main__":
    main()
