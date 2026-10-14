#!/usr/bin/env python3
"""Three-panel article figure joining phase attribution with the fresh mask scan."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


HERE = Path(__file__).resolve().parent
BLUE, ORANGE, GREEN, GRAY = "#0072B2", "#D55E00", "#009E73", "#555555"


def rows(relative: str) -> list[dict[str, str]]:
    """Read one processed result table relative to the paper data directory."""
    with (HERE / "data" / relative).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def three(row: dict[str, str], field: str) -> tuple[float, float, float]:
    """Extract a mean and lower/upper pointwise interval for one metric."""
    return tuple(float(row[field + suffix]) for suffix in ("_mean", "_ci95_low", "_ci95_high"))


def err(values: list[tuple[float, float, float]]) -> np.ndarray:
    """Convert intervals to the asymmetric error lengths expected by Matplotlib."""
    a = np.asarray(values)
    return np.vstack((a[:, 0] - a[:, 1], a[:, 2] - a[:, 0]))


def main() -> None:
    """Render the article's DC/AC, rotation, and output-word panels."""
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.8,
                         "axes.titlesize": 9.2, "axes.labelsize": 8.5,
                         "xtick.labelsize": 7.7, "ytick.labelsize": 7.7,
                         "legend.fontsize": 7.3, "pdf.fonttype": 42,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig = plt.figure(figsize=(5.15, 4.2), constrained_layout=True)
    grid = fig.add_gridspec(2, 2, height_ratios=(1, 1.05))
    a = fig.add_subplot(grid[0, 0])
    b = fig.add_subplot(grid[0, 1])
    c = fig.add_subplot(grid[1, :])

    old = rows("unified_six_results/unified_six_summary.csv")
    cha = next(row for row in old if row["family"] == "ChaCha20" and
               row["configuration"] == "2" and row["scenario"] == "single_bit" and
               row["window"] == "full32")
    sal = next(row for row in rows("salsa20_transfer_results/salsa20_transfer_summary.csv")
               if row["configuration"] == "2" and row["scenario"] == "single_bit" and
               row["window"] == "full32")
    for i, row in enumerate((cha, sal)):
        a.barh(i - 0.16, float(row["dc_attribution_mean"]), height=0.3,
               color=BLUE, label="DC" if i == 0 else None)
        a.barh(i + 0.16, float(row["ac_attribution_mean"]), height=0.3,
               color=ORANGE, label="AC" if i == 0 else None)
    a.axvline(0, color=GRAY, linewidth=0.7)
    a.set_yticks((0, 1), ("ChaCha20/2", "Salsa20/2"))
    a.invert_yaxis()
    a.set_xlim(-0.62, 1.95)
    a.set_xlabel(r"Contribution to $\Delta H_{\rm MP}$ (bits)")
    a.set_title("(a) Exact DC/AC attribution")
    a.legend(frameon=False, loc="lower right", ncol=2)

    matched = rows("matched_nonce_phase_results/matched_nonce_phase_summary.csv")
    mcha = next(row for row in matched if row["family"] == "ChaCha20" and
                row["configuration"] == "2" and row["scenario"] == "single_bit")
    msal = next(row for row in matched if row["family"] == "Salsa20" and
                row["configuration"] == "2" and row["scenario"] == "single_bit")
    x = np.arange(2)
    for offset, label, color, field in (
        (-0.17, "Aligned", BLUE, "delta_hnodc_original"),
        (0.17, "Rotated", ORANGE, "delta_hnodc_rotated"),
    ):
        vals = [three(row, field) for row in (mcha, msal)]
        b.bar(x + offset, [v[0] for v in vals], width=0.32, color=color, label=label)
        b.errorbar(x + offset, [v[0] for v in vals], yerr=err(vals), fmt="none",
                   ecolor=GRAY, elinewidth=0.7, capsize=1.5)
    b.axhline(0, color=GRAY, linewidth=0.7)
    b.set_xticks(x, ("ChaCha20/2", "Salsa20/2"))
    b.set_ylabel(r"$\Delta H_{\rm noDC}$")
    b.set_title("(b) Within-block rotation")
    b.legend(frameon=False, loc="lower left")

    words = rows("literature_mask_followup/arx_output_word_gap.csv")
    for family, color, marker in (("ChaCha20", BLUE, "o"), ("Salsa20", ORANGE, "s")):
        selected = sorted((row for row in words if row["family"] == family and row["rounds"] == "2"),
                          key=lambda row: int(row["output_word"]))
        w = np.asarray([int(row["output_word"]) for row in selected])
        y = np.asarray([float(row["second_minus_first_delta_word_hw"]) for row in selected])
        low = np.asarray([float(row["ci95_low"]) for row in selected])
        high = np.asarray([float(row["ci95_high"]) for row in selected])
        c.plot(w, y, color=color, marker=marker, markersize=2.7,
               linewidth=1.2, label=family)
        c.fill_between(w, low, high, color=color, alpha=0.17, linewidth=0)
    c.axhline(0, color=GRAY, linewidth=0.7)
    c.set_xticks([0, 3, 7, 11, 15])
    c.set_xlabel("Output word (0–15)")
    c.set_ylabel("Nonce-word gap in output HW (bits)")
    c.set_title("(c) Two-round output profile")
    c.legend(frameon=False, loc="upper center", ncol=2)

    pdf = HERE / "publication_unified_mask_followup.pdf"
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    print(pdf)


if __name__ == "__main__":
    main()
