#!/usr/bin/env python3
"""Render archived AC spectra and the independent 2/3/4-round transition.

Only the new figure and its own manifest are written. Frozen simulations,
observations, statistical tables and all previous figures remain unchanged.
The upper panels fold conjugate AC bins exactly, without smoothing or further
normalization. This preserves unit AC mass and, for real-valued trajectories,
the full two-sided L1 distance between the displayed mean spectra.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", tempfile.mkdtemp(prefix="arx-reviewed-spectrum-"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
PREDICTION = HERE / "data/arx_spectral_prediction"
TRANSITION = HERE / "data/arx_round_transition"
OUTPUT = HERE / "publication_reviewed_spectrum.pdf"
MANIFEST = HERE / "analysis/reviewed_spectrum_figure_manifest.json"
FAMILIES = ("ChaCha20", "Salsa20")
MODELS = ("M0", "M1")
WIDTH = 128
WINDOW = 8192
T = WINDOW // WIDTH
B = WINDOW // 512


def read(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fold_ac(q: np.ndarray) -> np.ndarray:
    """Sum each conjugate pair; omit DC and count Nyquist once."""
    q = np.asarray(q, dtype=float)
    if q.shape != (T,):
        raise AssertionError(f"Expected {T} spectral bins")
    np.testing.assert_allclose(q[1:T//2], q[:T//2:-1], rtol=0, atol=5e-14)
    folded = q[1:T//2+1].copy()
    folded[:-1] += q[:T//2:-1]
    # Independent explicit pairing guards the vectorized indexing.
    manual = np.array([q[k] + q[T-k] if k < T//2 else q[k]
                       for k in range(1, T//2+1)])
    np.testing.assert_array_equal(folded, manual)
    return folded


def main() -> None:
    spectral_path = PREDICTION / "spectral_summary.csv"
    evaluation_path = PREDICTION / "evaluation_spectra.npz"
    prediction_path = PREDICTION / "monte_carlo_spectra.npz"
    distance_path = PREDICTION / "spectral_errors.csv"
    within_path = TRANSITION / "within_word_summary.csv"
    power_path = TRANSITION / "singleton_summary.csv"
    rows = read(spectral_path)
    selected = {(row["model"], row["family"], int(row["frequency_bin"])): row
                for row in rows if int(row["segment_bits"]) == WIDTH}
    assert len(selected) == len(FAMILIES) * len(MODELS) * T
    distances = {(row["model"], row["family"]): float(row["ac_profile_l1_error"])
                 for row in read(distance_path) if int(row["segment_bits"]) == WIDTH}
    with np.load(evaluation_path) as raw:
        evaluation = raw[f"q_observed_s{WIDTH}"].copy()
    with np.load(prediction_path) as raw:
        prediction = raw[f"q_observed_s{WIDTH}_mean"].copy()
    assert evaluation.shape == (80, 2, T)
    assert prediction.shape == (2, 2, T)
    np.testing.assert_allclose(evaluation[..., 0], 0, atol=0)
    np.testing.assert_allclose(evaluation.sum(axis=-1), 1, atol=1e-13)
    np.testing.assert_allclose(evaluation[..., 1:T//2], evaluation[..., :T//2:-1],
                               rtol=0, atol=5e-14)

    spectral = {}
    verification = {}
    for fi, family in enumerate(FAMILIES):
        observed_rows = [selected["M0", family, k] for k in range(T)]
        observed = np.array([float(row["q_observed_evaluation"]) for row in observed_rows])
        low = np.array([float(row["q_observed_ci95_low"]) for row in observed_rows])
        high = np.array([float(row["q_observed_ci95_high"]) for row in observed_rows])
        np.testing.assert_allclose(observed, evaluation[:, fi].mean(axis=0), rtol=0, atol=5e-14)
        np.testing.assert_allclose(observed.sum(), 1, rtol=0, atol=1e-13)
        assert np.all(low[1:] > 0) and np.all(low <= observed) and np.all(high >= observed)
        observed_folded = fold_ac(observed)
        spectral[family] = {"observed": observed_folded, "low": fold_ac(low), "high": fold_ac(high)}
        verification[family] = {"observed_ac_mass": float(observed_folded.sum()),
                                "observed_dc": float(observed[0]), "models": {}}
        for mi, model in enumerate(MODELS):
            model_rows = [selected[model, family, k] for k in range(T)]
            assert all(a[col] == b[col] for a, b in zip(observed_rows, model_rows)
                       for col in ("q_observed_evaluation", "q_observed_ci95_low", "q_observed_ci95_high"))
            q = np.array([float(row["q_observed_prediction"]) for row in model_rows])
            np.testing.assert_allclose(q, prediction[mi, fi], rtol=0, atol=5e-14)
            assert q[0] == 0
            np.testing.assert_allclose(q.sum(), 1, rtol=0, atol=1e-13)
            folded = fold_ac(q)
            np.testing.assert_allclose(folded.sum(), 1, rtol=0, atol=1e-13)
            full_l1 = float(np.abs(observed-q).sum())
            folded_l1 = float(np.abs(observed_folded-folded).sum())
            np.testing.assert_allclose(folded_l1, full_l1, rtol=0, atol=1e-13)
            np.testing.assert_allclose(full_l1, distances[model, family], rtol=0, atol=1e-13)
            spectral[family][model] = folded
            verification[family]["models"][model] = {
                "ac_mass": float(folded.sum()), "full_two_sided_l1": full_l1,
                "folded_l1": folded_l1, "csv_npz_agreement": True}

    within = {(row["family"], int(row["rounds"])): row for row in read(within_path)
              if row["variant"] == "none"}
    powers = {(row["family"], int(row["rounds"])): row for row in read(power_path)
              if row["variant"] == "add" and int(row["segment_bits"]) == WIDTH}
    assert len(within) == len(powers) == 6
    assert all(int(row["n_keys"]) == 80 for row in list(within.values()) + list(powers.values()))

    plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 8,
                         "axes.labelsize": 8.5, "axes.titlesize": 9,
                         "xtick.labelsize": 7.5, "ytick.labelsize": 8,
                         "pdf.fonttype": 42, "ps.fonttype": 42})
    fig, axes = plt.subplots(2, 2, figsize=(7.05, 5.7))
    frequency = np.arange(1, T//2+1) / B
    styles = (("M0", "#c56a21", "s", "--"), ("M1", "#286f9b", "^", "-."))
    for ax, family, letter in zip(axes[0], FAMILIES, ("a", "b")):
        q = spectral[family]
        ax.fill_between(frequency, q["low"], q["high"], color="#555555", alpha=0.20, linewidth=0)
        for model, color, marker, linestyle in styles:
            ax.plot(frequency, q[model], color=color, marker=marker, markersize=2.6,
                    linewidth=0.9, linestyle=linestyle, label=model, zorder=2)
        ax.plot(frequency, q["observed"], color="#202020", marker="o", markersize=2.5,
                linewidth=0.85, label="Observed", zorder=3)
        ax.axvline(1, color="#777777", linewidth=0.7, linestyle=":", zorder=0)
        ax.axvline(2, color="#777777", linewidth=0.7, linestyle=":", zorder=0)
        ax.set_yscale("log")
        ax.set_ylim(1.8e-4, 1.1)
        ax.set_xlim(0, 2.06)
        ax.set_xticks((0, 0.5, 1, 1.5, 2))
        ax.set_xlabel("Frequency (cycles per 512-bit block)")
        ax.set_ylabel("Mean AC power fraction (folded)")
        ax.set_title(f"({letter}) {family}/2, 128-bit segments", loc="left")
        ax.legend(loc="upper left", fontsize=7.2, frameon=False, handlelength=2.3)

    colors = {"ChaCha20": "#286f9b", "Salsa20": "#bd581c"}
    symbols = {"ChaCha20": "o", "Salsa20": "s"}
    for ax, records, metric, letter, title, ylabel in (
        (axes[1, 0], within, "observed", "c", "Within-word derivative, no feed-forward", r"Mean $D^2$ HW in word 7 (bits)"),
        (axes[1, 1], powers, "delta_block_fundamental_share", "d", "Block structure, modular feed-forward", r"Block-power contrast $\Delta F_{512}$"),
    ):
        for family in FAMILIES:
            records_for_rounds = [records[family, r] for r in (2, 3, 4)]
            mean = np.array([float(row[metric + "_mean"]) for row in records_for_rounds])
            lo = np.array([float(row[metric + "_ci95_low"]) for row in records_for_rounds])
            hi = np.array([float(row[metric + "_ci95_high"]) for row in records_for_rounds])
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
    fig.subplots_adjust(left=0.095, right=0.985, top=0.95, bottom=0.09, hspace=0.52, wspace=0.34)
    fig.savefig(OUTPUT, metadata={"Title": "Observed and frozen-predicted AC spectra with single-round transition",
                                 "CreationDate": None, "ModDate": None})
    plt.close(fig)
    inputs = (spectral_path, evaluation_path, prediction_path, distance_path, within_path, power_path)
    manifest = {"source_sha256": sha(Path(__file__)), "pdf_sha256": sha(OUTPUT),
                "input_sha256": {str(path.relative_to(HERE.parent)): sha(path) for path in inputs},
                "segment_bits": WIDTH, "window_bits": WINDOW, "dft_length": T,
                "spectral_observable": "q_observed: cipher AC-normalized power, no reference subtraction",
                "averaging": "Pool four base powers per key/mask, normalize AC per key/mask, average masks, average keys; predictions average 4096 complete simulated key pairs.",
                "folding": "k=1..31: q[k]+q[64-k]; k=32: q[32]; DC omitted. No smoothing or renormalization.",
                "frequency_axis": "k/16 cycles per 512-bit block; k=16 is 1/512 cycles/bit and k=32 is 2/512 (Nyquist)",
                "observed_intervals": "Pointwise 95% whole-key bootstrap intervals; conjugate symmetry permits exact pair folding of the stored endpoints.",
                "model_intervals_shown": False,
                "prediction_training_indices": [840, 919], "prediction_evaluation_indices": [1200, 1279],
                "transition_indices": [1400, 1479], "verification": verification,
                "panels": ["ChaCha20/2 folded AC spectrum: new observations and frozen M0/M1", "Salsa20/2 folded AC spectrum: new observations and frozen M0/M1", "Raw within-x7 D2 word7 HW, none", "DeltaF512 of singleton HW, add, 128-bit segments"]}
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {OUTPUT.name}; CSV/NPZ agreement, AC mass, conjugate symmetry and L1 preservation verified")


if __name__ == "__main__":
    main()
