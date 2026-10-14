#!/usr/bin/env python3
"""Uniform multi-key study for the Entropy manuscript.

The independent experimental unit is a master key/seed.  For every key, the
same number of base states and masks is evaluated in every cell.  The script
stores key-level estimates so uncertainty can be computed across keys rather
than across points of an already aggregated depth curve.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import platform
import sys
from typing import Iterable

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from spectral_crypto_analyzer.primitives import (  # noqa: E402
    PrimitiveContext,
    build_primitive,
    xor_bytes,
)


FAMILY_DEPTHS: dict[str, list[int]] = {
    "A5/1": [20, 40, 60, 80, 120, 160, 240, 320],
    "RC4": [256, 512, 768, 1024, 1536, 2048, 3072, 4096],
    "RC4-direct": [256, 512, 768, 1024, 1536, 2048, 3072, 4096],
    "Grain-128": [32, 64, 96, 128, 192, 256, 384, 512],
    "Trivium": [64, 128, 192, 256, 384, 512, 768, 1024],
}
PRIMITIVE_NAMES = {
    "A5/1": "A5-1-{depth}R",
    "RC4": "RC4-{depth}R",
    "RC4-direct": "RC4-Direct-{depth}R",
    "Grain-128": "Grain-{depth}R",
    "Trivium": "Trivium-{depth}R",
}
TRAJECTORY_LENGTHS = (8, 16, 32, 64)


ACTIVE_BITS = {
    "A5/1": list(range(10, 32)),  # low 22 bits of the first big-endian word
    "RC4": list(range(128)),  # all bits enter the state-dependent key tweak
    "RC4-direct": list(range(128)),  # all bits enter the 16-byte key directly
    "Grain-128": list(range(96)),  # 96-bit IV
    "Trivium": list(range(80)),  # 80-bit IV
}
MASKS_PER_SCENARIO = 32
SCENARIO_NAMES = (
    "stratified_single_bit",
    "localized_four_bit",
    "dispersed_four_bit",
)


def _bit_mask(positions: Iterable[int]) -> bytes:
    data = bytearray(16)
    for position in positions:
        data[position // 8] |= 1 << (7 - position % 8)
    return bytes(data)


def _unique_linspace_indices(upper: int, count: int) -> list[int]:
    """Evenly spaced unique indices in ``0 .. upper`` inclusive."""
    if upper < 0:
        return []
    available = upper + 1
    n = min(count, available)
    if n == available:
        return list(range(available))
    raw = np.linspace(0, upper, n).round().astype(int)
    seen: set[int] = set()
    ordered: list[int] = []
    for value in raw.tolist():
        if value not in seen:
            seen.add(value)
            ordered.append(int(value))
    # Fill remaining slots from unused indices if rounding collapsed some.
    if len(ordered) < n:
        for candidate in range(available):
            if candidate not in seen:
                ordered.append(candidate)
                seen.add(candidate)
            if len(ordered) >= n:
                break
    return ordered[:n]


def scenario_masks(family: str, scenario: str) -> list[bytes]:
    """Return up to 32 active masks of equal weight for a family and scenario.

    For short active domains (e.g. A5/1's 22-bit frame) the catalogue uses every
    distinct mask of the requested form rather than repeating positions.
    """
    domain = ACTIVE_BITS[family]
    n = MASKS_PER_SCENARIO
    if scenario == "stratified_single_bit":
        indices = _unique_linspace_indices(len(domain) - 1, n)
        return [_bit_mask([domain[index]]) for index in indices]
    if scenario == "localized_four_bit":
        if len(domain) < 4:
            raise ValueError(f"{family} domain too short for four-bit masks")
        starts = _unique_linspace_indices(len(domain) - 4, n)
        return [_bit_mask(domain[start : start + 4]) for start in starts]
    if scenario == "dispersed_four_bit":
        if len(domain) < 4:
            raise ValueError(f"{family} domain too short for four-bit masks")
        # Four roughly equidistant active bits, with the pattern slid across the
        # domain so local vs dispersed four-bit probes can be contrasted.
        span = max(len(domain) // 4, 1)
        max_offset = len(domain) - (3 * span + 1)
        if max_offset < 0:
            # Fall back to every combination of four evenly spaced indices.
            offsets = _unique_linspace_indices(len(domain) - 4, n)
            masks = []
            for offset in offsets:
                positions = [
                    domain[offset],
                    domain[min(offset + span, len(domain) - 1)],
                    domain[min(offset + 2 * span, len(domain) - 1)],
                    domain[min(offset + 3 * span, len(domain) - 1)],
                ]
                # Deduplicate collapsed positions by stretching remaining picks.
                uniq = list(dict.fromkeys(positions))
                cursor = 0
                while len(uniq) < 4:
                    candidate = domain[cursor % len(domain)]
                    if candidate not in uniq:
                        uniq.append(candidate)
                    cursor += 1
                masks.append(_bit_mask(uniq[:4]))
            return masks
        offsets = _unique_linspace_indices(max_offset, n)
        return [
            _bit_mask(
                [
                    domain[offset],
                    domain[offset + span],
                    domain[offset + 2 * span],
                    domain[offset + 3 * span],
                ]
            )
            for offset in offsets
        ]
    raise ValueError(f"Unknown scenario: {scenario}")


@dataclass(frozen=True)
class Cell:
    family: str
    depth: int
    scenario: str
    trajectory_length: int


def _entropy(power: np.ndarray) -> float:
    total = float(np.sum(power))
    if total <= 0.0:
        return 0.0
    p = power / total
    positive = p > 0.0
    return float(-np.sum(p[positive] * np.log2(p[positive])))


def _normalised_ac_entropy(power: np.ndarray) -> float:
    ac = power[1:]
    if ac.size <= 1:
        return 0.0
    return _entropy(ac) / math.log2(ac.size)


def _summarise_trajectories(trajectories: list[np.ndarray]) -> dict[str, float]:
    """Compute Parseval-consistent metrics from the complete two-sided DFT."""
    values = np.asarray(trajectories, dtype=np.float64)
    spectra = np.fft.fft(values, axis=1)
    magnitudes = np.abs(spectra)
    powers = magnitudes**2
    mean_magnitude_power = np.mean(magnitudes, axis=0) ** 2
    mean_power = np.mean(powers, axis=0)
    per_trajectory_entropy = np.asarray([_entropy(row) for row in powers])
    one_sided_power = np.mean(
        np.abs(np.fft.rfft(values, axis=1)) ** 2, axis=0
    )
    one_sided_weights = np.ones(one_sided_power.size)
    if values.shape[1] % 2 == 0:
        one_sided_weights[1:-1] = 2.0
    else:
        one_sided_weights[1:] = 2.0
    one_sided_power *= one_sided_weights

    centered = values - np.mean(values, axis=1, keepdims=True)
    centered_power = np.mean(np.abs(np.fft.fft(centered, axis=1)) ** 2, axis=0)

    total_power = float(np.sum(mean_power))
    dc_power = float(mean_power[0])
    ac_power = float(np.sum(mean_power[1:]))
    dc_share = dc_power / total_power if total_power else 0.0
    no_dc_entropy = _normalised_ac_entropy(mean_power)
    binary_dc_entropy = 0.0
    if 0.0 < dc_share < 1.0:
        binary_dc_entropy = -dc_share * math.log2(dc_share) - (
            1.0 - dc_share
        ) * math.log2(1.0 - dc_share)
    entropy_decomposition = binary_dc_entropy + (
        1.0 - dc_share
    ) * math.log2(values.shape[1] - 1) * no_dc_entropy
    eps = np.finfo(float).tiny
    arithmetic = float(np.mean(np.sqrt(mean_power) + eps))
    geometric = float(np.exp(np.mean(np.log(np.sqrt(mean_power) + eps))))

    if mean_power.size > 1:
        # Peak identity is retained only as an implementation diagnostic.  For
        # a real signal, conjugate bins are folded to the lower frequency.
        positive_limit = values.shape[1] // 2 + 1
        peak_bins = np.argmax(powers[:, 1:positive_limit], axis=1) + 1
        _, counts = np.unique(peak_bins, return_counts=True)
        peak_stability = float(np.max(counts) / len(peak_bins))
    else:
        peak_stability = 1.0

    return {
        "entropy_squared_mean_magnitude": _entropy(mean_magnitude_power),
        "entropy_mean_power": _entropy(mean_power),
        "entropy_per_trajectory_mean": float(np.mean(per_trajectory_entropy)),
        "entropy_per_trajectory_sd": float(np.std(per_trajectory_entropy, ddof=1)),
        "entropy_mean_power_one_sided_weighted": _entropy(one_sided_power),
        "entropy_no_dc_one_sided_normalized": _normalised_ac_entropy(
            one_sided_power
        ),
        "dc_share": dc_share,
        "entropy_no_dc_normalized": no_dc_entropy,
        "entropy_centered_normalized": _normalised_ac_entropy(centered_power),
        "entropy_decomposition_residual": _entropy(mean_power)
        - entropy_decomposition,
        "ac_dc_ratio": ac_power / dc_power if dc_power else math.inf,
        "mean_hamming_weight": float(np.mean(values)),
        "mean_temporal_variance": float(np.mean(np.var(values, axis=1, ddof=0))),
        "spectral_flatness_mean_power": geometric / arithmetic if arithmetic else 0.0,
        "peak_stability": peak_stability,
        "trajectory_count": float(len(trajectories)),
    }


def _key_material(master_seed: int, key_index: int) -> tuple[bytes, np.random.Generator]:
    """Derive one reproducible master key and a separate seeded RNG stream."""
    seed_material = f"stream-publication-v1:{master_seed}:{key_index}".encode()
    key = hashlib.blake2b(seed_material, digest_size=32).digest()
    seed = int.from_bytes(hashlib.blake2b(seed_material + b":rng", digest_size=8).digest(), "big")
    return key, np.random.default_rng(seed)


def _cell_for_key(
    cell: Cell, key_index: int, master_seed: int, base_states: int
) -> tuple[dict[str, float | int | str], np.ndarray]:
    key, rng = _key_material(master_seed, key_index)
    primitive_name = PRIMITIVE_NAMES[cell.family].format(depth=cell.depth)
    wrapper = build_primitive(primitive_name)
    context = PrimitiveContext(key=key, projection_method="first_128", selected_positions=[])
    trajectories: list[np.ndarray] = []

    for _ in range(base_states):
        base = rng.bytes(16)
        masks = scenario_masks(cell.family, cell.scenario)
        for mask in masks:
            left = base
            right = xor_bytes(base, mask)
            hw = np.empty(cell.trajectory_length, dtype=np.float64)
            for iteration in range(cell.trajectory_length):
                left = wrapper.iterate(left, context)
                right = wrapper.iterate(right, context)
                hw[iteration] = int.from_bytes(xor_bytes(left, right), "big").bit_count()
            trajectories.append(hw)

    row: dict[str, float | int | str] = {
        "family": cell.family,
        "depth": cell.depth,
        "scenario": cell.scenario,
        "trajectory_length": cell.trajectory_length,
        "key_index": key_index,
        "key_seed": master_seed + key_index,
        "base_states": base_states,
        "masks": len(masks),
    }
    row.update(_summarise_trajectories(trajectories))
    return row, np.asarray(trajectories, dtype=np.uint8)


def _run_cell(
    cell: Cell, keys: int, master_seed: int, base_states: int, raw_dir: Path
) -> list[dict[str, float | int | str]]:
    results = [
        _cell_for_key(cell, key_index, master_seed, base_states)
        for key_index in range(keys)
    ]
    raw = np.stack([result[1] for result in results])
    safe_family = cell.family.lower().replace("/", "").replace("-", "_")
    np.savez_compressed(
        raw_dir
        / (
            f"{safe_family}_d{cell.depth}_{cell.scenario}"
            f"_t{cell.trajectory_length}.npz"
        ),
        hamming_weight_trajectories=raw,
        key_indices=np.arange(keys, dtype=np.int16),
    )
    return [result[0] for result in results]


def _ideal_rows(
    keys: int, master_seed: int, base_states: int
) -> list[dict[str, float | int | str]]:
    rows: list[dict[str, float | int | str]] = []
    for length in TRAJECTORY_LENGTHS:
        for scenario in SCENARIO_NAMES:
            masks = scenario_masks("RC4", scenario)
            for key_index in range(keys):
                _, rng = _key_material(master_seed + 1_000_000, key_index)
                trajectories = [
                    rng.binomial(128, 0.5, size=length).astype(np.float64)
                    for _ in range(base_states * len(masks))
                ]
                row: dict[str, float | int | str] = {
                    "family": "Ideal-Random-128",
                    "depth": 0,
                    "scenario": scenario,
                    "trajectory_length": length,
                    "key_index": key_index,
                    "key_seed": master_seed + 1_000_000 + key_index,
                    "base_states": base_states,
                    "masks": len(masks),
                }
                row.update(_summarise_trajectories(trajectories))
                rows.append(row)
    return rows


def _bootstrap_mean_ci(values: np.ndarray, seed: int, replicates: int = 5000) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(values), size=(replicates, len(values)))
    means = np.mean(values[indices], axis=1)
    return float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))


def _aggregate(rows: list[dict[str, float | int | str]], master_seed: int) -> list[dict[str, float | int | str]]:
    identity = ("family", "depth", "scenario", "trajectory_length")
    metrics = [
        "entropy_squared_mean_magnitude",
        "entropy_mean_power",
        "entropy_per_trajectory_mean",
        "entropy_mean_power_one_sided_weighted",
        "entropy_no_dc_one_sided_normalized",
        "dc_share",
        "entropy_no_dc_normalized",
        "entropy_centered_normalized",
        "entropy_decomposition_residual",
        "ac_dc_ratio",
        "mean_hamming_weight",
        "mean_temporal_variance",
        "spectral_flatness_mean_power",
        "peak_stability",
    ]
    groups: dict[tuple[object, ...], list[dict[str, float | int | str]]] = {}
    for row in rows:
        groups.setdefault(tuple(row[name] for name in identity), []).append(row)

    output: list[dict[str, float | int | str]] = []
    ordered_groups = sorted(groups.items(), key=lambda item: str(item[0]))
    for group_index, (key, group) in enumerate(ordered_groups):
        summary: dict[str, float | int | str] = dict(zip(identity, key))
        summary["independent_keys"] = len(group)
        summary["base_states_per_key"] = int(group[0]["base_states"])
        summary["masks_per_base_state"] = int(group[0]["masks"])
        for metric_index, metric in enumerate(metrics):
            values = np.asarray([float(row[metric]) for row in group], dtype=np.float64)
            low, high = _bootstrap_mean_ci(
                values, master_seed + group_index * 100 + metric_index
            )
            summary[f"{metric}_mean"] = float(np.mean(values))
            summary[f"{metric}_sd_between_keys"] = float(np.std(values, ddof=1))
            summary[f"{metric}_ci_low"] = low
            summary[f"{metric}_ci_high"] = high
        output.append(summary)

    # Direct uncertainty for departures from the matched ideal control.
    # Cipher and control keys are independently resampled, avoiding artificial
    # pairing between unrelated key indices.
    control_metrics = ("entropy_mean_power", "mean_temporal_variance")
    summary_by_id = {
        tuple(summary[name] for name in identity): summary for summary in output
    }
    for group_index, (key, group) in enumerate(ordered_groups):
        family, _depth, scenario, trajectory_length = key
        if family == "Ideal-Random-128":
            continue
        ideal_key = ("Ideal-Random-128", 0, scenario, trajectory_length)
        if ideal_key not in groups:
            continue
        ideal_group = groups[ideal_key]
        summary = summary_by_id[key]
        for metric_index, metric in enumerate(control_metrics):
            cipher_values = np.asarray([float(row[metric]) for row in group])
            ideal_values = np.asarray([float(row[metric]) for row in ideal_group])
            rng = np.random.default_rng(
                master_seed + 2_000_000 + group_index * 10 + metric_index
            )
            cipher_indices = rng.integers(
                0, len(cipher_values), size=(5000, len(cipher_values))
            )
            ideal_indices = rng.integers(
                0, len(ideal_values), size=(5000, len(ideal_values))
            )
            differences = np.mean(cipher_values[cipher_indices], axis=1) - np.mean(
                ideal_values[ideal_indices], axis=1
            )
            pooled_sd = math.sqrt(
                (
                    float(np.var(cipher_values, ddof=1))
                    + float(np.var(ideal_values, ddof=1))
                )
                / 2.0
            )
            prefix = f"{metric}_delta_control"
            summary[f"{prefix}_mean"] = float(
                np.mean(cipher_values) - np.mean(ideal_values)
            )
            summary[f"{prefix}_ci_low"] = float(np.quantile(differences, 0.025))
            summary[f"{prefix}_ci_high"] = float(np.quantile(differences, 0.975))
            summary[f"{prefix}_standardized"] = (
                float(summary[f"{prefix}_mean"]) / pooled_sd if pooled_sd else 0.0
            )
    return output


def _write_csv(path: Path, rows: Iterable[dict[str, object]]) -> None:
    materialised = list(rows)
    if not materialised:
        return
    fieldnames = list(materialised[0])
    for row in materialised[1:]:
        for field in row:
            if field not in fieldnames:
                fieldnames.append(field)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(materialised)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keys", type=int, default=40)
    parser.add_argument("--base-states", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260721)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument(
        "--families",
        default="",
        help="Optional comma-separated family subset (useful for incremental reruns)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "publication_results",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = args.output_dir / "raw_trajectories"
    raw_dir.mkdir(parents=True, exist_ok=True)
    selected_families = (
        {name.strip() for name in args.families.split(",") if name.strip()}
        or set(FAMILY_DEPTHS)
    )
    unknown = selected_families - set(FAMILY_DEPTHS)
    if unknown:
        raise SystemExit(f"Unknown families: {sorted(unknown)}")
    cells = [
        Cell(family, depth, scenario, length)
        for family, depths in FAMILY_DEPTHS.items()
        if family in selected_families
        for depth in depths
        for scenario in SCENARIO_NAMES
        for length in TRAJECTORY_LENGTHS
    ]

    rows: list[dict[str, float | int | str]] = []
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(
                _run_cell, cell, args.keys, args.seed, args.base_states, raw_dir
            ): cell
            for cell in cells
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            rows.extend(future.result())
            print(f"[{completed}/{len(cells)}] {futures[future]}", flush=True)

    rows.extend(_ideal_rows(args.keys, args.seed, args.base_states))
    rows.sort(
        key=lambda row: (
            str(row["family"]),
            int(row["depth"]),
            str(row["scenario"]),
            int(row["trajectory_length"]),
            int(row["key_index"]),
        )
    )
    summaries = _aggregate(rows, args.seed)
    _write_csv(args.output_dir / "per_key_metrics.csv", rows)
    _write_csv(args.output_dir / "summary_metrics.csv", summaries)

    manifest = {
        "schema": "stream-publication-v4-scaled-masks-keys",
        "master_seed": args.seed,
        "independent_keys": args.keys,
        "masks_per_scenario_target": MASKS_PER_SCENARIO,
        "master_keys_hex": [
            _key_material(args.seed, key_index)[0].hex()
            for key_index in range(args.keys)
        ],
        "base_states_per_key": args.base_states,
        "scenarios": {
            family: {
                scenario: [mask.hex() for mask in scenario_masks(family, scenario)]
                for scenario in SCENARIO_NAMES
            }
            for family in FAMILY_DEPTHS
        },
        "trajectory_lengths": list(TRAJECTORY_LENGTHS),
        "family_depths": FAMILY_DEPTHS,
        "hierarchy": "key/seed -> base state -> mask -> trajectory",
        "raw_array_axes": ["key", "base_state_x_mask", "iteration"],
        "raw_trajectory_files": len(cells),
        "primary_configuration": {"trajectory_length": 32},
        "spectral_convention": "complete two-sided numpy.fft.fft; Parseval-consistent power",
        "one_sided_sensitivity": "numpy.fft.rfft with doubled interior-bin power",
        "temporal_variance": "population variance within trajectory (ddof=0)",
        "python": sys.version,
        "platform": platform.platform(),
        "numpy": np.__version__,
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"Wrote {len(rows)} key-level rows to {args.output_dir}")


if __name__ == "__main__":
    main()
