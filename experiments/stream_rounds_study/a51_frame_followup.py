#!/usr/bin/env python3
"""Fresh-key A5/1 frame-difference study; protocol is fixed separately."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import sys
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from spectral_crypto_analyzer.primitives import _a5_1_keystream_128  # noqa: E402

PROTOCOL = ROOT / "doc_stream_ciphers" / "A51_KNOWN_WEAKNESS_PROTOCOL.txt"
OUT = ROOT / "doc_stream_ciphers" / "data" / "a51_frame_followup"
SEED = 20261013
INDICES = tuple(range(680, 760))
DEPTHS = (0, 20, 40, 60, 80, 100)
MASKS = tuple(1 << bit for bit in range(22))
FRAME_MASK = (1 << 22) - 1


def _master(index: int) -> bytes:
    return hashlib.shake_256(f"a51-frame-study|{SEED}|{index}".encode()).digest(32)


def _bases(master: bytes) -> tuple[int, ...]:
    """Derive four frame numbers whose 22-mask IV stars do not overlap."""
    result: list[int] = []
    vertices: set[int] = set()
    candidate = 0
    while len(result) < 4:
        raw = hashlib.shake_256(b"a51-base-frame|" + master + candidate.to_bytes(4, "big")).digest(4)
        frame = int.from_bytes(raw, "big") & FRAME_MASK
        star = {frame} | {frame ^ mask for mask in MASKS}
        if not (star & vertices):
            result.append(frame)
            vertices.update(star)
        candidate += 1
        if candidate > 10000:
            raise AssertionError("Could not generate four disjoint frame stars")
    if len(vertices) != 4 * (1 + len(MASKS)):
        raise AssertionError("Frame-star collision")
    return tuple(result)


def _first_114(data: bytes) -> np.ndarray:
    """Keep the GSM frame's first 114 bits in 15 bytes; clear six unused bits."""
    out = np.frombuffer(data[:15], dtype=np.uint8).copy()
    out[-1] &= 0xC0
    return out


def _one(index: int) -> tuple[int, bytes, tuple[int, ...], np.ndarray, np.ndarray]:
    """Generate frame XORs for one key at six A5/1 warm-up settings."""
    master = _master(index)
    key = hashlib.shake_256(b"a51-key|" + master).digest(8)
    secret = hashlib.shake_256(b"a51-control-secret|" + master).digest(32)
    bases = _bases(master)
    frames = sorted({frame for base in bases for frame in ((base,) + tuple(base ^ m for m in MASKS))})
    observed = np.empty((len(DEPTHS), len(MASKS), 4, 15), dtype=np.uint8)
    control = np.empty_like(observed)
    for d_index, depth in enumerate(DEPTHS):
        obs_stream = {frame: _first_114(_a5_1_keystream_128(key, frame, depth))
                      for frame in frames}
        ctrl_stream = {frame: _first_114(hashlib.shake_256(
            b"a51-control|" + secret + depth.to_bytes(2, "big") + frame.to_bytes(4, "big")
        ).digest(15)) for frame in frames}
        for m_index, mask in enumerate(MASKS):
            for b_index, base in enumerate(bases):
                observed[d_index, m_index, b_index] = obs_stream[base] ^ obs_stream[base ^ mask]
                control[d_index, m_index, b_index] = ctrl_stream[base] ^ ctrl_stream[base ^ mask]
    return index, key, bases, observed, control


def _published_vector() -> None:
    """Check the first 114 output bits against a published A5/1 vector."""
    actual = _a5_1_keystream_128(bytes.fromhex("1223456789abcdef"), 0x134, 100)
    expected = bytes.fromhex("534eaa582fe8151ab6e1855a728c00")
    if actual[:14] != expected[:14] or (actual[14] & 0xC0) != (expected[14] & 0xC0):
        raise AssertionError("A5/1 published 114-bit vector mismatch")


def main() -> None:
    """Save the locked A5/1 screen; ``--smoke`` writes a two-key trial to /tmp."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--smoke", action="store_true", help="two keys, output to /tmp")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")
    _published_vector()
    indices = INDICES[:2] if args.smoke else INDICES
    directory = Path("/tmp/a51_frame_followup_smoke") if args.smoke else OUT
    directory.mkdir(parents=True, exist_ok=True)
    records = []
    start = perf_counter()
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_one, index): index for index in indices}
        for future in as_completed(futures):
            records.append(future.result())
            if len(records) % 10 == 0 or len(records) == len(indices):
                print(f"A5/1: {len(records)}/{len(indices)} keys, {perf_counter()-start:.1f}s", flush=True)
    records.sort(key=lambda item: item[0])
    raw = directory / "a51_frame_raw.npz"
    np.savez_compressed(
        raw, key_indices=np.asarray([row[0] for row in records], dtype=np.int32),
        keys=np.asarray([np.frombuffer(row[1], dtype=np.uint8) for row in records]),
        bases=np.asarray([row[2] for row in records], dtype=np.uint32),
        depths=np.asarray(DEPTHS, dtype=np.int16),
        masks=np.asarray(MASKS, dtype=np.uint32),
        observed=np.stack([row[3] for row in records]),
        control=np.stack([row[4] for row in records]),
    )
    manifest = {
        "protocol": str(PROTOCOL.relative_to(ROOT)),
        "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
        "source": str(Path(__file__).relative_to(ROOT)),
        "master_seed": SEED,
        "key_indices": [int(indices[0]), int(indices[-1])],
        "depths": DEPTHS,
        "frame_mask_bits": 22,
        "bases_per_key": 4,
        "output_bits": 114,
        "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {raw} ({raw.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
