#!/usr/bin/env python3
"""Generate fresh-key, graph-matched data for the locked mask follow-up."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path
import sys
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream
from publication_study import _key_material
from spectral_crypto_analyzer.primitives import _grain128_keystream_128, _trivium_keystream_128


PROTOCOL = ROOT / "doc_stream_ciphers" / "MASK_LITERATURE_FOLLOWUP_PROTOCOL.txt"
OUT = ROOT / "doc_stream_ciphers" / "data" / "literature_mask_followup"
SEED = 20260721
ARX_INDICES = tuple(range(520, 600))
SECONDARY_INDICES = tuple(range(600, 680))
ARX_FAMILIES = ("ChaCha20", "Salsa20")
ARX_ROUNDS = (2, 4, 6, 8, 20)
TRIVIUM_CLOCKS = (192, 384, 768, 1152)
TRIVIUM_DEGREES = (2, 4, 6)
GRAIN_CLOCKS = (0, 32, 64, 256)
GRAIN_BITS = (0, 32, 63, 64, 65, 95)
POPCOUNT = np.asarray([i.bit_count() for i in range(256)], dtype=np.uint8)


def _digest(label: bytes, master: bytes, n: int) -> bytes:
    return hashlib.blake2b(label + master, digest_size=n).digest()


def _xor_nonce(base: bytes, bit: int) -> bytes:
    """Flip one nonce bit, numbered most-significant-bit first."""
    data = bytearray(base)
    data[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(data)


def _xor_iv_lsb(base: bytes, positions: tuple[int, ...]) -> bytes:
    """Flip one or more Trivium IV bits in its LSB-first convention."""
    data = bytearray(base)
    for bit in positions:
        data[bit // 8] ^= 1 << (bit % 8)
    return bytes(data)


def _word_hw(left: bytes, right: bytes) -> np.ndarray:
    """Count changed bits in each 32-bit word of eight 512-bit output blocks."""
    if len(left) != 512 or len(right) != 512:
        raise AssertionError("Expected 512-byte streams")
    x = np.bitwise_xor(np.frombuffer(left, dtype=np.uint8), np.frombuffer(right, dtype=np.uint8))
    return POPCOUNT[x].reshape(8, 16, 4).sum(axis=-1, dtype=np.uint8)


def _trajectory_hw(left: bytes, right: bytes) -> np.ndarray:
    return _word_hw(left, right).reshape(8, 4, 4).sum(axis=-1, dtype=np.uint8).reshape(32)


def _oracle(domain: bytes, secret: bytes, config: int, iv: bytes, length: int) -> bytes:
    payload = domain + secret + config.to_bytes(2, "big") + iv
    return hashlib.shake_256(payload).digest(length)


def _arx_one(key_index: int) -> tuple[np.ndarray, np.ndarray]:
    """Collect observed and matched-control output-word HW for all nonce bits.

    Both cores use the same four 64-bit base nonces. The returned arrays keep
    cipher, round, mask, base-nonce, block, and output-word structure.
    """
    master, _ = _key_material(SEED, key_index)
    nonce_material = hashlib.shake_256(b"litmask-common-nonce-v1:" + master).digest(32)
    bases = tuple(nonce_material[8 * i:8 * (i + 1)] for i in range(4))
    others = tuple(tuple(_xor_nonce(base, bit) for bit in range(64)) for base in bases)
    vertices = set(bases)
    vertices.update(iv for group in others for iv in group)
    if len(vertices) != 4 * 65:
        raise AssertionError(f"Nonce-star collision at key {key_index}")
    actual = np.empty((2, 5, 64, 4, 8, 16), dtype=np.uint8)
    control = np.empty_like(actual)
    for family_index, family in enumerate(ARX_FAMILIES):
        label = family.encode()
        key = _digest(b"litmask-arx-key-v1:" + label + b":", master, 32)
        secret = _digest(b"litmask-arx-oracle-secret-v1:" + label + b":", master, 32)
        cipher = chacha20_iv_stream if family == "ChaCha20" else salsa20_iv_stream
        for round_index, rounds in enumerate(ARX_ROUNDS):
            base_streams = [cipher(key, (b"\0" * 4 + base) if family == "ChaCha20" else base,
                                   rounds, 512) for base in bases]
            base_oracles = [_oracle(b"litmask-arx-oracle-v1:" + label + b":", secret,
                                    rounds, base, 512) for base in bases]
            for base_index, group in enumerate(others):
                for bit, other in enumerate(group):
                    stream = cipher(key, (b"\0" * 4 + other) if family == "ChaCha20" else other,
                                    rounds, 512)
                    null = _oracle(b"litmask-arx-oracle-v1:" + label + b":", secret,
                                   rounds, other, 512)
                    actual[family_index, round_index, bit, base_index] = _word_hw(
                        base_streams[base_index], stream)
                    control[family_index, round_index, bit, base_index] = _word_hw(
                        base_oracles[base_index], null)
    return actual, control


def _cube_vertices(base: bytes, degree: int) -> tuple[bytes, ...]:
    positions = tuple(3 * i for i in range(degree))
    return tuple(_xor_iv_lsb(base, tuple(positions[i] for i in range(degree) if mask & (1 << i)))
                 for mask in range(1 << degree))


def _trivium_one(key_index: int) -> tuple[np.ndarray, np.ndarray]:
    """Measure higher-order Trivium IV subcubes on one independent key."""
    master, _ = _key_material(SEED, key_index)
    key = _digest(b"litmask-trivium-key-v1:", master, 10)
    secret = _digest(b"litmask-trivium-oracle-secret-v1:", master, 32)
    blank = bytes(10)
    bases = (blank, _xor_iv_lsb(blank, (72,)), _xor_iv_lsb(blank, (75,)),
             _xor_iv_lsb(blank, (78,)))
    groups = {(di, bi): _cube_vertices(base, degree)
              for di, degree in enumerate(TRIVIUM_DEGREES) for bi, base in enumerate(bases)}
    vertices = set(iv for group in groups.values() for iv in group)
    if len(vertices) != 4 * 64:
        raise AssertionError("Trivium cube vertices are not the expected four disjoint 6-cubes")
    actual = np.empty((4, 3, 4, 64), dtype=np.uint8)
    control = np.empty_like(actual)
    for clock_index, clocks in enumerate(TRIVIUM_CLOCKS):
        actual_streams = {iv: _trivium_keystream_128(key, iv, clocks, 512) for iv in vertices}
        null_streams = {iv: _oracle(b"litmask-trivium-oracle-v1:", secret, clocks, iv, 64)
                        for iv in vertices}
        for (degree_index, base_index), group in groups.items():
            for target, streams in ((actual, actual_streams), (control, null_streams)):
                derivative = 0
                for iv in group:
                    derivative ^= int.from_bytes(streams[iv], "little")
                target[clock_index, degree_index, base_index] = np.frombuffer(
                    derivative.to_bytes(64, "little"), dtype=np.uint8)
    return actual, control


def _grain_one(key_index: int) -> tuple[np.ndarray, np.ndarray]:
    """Measure selected Grain-128 IV positions across initialization depths."""
    master, _ = _key_material(SEED, key_index)
    key = _digest(b"litmask-grain-key-v1:", master, 16)
    secret = _digest(b"litmask-grain-oracle-secret-v1:", master, 32)
    material = hashlib.shake_256(b"litmask-grain-ivs-v1:" + master).digest(48)
    bases = tuple(material[12 * i:12 * (i + 1)] for i in range(4))
    others = tuple(tuple(_xor_nonce(base, bit) for bit in GRAIN_BITS) for base in bases)
    vertices = set(bases)
    vertices.update(iv for group in others for iv in group)
    if len(vertices) != 4 * (1 + len(GRAIN_BITS)):
        raise AssertionError(f"Grain IV-star collision at key {key_index}")
    actual = np.empty((4, 6, 4, 32), dtype=np.uint8)
    control = np.empty_like(actual)
    for clock_index, clocks in enumerate(GRAIN_CLOCKS):
        base_streams = [_grain128_keystream_128(key, base, clocks, 4096) for base in bases]
        base_oracles = [_oracle(b"litmask-grain-oracle-v1:", secret, clocks, base, 512)
                        for base in bases]
        for base_index, group in enumerate(others):
            for bit_index, other in enumerate(group):
                stream = _grain128_keystream_128(key, other, clocks, 4096)
                null = _oracle(b"litmask-grain-oracle-v1:", secret, clocks, other, 512)
                actual[clock_index, bit_index, base_index] = _trajectory_hw(
                    base_streams[base_index], stream)
                control[clock_index, bit_index, base_index] = _trajectory_hw(
                    base_oracles[base_index], null)
    return actual, control


def _run(section: str, indices: tuple[int, ...], worker, workers: int, directory: Path) -> None:
    """Run one study section in parallel and save its raw observed/control arrays."""
    start = perf_counter()
    observed = []
    oracle = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for done, (a, b) in enumerate(pool.map(worker, indices, chunksize=1), 1):
            observed.append(a)
            oracle.append(b)
            if done % 10 == 0 or done == len(indices):
                print(f"{section}: {done}/{len(indices)} keys, {perf_counter()-start:.1f}s", flush=True)
    path = directory / f"{section}_raw.npz"
    np.savez_compressed(path, observed=np.stack(observed), oracle=np.stack(oracle),
                        key_indices=np.asarray(indices, dtype=np.int32))
    print(f"saved {path}, {path.stat().st_size} bytes", flush=True)


def main() -> None:
    """Generate the independent ARX, Trivium, and Grain mask cohorts."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--section", choices=("arx", "trivium", "grain", "all"), default="all")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--smoke", action="store_true", help="two keys, output to /tmp")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")
    directory = Path("/tmp/literature_mask_followup_smoke") if args.smoke else OUT
    directory.mkdir(parents=True, exist_ok=True)
    protocol_hash = hashlib.sha256(PROTOCOL.read_bytes()).hexdigest()
    selected = ("arx", "trivium", "grain") if args.section == "all" else (args.section,)
    for section in selected:
        if section == "arx":
            _run(section, ARX_INDICES[:2] if args.smoke else ARX_INDICES,
                 _arx_one, args.workers, directory)
        elif section == "trivium":
            _run(section, SECONDARY_INDICES[:2] if args.smoke else SECONDARY_INDICES,
                 _trivium_one, args.workers, directory)
        else:
            _run(section, SECONDARY_INDICES[:2] if args.smoke else SECONDARY_INDICES,
                 _grain_one, args.workers, directory)
    if not args.smoke:
        manifest = {
            "protocol": str(PROTOCOL.relative_to(ROOT)), "protocol_sha256": protocol_hash,
            "source": str(Path(__file__).relative_to(ROOT)), "master_seed": SEED,
            "arx_key_indices": [ARX_INDICES[0], ARX_INDICES[-1]],
            "secondary_key_indices": [SECONDARY_INDICES[0], SECONDARY_INDICES[-1]],
            "arx_families": ARX_FAMILIES, "arx_rounds": ARX_ROUNDS,
            "trivium_clocks": TRIVIUM_CLOCKS, "trivium_degrees": TRIVIUM_DEGREES,
            "grain_clocks": GRAIN_CLOCKS, "grain_bits_msb_first": GRAIN_BITS,
            "raw_sha256": {name: hashlib.sha256((directory / f"{name}_raw.npz").read_bytes()).hexdigest()
                           for name in ("arx", "trivium", "grain")
                           if (directory / f"{name}_raw.npz").exists()},
        }
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
