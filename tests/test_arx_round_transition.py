"""Independent scalar single-round checks and named operation witnesses."""

from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/stream_rounds_study"))

from arx_round_transition import (CHECKPOINTS, PANEL, changed_nonce, cohort_inputs,
                                  derivative_vertices, finalize_rounds, hw32,
                                  initial_vertex_blocks, working_rounds)
from arx_feedforward_study import initial_blocks
from extension_stream_cores import chacha20_iv_stream, salsa20_iv_stream


def _scalar_rounds(initial, family):
    """Scalar arithmetic and algebraically generated indices, independently coded."""
    x = [int(v) for v in initial]
    mask = (1 << 32)-1
    rot = lambda v, n: ((v << n) | (v >> (32-n))) & mask
    history, checkpoints = [], []
    for r in range(4):
        for j in range(4):
            if family == "ChaCha20":
                a, b, c, d = ([j+4*i for i in range(4)] if r % 2 == 0 else
                               [4*i+(j+i) % 4 for i in range(4)])
                va, vb, vc, vd = x[a], x[b], x[c], x[d]
                for p, q in ((16, 12), (8, 7)):
                    va = (va+vb) & mask
                    vd = rot(vd ^ va, p)
                    vc = (vc+vd) & mask
                    vb = rot(vb ^ vc, q)
                x[a], x[b], x[c], x[d] = va, vb, vc, vd
            else:
                ids = ([(5*j+4*i) % 16 for i in range(4)] if r % 2 == 0 else
                       [4*j+(j+i) % 4 for i in range(4)])
                a, b, c, d = ids
                va, vb, vc, vd = x[a], x[b], x[c], x[d]
                vb ^= rot((va+vd) & mask, 7)
                if r == 2 and j == 3:
                    checkpoints.append(vc)
                vc ^= rot((vb+va) & mask, 9)
                if r == 2 and j == 3:
                    checkpoints.append(vc)
                vd ^= rot((vc+vb) & mask, 13)
                va ^= rot((vd+vc) & mask, 18)
                x[a], x[b], x[c], x[d] = va, vb, vc, vd
        history.append(x.copy())
    return np.asarray(history, dtype=np.uint32), checkpoints


def test_single_round_boundaries_and_named_checkpoint_match_scalar() -> None:
    random = np.random.default_rng(314159)
    arbitrary = random.integers(0, 1 << 32, (7, 16), dtype=np.uint32)
    for family in ("ChaCha20", "Salsa20"):
        initial = np.concatenate((arbitrary, initial_blocks(bytes(range(32)), bytes(range(8)), family, 2)))
        original = initial.copy()
        actual, checkpoints = working_rounds(initial, family, (1, 2, 3, 4))
        for i, state in enumerate(initial):
            expected, scalar_checkpoints = _scalar_rounds(state, family)
            np.testing.assert_array_equal(actual[:, i], expected)
            if family == "Salsa20":
                assert [int(checkpoints[name][i]) for name in CHECKPOINTS] == scalar_checkpoints
        np.testing.assert_array_equal(initial, original)
        assert np.any(actual[2] != actual[1])
        assert np.any(actual[2] != actual[3])


def test_even_rounds_reproduce_vector_checked_streams_and_known_chacha_vector() -> None:
    for family in ("ChaCha20", "Salsa20"):
        for key, nonce in ((bytes(32), bytes(8)), (bytes(range(32)), bytes(range(8)))):
            initial = initial_blocks(key, nonce, family, 2)
            working, _ = working_rounds(initial, family, (2, 4, 20))
            finalized = finalize_rounds(working, initial)
            for ri, r in enumerate((2, 4, 20)):
                expected = (chacha20_iv_stream(key, bytes(4)+nonce, r, 128) if family == "ChaCha20"
                            else salsa20_iv_stream(key, nonce, r, 128))
                assert finalized[ri, 0].astype("<u4").tobytes() == expected
    initial = initial_blocks(bytes(32), bytes(8), "ChaCha20", 1)
    working, _ = working_rounds(initial, "ChaCha20", (20,))
    actual = finalize_rounds(working, initial)[0, 0].astype("<u4").tobytes()
    assert actual[:16].hex() == "76b8e0ada0f13d90405d6ae55386bd28"


def test_vector_vertex_derivatives_and_nonce_mapping_match_explicit_xor() -> None:
    _, bases, vertices = cohort_inputs(1480)
    assert len(set(vertices)) == 412
    for bi, base in enumerate(bases):
        assert vertices[103*bi] == base
        for pi, panel in enumerate(PANEL):
            assert vertices[103*bi+65+pi] == changed_nonce(base, tuple(panel["bits_msb_first"]))
    random = np.random.default_rng(271828)
    values = random.integers(0, 1 << 32, (2, 3, 412, 16, 16), dtype=np.uint32)
    for order in (1, 2):
        actual = derivative_vertices(values, order)
        count = 64 if order == 1 else 38
        for bi in range(4):
            base = 103*bi
            for pi in range(count):
                if order == 1:
                    expected = values[..., base, :, :] ^ values[..., base+1+pi, :, :]
                else:
                    a, b = PANEL[pi]["bits_msb_first"]
                    expected = (values[..., base, :, :] ^ values[..., base+a+1, :, :]
                                ^ values[..., base+b+1, :, :] ^ values[..., base+65+pi, :, :])
                np.testing.assert_array_equal(actual[..., pi, bi, :, :], expected)
    for family in ("ChaCha20", "Salsa20"):
        initial = initial_vertex_blocks(bytes(range(32)), vertices, family)
        for position in (0, 103, 411):
            np.testing.assert_array_equal(initial[position], initial_blocks(bytes(range(32)), vertices[position], family))


def test_named_salsa_checkpoint_derivatives_preserve_two_round_zero() -> None:
    _, _, vertices = cohort_inputs(1481)
    initial = initial_vertex_blocks(bytes(range(32)), vertices, "Salsa20")
    states, checkpoints = working_rounds(initial, "Salsa20")
    np.testing.assert_array_equal(checkpoints[CHECKPOINTS[0]], states[0, ..., 7])
    np.testing.assert_array_equal(checkpoints[CHECKPOINTS[1]], states[1, ..., 7])
    derivatives = derivative_vertices(finalize_rounds(states, initial), 2)
    np.testing.assert_array_equal(derivatives[:, 1], derivatives[:, 2])
    assert not derivatives[0, :, 36:38, ..., 7].any()
    for ci, name in enumerate(CHECKPOINTS):
        embedded = np.zeros_like(initial)
        embedded[..., 7] = checkpoints[name]
        checkpoint = derivative_vertices(embedded, 2)[36:38, ..., 7]
        np.testing.assert_array_equal(checkpoint, derivatives[ci, 1, 36:38, ..., 7])
    # No assertion about whether the empirical third-round derivatives are zero.


def test_hw32_counts_bits_before_aggregation() -> None:
    values = np.asarray([[0, 1, 3, 0x80000000, 0xFFFFFFFF]], dtype=np.uint32)
    np.testing.assert_array_equal(hw32(values), [[0, 1, 2, 1, 32]])
    noncontiguous = np.tile(values, (2, 1)).T
    expected = np.asarray([[int(v).bit_count() for v in row] for row in noncontiguous], dtype=np.uint8)
    np.testing.assert_array_equal(hw32(noncontiguous), expected)
