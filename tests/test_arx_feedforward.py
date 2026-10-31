"""Independent finalization and mixed-derivative checks, without cohort data."""

from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))

from arx_feedforward_study import (changed_nonce, difference_hw, finalized_words,
                                  finalize, initial_blocks, global_bit, PANEL, lb)
from arx_mechanism_analysis import evaluate


def test_finalizations_match_independent_working_state_at_two_and_four_rounds() -> None:
    for family in ("ChaCha20", "Salsa20"):
        for key, nonce in ((bytes(32), bytes(8)), (bytes(range(32)), bytes(range(8)))):
            initial = initial_blocks(key, nonce, family, 2)
            for rounds in (2, 4):
                reference = []
                for state in initial:
                    working = list(map(int, state))
                    for _ in range(rounds // 2):
                        working = evaluate(working, family)[1]
                    reference.append(working)
                reference = np.asarray(reference, dtype=np.uint32)
                actual = finalized_words(key, nonce, family, rounds, 2)
                np.testing.assert_array_equal(actual[1], reference)
                np.testing.assert_array_equal(actual, finalize(reference, initial))


def test_modular_finalization_wraps_without_changing_working_state() -> None:
    working = np.full((2, 16), 0xFFFFFFFF, dtype=np.uint32)
    initial = np.ones((2, 16), dtype=np.uint32)
    variants = finalize(working, initial)
    assert np.all(variants[0] == 0)
    assert np.all(variants[1] == 0xFFFFFFFF)
    assert np.all(variants[2] == 0xFFFFFFFE)
    assert np.all(working == 0xFFFFFFFF)


def test_mixed_derivative_counts_xor_before_hamming_weights() -> None:
    vertices = [np.full((3, 2, 16), value, dtype=np.uint32) for value in (0, 3, 5, 6)]
    assert not difference_hw(*vertices).any()
    vertices[-1][2, 1, 9] ^= np.uint32(1 << 31)
    expected = np.zeros((3, 2, 16), dtype=np.uint8)
    expected[2, 1, 9] = 1
    np.testing.assert_array_equal(difference_hw(*vertices), expected)
    assert np.all(difference_hw(vertices[0], vertices[1]) == 2)


def test_nonce_masks_have_expected_little_endian_state_bits() -> None:
    assert int.from_bytes(changed_nonce(bytes(8), (56,))[4:], "little") == 1 << 31
    cross = changed_nonce(bytes(8), (24, 56))
    assert int.from_bytes(cross[:4], "little") == int.from_bytes(cross[4:], "little") == 1 << 31


def test_fixed_panel_has_38_distinct_pairs_and_103_vertices() -> None:
    masks = [tuple(pair["bits_msb_first"]) for pair in PANEL]
    assert len(masks) == len(set(tuple(sorted(x)) for x in masks)) == 38
    base = bytes(8)
    vertices = {base, *(changed_nonce(base, (bit,)) for bit in range(64)),
                *(changed_nonce(base, pair) for pair in masks)}
    assert len(vertices) == 103
    for b in range(32):
        assert PANEL[b]["bits_msb_first"] == [global_bit(0, b), global_bit(1, b)]


def test_salsa_second_nonce_word_identities_on_fixed_known_inputs() -> None:
    key, nonce = bytes(range(32)), bytes(range(8))
    base = finalized_words(key, nonce, "Salsa20", 2, 2)
    c = base[1, :, 7] ^ np.uint32(int.from_bytes(nonce[4:], "little"))
    for bit in (0, 7, 15, 30, 31):
        other = finalized_words(key, changed_nonce(nonce, (global_bit(1, bit),)), "Salsa20", 2, 2)
        derivative = base[..., 7] ^ other[..., 7]
        np.testing.assert_array_equal(derivative[0], lb(c, bit))
        assert np.all(derivative[1] == np.uint32(1 << bit))
        assert np.all(derivative[2] == 0)
        if bit == 31:
            assert not derivative[0].any()
