"""Exact algebra, independent elimination, and corrupted-observation checks."""

from pathlib import Path
import sys

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/stream_rounds_study"))

from arx_affine_corollary import (check_base_observations, direct_columns,
                                 exhaustive_small_words, f_c, gf2_rank,
                                 rank_formula, trailing_ones, weight_sum_formula)


def test_elimination_handles_dependent_columns_without_a_cipher_formula() -> None:
    assert gf2_rank([0b001, 0b010, 0b011, 0b100, 0b111, 0]) == 3
    assert gf2_rank([0, 0, 0]) == 0
    assert gf2_rank([1 << bit for bit in range(32)]) == 32


def test_exhaustive_maps_match_affine_reconstruction_rank_and_image_size() -> None:
    result = exhaustive_small_words(8)
    assert result["constants_checked"] == 510
    assert result["input_constant_pairs_checked"] == 87380
    assert result["image_cardinalities_checked"] == 510
    assert result["violations"] == 0


def test_same_mean_hw_can_have_rank_31_or_1() -> None:
    columns_full = direct_columns(0)
    columns_one = direct_columns(0xFFFFFFFE)
    assert gf2_rank(columns_full) == rank_formula(0) == 31
    assert gf2_rank(columns_one) == rank_formula(0xFFFFFFFE) == 1
    assert sum(c.bit_count() for c in columns_full) == sum(c.bit_count() for c in columns_one) == 31
    assert columns_one[0] == 0xFFFFFFFE
    assert not any(columns_one[1:])


def test_full_width_singletons_are_independent_of_base_u_and_obey_bound() -> None:
    for c in (0, 1, 7, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xAAAAAAAA):
        columns = direct_columns(c)
        for u in (0, 0xFFFFFFFF, 0x12345678, 0x80000001):
            differences = tuple(f_c(u ^ (1 << bit), c) ^ f_c(u, c) for bit in range(32))
            assert differences == columns
        assert columns[31] == 0
        assert sum(value.bit_count() for value in columns) == weight_sum_formula(c) <= 31
        assert gf2_rank(columns) == rank_formula(c)


def test_trailing_ones_includes_the_all_ones_boundary() -> None:
    assert trailing_ones(0) == 0
    assert trailing_ones(7) == 3
    assert trailing_ones(0x7FFFFFFF) == 31
    assert trailing_ones(0xFFFFFFFF) == 32
    assert weight_sum_formula(0x7FFFFFFF) == weight_sum_formula(0xFFFFFFFF) == 0


def test_observation_audit_rejects_one_corrupted_uint32_column() -> None:
    constants = np.asarray([[0, 0xFFFFFFFE], [0xAAAAAAAA, 7]], dtype=np.uint32)
    u = 0x13579BDF
    observed = np.asarray([[f_c(u ^ (1 << bit), int(c)) ^ f_c(u, int(c))
                            for bit in range(32)] for c in constants.flat], dtype=np.uint32).reshape(2, 2, 32)
    assert len(check_base_observations(constants, observed)) == 4
    observed[1, 0, 9] ^= np.uint32(1)
    with pytest.raises(AssertionError, match="Stored singleton column mismatch"):
        check_base_observations(constants, observed)


def test_incorrect_observation_shape_is_rejected() -> None:
    with pytest.raises(ValueError, match="32-column"):
        check_base_observations(np.zeros(2, dtype=np.uint32), np.zeros((2, 31), dtype=np.uint32))
