import math

import pytest

from evaluation.metrics import wilson


def test_all_successes_has_a_lower_bound_below_one():
    low, high = wilson(22, 22)
    assert low == pytest.approx(0.8513, abs=1e-3)
    assert high == pytest.approx(1.0)


def test_no_successes_has_an_upper_bound_above_zero():
    low, high = wilson(0, 10)
    assert low == pytest.approx(0.0, abs=1e-9)
    assert high == pytest.approx(0.2775, abs=1e-3)


def test_half_is_centered_on_one_half():
    low, high = wilson(5, 10)
    assert low + high == pytest.approx(1.0)


def test_empty_sample_is_not_a_number():
    assert all(math.isnan(x) for x in wilson(0, 0))