"""Scores do not depend on the Python version, and out-of-range metadata is handled, not raised.

* ``statistics.pstdev`` became correctly rounded in Python 3.11, so on 3.10 the latency jitter,
  and with it ``congestion_signature``, differed in the last bit for some inputs. The windows in
  ``DIVERGENT_WINDOWS`` are synthetic latency windows on which 3.10's ``statistics.pstdev``
  returned the second hex value; the first is the correctly rounded one, which every version
  must now produce.
* ``math.isfinite(10**400)`` raises ``OverflowError``. Validation accepts such ints (as the
  pydantic reference did), and scoring then crashed. They are now treated like non-finite
  metadata: missing.
"""

from __future__ import annotations

import math
import random
import statistics
import sys
from fractions import Fraction

import pytest

from lionlock.anomaly import detector
from lionlock.core import numeric, scoring
from lionlock.core.numeric import is_finite, pstdev
from lionlock.core.scoring import score_payload

BASE = {"prompt": "What is the capital of France?", "response": "The capital of France is Paris."}
HUGE = 10**400

# (window, correctly rounded pstdev, what Python 3.10's statistics.pstdev returned)
DIVERGENT_WINDOWS = [
    ([80.0, 300.0, 120.0], "0x1.7ebd196c74ae9p+6", "0x1.7ebd196c74ae8p+6"),
    ([503.0, 672.0, 403.0, 462.0, 456.0, 60.0], "0x1.6ffdae5e97ec9p+7", "0x1.6ffdae5e97ecap+7"),
    ([3.0, 121.0, 246.0, 785.0, 598.0, 735.0], "0x1.30d4933e9a99cp+8", "0x1.30d4933e9a99dp+8"),
    ([405.0, 814.0, 786.0, 195.0, 576.0], "0x1.d35171582e01fp+7", "0x1.d35171582e01ep+7"),
    ([499.0, 214.0, 419.0], "0x1.e017b3901fbebp+6", "0x1.e017b3901fbeap+6"),
]


def _correctly_rounded(data: list[float], result: float) -> bool:
    """Independent of the standard library: sqrt(variance) lies in result's rounding interval."""
    xs = [Fraction(x) for x in data]
    mean = sum(xs) / len(xs)
    variance = sum((x - mean) ** 2 for x in xs) / len(xs)
    exact = Fraction(result)
    low = (exact + Fraction(math.nextafter(result, -math.inf))) / 2 if result > 0 else Fraction(0)
    high = (exact + Fraction(math.nextafter(result, math.inf))) / 2
    if low * low == variance or high * high == variance:  # a tie: the even neighbour wins
        return result.hex().split("p")[0][-1] in "02468ace"
    return low * low <= variance <= high * high


@pytest.mark.parametrize(("window", "expected", "old_310"), DIVERGENT_WINDOWS)
def test_pstdev_is_correctly_rounded_where_python_310_was_not(
    window: list[float], expected: str, old_310: str
) -> None:
    assert pstdev(window).hex() == expected
    assert expected != old_310
    assert _correctly_rounded(window, pstdev(window))
    mean = sum(window) / len(window)
    assert scoring._latency_jitter_score(window) == min(1.0, float.fromhex(expected) / mean)


def _random_data(rng: random.Random, case: int) -> list[float | int]:
    kind = case % 6
    count = rng.randint(1, 10)
    if kind == 0:
        return [float(rng.randrange(900)) for _ in range(count)]
    if kind == 1:
        return [rng.uniform(0.0, 1000.0) for _ in range(count)]
    if kind == 2:
        return [
            rng.choice((-1, 1)) * math.ldexp(rng.random(), rng.randint(-1074, 1000))
            for _ in range(count)
        ]
    if kind == 3:
        base = rng.uniform(1.0, 1000.0)
        return [base + rng.randint(-4, 4) * math.ulp(base) for _ in range(count)]
    if kind == 4:
        return [math.ldexp(rng.randrange(1 << 16), -1074) for _ in range(count)]
    return [rng.randint(-(10**12), 10**12) for _ in range(count)]


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="statistics.pstdev is correctly rounded from 3.11"
)
def test_pstdev_matches_the_standard_library_bit_for_bit() -> None:
    rng = random.Random(20261118)
    for case in range(20_000):
        data = _random_data(rng, case)
        assert pstdev(data).hex() == float(statistics.pstdev(data)).hex(), data


def test_pstdev_is_correctly_rounded_on_any_version() -> None:
    rng = random.Random(7)
    for case in range(1_500):
        data = _random_data(rng, case)
        assert _correctly_rounded(data, pstdev(data)), data


def test_pstdev_edge_cases() -> None:
    assert pstdev([5.0]) == 0.0
    assert pstdev([2.0, 2.0, 2.0]) == 0.0
    # Exactly half the smallest subnormal: a tie, rounded to the even neighbour, 0.0.
    assert pstdev([0.0, 5e-324]) == 0.0
    assert _correctly_rounded([0.0, 5e-324], 0.0)
    assert pstdev([0.0, 2e-323]) == 1e-323
    assert pstdev([-1.7976931348623157e308, 1.7976931348623157e308]) == 1.7976931348623157e308
    for bad in ([], [float("nan")], [1.0, float("inf")], [1.0, HUGE]):
        with pytest.raises(ValueError):
            pstdev(bad)
    with pytest.raises(TypeError):
        pstdev([True, 1.0])


def test_is_finite_reports_ints_beyond_float_range_as_non_finite() -> None:
    assert is_finite(10**300) and is_finite(1.5) and not is_finite(float("nan"))
    assert not is_finite(HUGE) and not is_finite(-HUGE)
    assert numeric.is_finite(0)


@pytest.mark.parametrize(
    ("key", "huge", "non_finite_twin"),
    [
        pytest.param("entropy_decay", HUGE, float("nan"), id="entropy_decay"),
        pytest.param("drift_slope", -HUGE, float("inf"), id="drift_slope"),
        pytest.param("duration_ms", HUGE, float("inf"), id="duration_ms"),
        pytest.param("turn_index", HUGE, None, id="turn_index"),
    ],
)
def test_huge_int_metadata_is_missing_like_non_finite_metadata(
    key: str, huge: int, non_finite_twin: float | None
) -> None:
    metadata = {"entropy_decay": 0.4, "drift_slope": 0.2, "turn_index": 7, "duration_ms": 900.0}
    bundle = score_payload({**BASE, "metadata": {**metadata, key: huge}})
    assert bundle is not None
    assert key in bundle.missing_inputs
    if non_finite_twin is None:  # turn_index cannot be a float, so compare with it absent
        twin = {k: v for k, v in metadata.items() if k != key}
    else:
        twin = {**metadata, key: non_finite_twin}
    assert bundle == score_payload({**BASE, "metadata": twin})


def test_huge_int_latency_entry_is_dropped_like_a_non_finite_one() -> None:
    bundle = score_payload({**BASE, "metadata": {"latency_window_stats": [HUGE, 120.0, 180.0]}})
    twin = score_payload({**BASE, "metadata": {"latency_window_stats": [math.inf, 120.0, 180.0]}})
    plain = score_payload({**BASE, "metadata": {"latency_window_stats": [120.0, 180.0]}})
    assert bundle is not None and bundle == twin == plain
    only_huge = score_payload({**BASE, "metadata": {"latency_window_stats": [HUGE]}})
    assert only_huge is not None and "latency_window_stats" in only_huge.missing_inputs


def test_anomaly_detector_handles_huge_ints_like_non_finite_values() -> None:
    assert detector._latency_jitter_score([HUGE, 120.0, 180.0]) == detector._latency_jitter_score(
        [120.0, 180.0]
    )
    assert detector._safe_float(HUGE) is None
    assert detector._safe_int(HUGE) is None
