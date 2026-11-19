"""Numeric helpers whose results are the same on every supported Python version.

``statistics.pstdev`` is not: Python 3.11 made it correctly rounded, so 3.10 returns a different
last bit for some inputs, and a score built on it then differs between interpreters. ``pstdev``
here computes the population variance exactly in integer arithmetic and rounds its square root
once, so its result is the correctly rounded value on every version. That is the same value
``statistics.pstdev`` returns for float input on Python 3.11 and later.

Method. A finite float is an integer multiple of a power of two, so with the smallest such power
``2**-e`` shared by all inputs each input becomes an integer ``X_i``. With ``S = sum X_i`` and
``Q = sum X_i**2`` the population variance is exactly ``(n*Q - S*S) / (n * 2**e)**2``. The square
root of that fraction is rounded with *round-to-odd*: truncate it to an integer of at least 60
bits after scaling by a power of two, and set the lowest bit when the truncation was inexact.
Rounding a round-to-odd value that carries at least two more bits than the target precision to
nearest gives the same result as rounding the exact value to nearest (S. Boldo and G. Melquiond,
"Emulation of FMA and correctly-rounded sums: proved algorithms using rounding to odd", IEEE
Transactions on Computers 57(4), 2008). The final rounding to nearest is Python's ``int / int``
true division, which CPython rounds correctly, subnormal results included.
"""

from __future__ import annotations

import math
from typing import Iterable

# Bits kept before the final rounding: comfortably more than float's 53 plus the 2 guard bits the
# round-to-odd argument needs.
_GUARD_BITS = 60


def is_finite(value: int | float) -> bool:
    """``math.isfinite`` for ints and floats, but ``False`` for an int beyond the float range.

    ``math.isfinite(10**400)`` raises ``OverflowError``. Such an int is no more usable as a float
    measurement than ``inf`` is, so callers treat it the way they treat a non-finite value.
    """
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _sqrt_of_fraction(numerator: int, denominator: int) -> float:
    """``sqrt(numerator / denominator)`` rounded once, to nearest with ties to even."""
    if numerator < 0 or denominator <= 0:
        raise ValueError("square root of a negative or undefined fraction")
    if numerator == 0:
        return 0.0
    # Scale by 4**k so the integer square root carries at least _GUARD_BITS bits.
    deficit = 2 * _GUARD_BITS + 1 - (numerator.bit_length() - denominator.bit_length())
    k = max(0, (deficit + 1) // 2)
    quotient, remainder = divmod(numerator << (2 * k), denominator)
    root = math.isqrt(quotient)
    if remainder or root * root != quotient:
        root |= 1  # round to odd: the exact root lies strictly between root and root + 1
    return root / (1 << k)


def pstdev(data: Iterable[float | int]) -> float:
    """Population standard deviation of finite numbers, correctly rounded.

    Raises ``ValueError`` for no data or for a non-finite value.
    """
    ratios = []
    for value in data:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"pstdev needs ints or floats, got {type(value).__name__}")
        if not is_finite(value):
            raise ValueError(f"pstdev needs finite values, got {value!r}")
        ratios.append(value.as_integer_ratio())
    count = len(ratios)
    if count == 0:
        raise ValueError("pstdev requires at least one data point")
    # Every denominator is a power of two, so the largest is a common denominator.
    scale = max(denominator for _, denominator in ratios)
    scaled = [numerator * (scale // denominator) for numerator, denominator in ratios]
    total = sum(scaled)
    squares = sum(x * x for x in scaled)
    return _sqrt_of_fraction(count * squares - total * total, (count * scale) ** 2)
