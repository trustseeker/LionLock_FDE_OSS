"""Format 2 test vectors, recomputed from the rule in docs/AUDIT_LOGGING.md.

The first test is a separate implementation of the documented canonical form written from the
documentation alone. It imports nothing from ``lionlock``, and derives number digits a different
way from the library (searching for the shortest round-tripping precision instead of reading
``repr``), so it is an independent check of both the vectors and the document.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest

VECTORS = Path(__file__).parent / "fixtures" / "trustvault_format2_vectors.json"
GENESIS = "0" * 64

# Hashes listed in docs/AUDIT_LOGGING.md, in chain order.
EXPECTED = [
    "db5f2c557e0c4d35e2038c0c92501e32338d1abe7a5d056c385e960f18643ef6",
    "066299926f6389f9c27fca2fce15d79a02b4ba6881b90f71836424d50a3493f1",
    "4d322f0a75ed67e0888cdf53de2395df47cb3604082441524be6a9bb14cdaf63",
    "aa59d134670c8b8c860610b38f3667ac45bede110e9765d21840234a1fe0c28d",
    "4484f33a77c713780cb30904fc3adb11129d2dc05d8c4156d8b3365c62f1d752",
    "40d53f34adf95bf4c3c6c77d6b0cab7ffb35a9593e12b0bba41e524b6a058407",
]


def _vectors() -> list[dict[str, str]]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]


# --- independent implementation of the documented rule ---------------------------------------


def _number(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("not finite")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    value = abs(value)
    for precision in range(1, 18):  # fewest significant digits that read back as the same double
        text = f"{value:.{precision - 1}e}"
        if float(text) == value:
            break
    mantissa, exponent = text.split("e")
    digits = mantissa.replace(".", "").rstrip("0")
    k, n = len(digits), int(exponent) + 1  # value = 0.<digits> * 10**n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    rest = "." + digits[1:] if k > 1 else ""
    return f"{sign}{digits[0]}{rest}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"


def _string(text: str) -> str:
    named = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f"}
    named["\r"] = "\\r"
    out = []
    for char in text:
        if char in named:
            out.append(named[char])
        elif ord(char) < 0x20:
            out.append("\\u%04x" % ord(char))
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def _canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _number(float(value))
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    keys = sorted(value, key=lambda key: key.encode("utf-16-be"))  # UTF-16 code unit order
    return "{" + ",".join(_string(key) + ":" + _canonical(value[key]) for key in keys) + "}"


def test_vectors_recompute_from_the_documented_rule_alone() -> None:
    vectors = _vectors()
    assert [vector["sha256"] for vector in vectors] == EXPECTED
    previous = GENESIS
    for vector in vectors:
        entry = json.loads(vector["line"])
        assert entry["prev_hash"] == previous
        assert entry["format"] == 2
        body = {key: value for key, value in entry.items() if key != "sha256"}
        hashed = _canonical(body)
        assert hashed == vector["hashed"], vector["name"]
        assert hashlib.sha256(hashed.encode("utf-8")).hexdigest() == vector["sha256"]
        assert entry["sha256"] == vector["sha256"]
        assert _canonical(entry) == vector["line"]  # lines are written in canonical form
        previous = entry["sha256"]


@pytest.mark.parametrize(
    "value, text",
    [
        (1.0, "1"),
        (-0.0, "0"),
        (0.1, "0.1"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (1e16, "10000000000000000"),
        (1e21, "1e+21"),
        (123456789012345680000.0, "123456789012345680000"),
        (5e-324, "5e-324"),
        (-1.7976931348623157e308, "-1.7976931348623157e+308"),
        (2**53 - 1, "9007199254740991"),
    ],
)
def test_documented_number_examples(value: float, text: str) -> None:
    assert _number(float(value)) == text


# --- the library agrees with the vectors ------------------------------------------------------


def test_the_library_verifies_the_vectors_as_one_chain(tmp_path: Path) -> None:
    from lionlock.utils.chain_verifier import entry_hash, verify_chain_file
    from lionlock.utils.jcs import canonical_text, format_number

    path = tmp_path / "vectors.log"
    path.write_text("".join(v["line"] + "\n" for v in _vectors()), encoding="utf-8")
    count = len(EXPECTED)
    verify_chain_file(path, expected_head=EXPECTED[-1], expected_count=count)
    for vector in _vectors():
        entry = json.loads(vector["line"])
        assert entry_hash(entry) == vector["sha256"]
        # Parsed back, 1e20 and the like are integers beyond 2**53: read them as doubles.
        assert canonical_text(entry, exact_integers=False) == vector["line"]
    for value in (0.1, 1e-7, 1e21, 5e-324, 1 / 3, 2.5e-5, 4.35, 1e300, 123e-20):
        assert format_number(value) == _number(value)
