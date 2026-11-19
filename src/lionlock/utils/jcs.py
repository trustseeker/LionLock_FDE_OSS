"""Strict canonical JSON for hash inputs: RFC 8785 (JCS) restricted to portable values.

The encoding is the JSON Canonicalization Scheme of RFC 8785, so any JCS implementation, in any
language, produces the same bytes for the same parsed value:

- objects: members sorted by key, compared as UTF-16 code units; no whitespace;
- strings: only ``"``, ``\\`` and U+0000..U+001F are escaped (``\\b \\t \\n \\f \\r``, else
  ``\\u00xx`` in lowercase hex); everything else, including non-ASCII, is written as UTF-8;
- numbers: the IEEE-754 double value written as ECMAScript ``Number.prototype.toString`` does
  (``1.0`` is ``1``, ``-0.0`` is ``0``, ``1e-7`` is ``1e-7``, ``1e21`` is ``1e+21``).

On top of RFC 8785 the input is restricted to values every JSON implementation reads the same way:
text keys only, finite numbers only, strings that are valid Unicode (no unpaired surrogates), and,
when ``exact_integers`` is set, integers within +/-(2**53 - 1). Anything else raises
:class:`CanonicalFormError` naming where it was found. Nothing is coerced: a non-text key is an
error, never converted to text.

``docs/AUDIT_LOGGING.md`` specifies this encoding at byte level.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, List, Set

MAX_SAFE_INTEGER = 2**53 - 1

_ESCAPE = re.compile(r'[\x00-\x1f"\\]')
_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


class CanonicalFormError(ValueError, TypeError):
    """A value has no canonical form.

    ``path`` says where, for example ``payload.turn_scores`` or ``payload.scores[2]``. It is a
    ``ValueError``; it is also a ``TypeError`` so that callers who caught the ``TypeError`` that
    ``json.dumps`` raises for unserializable objects keep working.
    """

    def __init__(self, path: str, problem: str) -> None:
        self.path = path or "(root)"
        self.problem = problem
        super().__init__(f"{self.path}: {problem}")


def canonical_text(value: Any, *, exact_integers: bool = True) -> str:
    """The canonical JSON text of ``value``.

    ``exact_integers`` refuses integers outside +/-(2**53 - 1), which other languages cannot hold
    exactly. Verifiers pass ``False``: an integer read back from a file is then taken as the
    nearest double, as a JSON parser in any other language would read it.
    """
    out: List[str] = []
    _encode(value, "", out, exact_integers, set())
    return "".join(out)


def canonical_bytes(value: Any, *, exact_integers: bool = True) -> bytes:
    """``canonical_text`` encoded as UTF-8: the bytes that get hashed."""
    return canonical_text(value, exact_integers=exact_integers).encode("utf-8")


def format_number(number: float) -> str:
    """A finite double as ECMAScript ``Number.prototype.toString`` writes it (RFC 8785 3.2.2.3)."""
    if not math.isfinite(number):
        raise ValueError("NaN and Infinity have no JSON form")
    if number == 0:
        return "0"  # also -0.0
    sign = "-" if number < 0 else ""
    # repr() gives the shortest digit string that reads back as the same double, the same digits
    # ECMAScript chooses. Rewrite it as value = 0.<digits> * 10**point.
    mantissa, _, exponent = repr(abs(number)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = whole + fraction
    point = len(whole) + (int(exponent) if exponent else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    k = len(digits)
    if k <= point <= 21:
        body = digits + "0" * (point - k)
    elif 0 < point <= 21:
        body = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        body = "0." + "0" * (-point) + digits
    else:
        power = point - 1
        sign_of_power = "+" if power >= 0 else "-"
        fraction_digits = "." + digits[1:] if k > 1 else ""
        body = f"{digits[0]}{fraction_digits}e{sign_of_power}{abs(power)}"
    return sign + body


def _quote(text: str, path: str, what: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalFormError(path, f"{what} is not valid Unicode text") from None

    def escape(match: re.Match[str]) -> str:
        char = match.group(0)
        return _SHORT_ESCAPES.get(char) or f"\\u{ord(char):04x}"

    return '"' + _ESCAPE.sub(escape, text) + '"'


def _child(path: str, key: str) -> str:
    if key.isidentifier():
        return f"{path}.{key}" if path else key
    return f"{path}[{json.dumps(key)}]"


def _describe_key(key: Any) -> str:
    text = repr(key)
    if len(text) > 40:
        text = text[:37] + "..."
    return f"{text} ({type(key).__name__})"


def _encode(value: Any, path: str, out: List[str], exact: bool, active: Set[int]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_quote(value, path, "string"))
    elif isinstance(value, int):
        if exact and abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalFormError(
                path, "integer is outside +/-(2**53 - 1); pass it as a float or as text"
            )
        try:
            out.append(format_number(float(value)))
        except OverflowError:
            raise CanonicalFormError(path, "integer is too large for a double") from None
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalFormError(path, f"{value!r} is not a finite number")
        out.append(format_number(float(value)))
    elif isinstance(value, dict):
        _encode_object(value, path, out, exact, active)
    elif isinstance(value, (list, tuple)):
        if id(value) in active:
            raise CanonicalFormError(path, "circular reference")
        active.add(id(value))
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _encode(item, f"{path}[{index}]", out, exact, active)
        out.append("]")
        active.discard(id(value))
    else:
        raise CanonicalFormError(path, f"{type(value).__name__} is not a JSON value")


def _encode_object(
    value: "dict[Any, Any]", path: str, out: List[str], exact: bool, active: Set[int]
) -> None:
    if id(value) in active:
        raise CanonicalFormError(path, "circular reference")
    active.add(id(value))
    members = []
    for key, item in value.items():
        if not isinstance(key, str):
            raise CanonicalFormError(path, f"key {_describe_key(key)} is not text")
        members.append((key.encode("utf-16-be", "surrogatepass"), key, item))
    members.sort(key=lambda member: member[0])
    out.append("{")
    for index, (_, key, item) in enumerate(members):
        if index:
            out.append(",")
        out.append(_quote(key, path, f"key {_describe_key(key)}"))
        out.append(":")
        _encode(item, _child(path, key), out, exact, active)
    out.append("}")
    active.discard(id(value))
