"""Validation of inbound Module 02 signal payloads: one pure-Python path.

Until 1.0.0b2 this module validated with pydantic when it was importable and with a hand-written
fallback otherwise, and the two disagreed: a lone surrogate in the reply, a NaN ``duration_ms``
and a negative latency entry each got a different verdict depending on what happened to be
installed. Pydantic also loads plugins from any installed package (the ``pydantic`` entry-point
group), and those ran inside scoring with the raw prompt and reply as input. This module now
imports nothing outside the standard library, so the verdict cannot depend on the environment
and no third-party code sees the text.

The rules reproduce what the pydantic models (strict mode, ``extra="forbid"``) decided in the
pinned environment, pydantic 2.13.5, which is the reference:

* ``prompt`` and ``response`` are required ``str`` (subclasses accepted, returned as ``str``),
  at least one character, and must be valid Unicode: a lone surrogate is rejected.
* ``metadata`` is absent, ``None`` or a ``dict``; unknown keys are rejected, at the top level too.
* ``entropy_decay``, ``drift_slope`` and each ``latency_window_stats`` entry are numbers: an exact
  ``int`` is kept, any other non-``bool``, non-string value is converted with ``float()``
  (``float`` subclasses, ``int`` subclasses, ``Decimal``, ``Fraction`` and other objects
  ``float()`` accepts), and a value ``float()`` refuses is rejected. NaN, infinities and negative
  values are accepted here; scoring treats a non-finite or out-of-range input as it always has.
* ``turn_index`` is an ``int`` (not ``bool``, not ``float``) ``>= 0``.
* ``duration_ms`` is a number ``>= 0``: NaN and ``-inf`` fail the comparison and are rejected,
  ``+inf`` and ``-0.0`` are accepted.
* ``latency_window_stats`` is a ``list`` (subclasses accepted, tuples rejected).

Deliberate differences from the pydantic models, none of which changes whether a payload is
accepted or what is scored:

* A rejected numeric field yields one error at its own location, where pydantic reported one per
  member of the ``float | int`` union (``metadata.entropy_decay.float`` and ``...int``).
* Error entries carry ``loc``, ``type`` and ``msg`` only. Pydantic also returned the offending
  ``input``, which for ``prompt`` and ``response`` is the raw text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

METADATA_FIELDS = (
    "entropy_decay",
    "drift_slope",
    "turn_index",
    "duration_ms",
    "latency_window_stats",
)
PAYLOAD_FIELDS = ("prompt", "response", "metadata")

_Loc = tuple[Any, ...]


class ValidationError(ValueError):
    """Raised by ``SignalPayload.model_validate``; ``errors()`` lists every problem found."""

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        super().__init__(f"{len(errors)} validation error(s) for SignalPayload")
        self._errors = errors

    def errors(self) -> list[dict[str, Any]]:
        return [dict(error) for error in self._errors]


class _Invalid(Exception):
    def __init__(self, error_type: str, msg: str) -> None:
        super().__init__(msg)
        self.error_type = error_type
        self.msg = msg


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise _Invalid("string_type", "Input should be a valid string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise _Invalid("string_unicode", "Input should be a valid string, not invalid Unicode")
    if len(value) < 1:
        raise _Invalid("string_too_short", "String should have at least 1 character")
    return str.__str__(value)  # a plain str, also for a str subclass


def _number(value: Any) -> int | float:
    if isinstance(value, bool) or isinstance(value, (str, bytes, bytearray)):
        raise _Invalid("number_type", "Input should be a valid number")
    if type(value) is int:
        return value
    try:
        return float(value)
    except OverflowError:
        if isinstance(value, int):  # an int subclass beyond the float range stays an int
            return int(value)
        raise _Invalid("number_type", "Input should be a valid number") from None
    except (TypeError, ValueError):
        raise _Invalid("number_type", "Input should be a valid number") from None


def _non_negative(number: int | float) -> int | float:
    # Written as "not >=" so NaN fails, exactly as the ge=0 constraint did.
    if not number >= 0:
        raise _Invalid("greater_than_equal", "Input should be greater than or equal to 0")
    return number


def _turn_index(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Invalid("int_type", "Input should be a valid integer")
    return int(_non_negative(int(value)))


def _latency_window(value: Any, errors: list[dict[str, Any]], loc: _Loc) -> list[int | float]:
    if not isinstance(value, list):
        raise _Invalid("list_type", "Input should be a valid list")
    entries: list[int | float] = []
    for index, item in enumerate(value):
        try:
            entries.append(_number(item))
        except _Invalid as exc:
            errors.append(_error((*loc, index), exc))
    return entries


def _error(loc: _Loc, exc: _Invalid) -> dict[str, Any]:
    return {"loc": loc, "type": exc.error_type, "msg": exc.msg}


def _unknown_keys(mapping: dict[Any, Any], allowed: tuple[str, ...]) -> list[Any]:
    return sorted((key for key in mapping if key not in allowed), key=repr)


@dataclass(frozen=True)
class SignalMetadata:
    """Optional metadata used for derived signal calculations."""

    entropy_decay: float | int | None = None
    drift_slope: float | int | None = None
    turn_index: int | None = None
    duration_ms: float | int | None = None
    latency_window_stats: list[float | int] | None = None

    def model_dump(self, *, exclude_none: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "entropy_decay": self.entropy_decay,
            "drift_slope": self.drift_slope,
            "turn_index": self.turn_index,
            "duration_ms": self.duration_ms,
            "latency_window_stats": (
                list(self.latency_window_stats) if self.latency_window_stats is not None else None
            ),
        }
        if exclude_none:
            return {key: value for key, value in payload.items() if value is not None}
        return payload

    @classmethod
    def _validate(cls, raw: Any, errors: list[dict[str, Any]]) -> "SignalMetadata | None":
        if isinstance(raw, SignalMetadata):
            return raw
        if not isinstance(raw, dict):
            errors.append(
                _error(("metadata",), _Invalid("model_type", "Input should be a dictionary"))
            )
            return None
        start = len(errors)
        for key in _unknown_keys(raw, METADATA_FIELDS):
            errors.append(
                _error(
                    ("metadata", key), _Invalid("extra_forbidden", "Extra inputs are not permitted")
                )
            )
        values: dict[str, Any] = {}
        for key in METADATA_FIELDS:
            value = raw.get(key)
            if value is None:
                continue
            loc: _Loc = ("metadata", key)
            try:
                if key == "turn_index":
                    values[key] = _turn_index(value)
                elif key == "duration_ms":
                    values[key] = _non_negative(_number(value))
                elif key == "latency_window_stats":
                    values[key] = _latency_window(value, errors, loc)
                else:
                    values[key] = _number(value)
            except _Invalid as exc:
                errors.append(_error(loc, exc))
        if len(errors) > start:
            return None
        return cls(**values)


@dataclass(frozen=True)
class SignalPayload:
    """Strict boundary payload for scoring."""

    prompt: str
    response: str
    metadata: SignalMetadata | None = None

    @classmethod
    def model_validate(cls, payload: Any) -> "SignalPayload":
        if isinstance(payload, SignalPayload):
            return payload
        if not isinstance(payload, dict):
            raise ValidationError(
                [_error((), _Invalid("model_type", "Input should be a dictionary"))]
            )
        errors: list[dict[str, Any]] = []
        texts: dict[str, str] = {}
        for key in ("prompt", "response"):
            if key not in payload:
                errors.append(_error((key,), _Invalid("missing", "Field required")))
                continue
            try:
                texts[key] = _text(payload[key])
            except _Invalid as exc:
                errors.append(_error((key,), exc))
        for key in _unknown_keys(payload, PAYLOAD_FIELDS):
            errors.append(
                _error((key,), _Invalid("extra_forbidden", "Extra inputs are not permitted"))
            )
        metadata = None
        if payload.get("metadata") is not None:
            metadata = SignalMetadata._validate(payload["metadata"], errors)
        if errors:
            raise ValidationError(errors)
        return cls(prompt=texts["prompt"], response=texts["response"], metadata=metadata)
