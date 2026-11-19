"""Payload validation has one pure-Python path, whatever is installed.

``lionlock.signal_schemas`` used pydantic when it was importable and a hand-written fallback
otherwise, and the two disagreed on a lone surrogate in the reply, a NaN ``duration_ms`` and a
negative latency entry. Pydantic also runs plugins from any installed package inside validation,
and those received the raw prompt and reply. The expected verdicts below are the ones pydantic
2.13.5 (the pinned version, strict models) returned, which are the reference semantics.
"""

from __future__ import annotations

import json
import subprocess
import sys
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest

from lionlock.core.scoring import score_payload
from lionlock.signal_schemas import SignalPayload, ValidationError

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
NAN = float("nan")
OK = {"prompt": "What is the capital of France?", "response": "The capital of France is Paris."}


class _Str(str):
    pass


class _Float(float):
    pass


class _Int(int):
    pass


class _Dict(dict):
    pass


class _List(list):
    pass


def _md(**metadata: Any) -> dict[str, Any]:
    return {**OK, "metadata": metadata}


# (case, payload, accepted?, metadata as dumped when accepted)
REFERENCE: list[tuple[str, Any, bool, Any]] = [
    # the three cases on which the two old paths disagreed
    ("lone surrogate in reply", {"prompt": "hi there", "response": "ok \ud800 ok."}, False, None),
    ("NaN duration_ms", _md(duration_ms=float("nan")), False, None),
    (
        "negative latency entry",
        _md(latency_window_stats=[-1.0, 2.0]),
        True,
        {"latency_window_stats": [-1.0, 2.0]},
    ),
    # strings
    ("lone surrogate in prompt", {"prompt": "\udfff", "response": "r"}, False, None),
    ("empty prompt", {"prompt": "", "response": "r"}, False, None),
    ("empty reply", {"prompt": "p", "response": ""}, False, None),
    ("whitespace reply", {"prompt": "p", "response": " "}, True, None),
    ("str subclass", {"prompt": _Str("p"), "response": _Str("r")}, True, None),
    ("bytes reply", {"prompt": "p", "response": b"r"}, False, None),
    ("None reply", {"prompt": "p", "response": None}, False, None),
    ("missing reply", {"prompt": "p"}, False, None),
    ("unknown top-level key", {**OK, "extra": 1}, False, None),
    # payload and metadata containers
    ("payload not a dict", [OK], False, None),
    ("payload dict subclass", _Dict(OK), True, None),
    ("metadata None", {**OK, "metadata": None}, True, None),
    ("metadata empty", {**OK, "metadata": {}}, True, {}),
    ("metadata list", {**OK, "metadata": []}, False, None),
    ("metadata dict subclass", {**OK, "metadata": _Dict(turn_index=1)}, True, {"turn_index": 1}),
    ("unknown metadata key", _md(foo=1), False, None),
    ("metadata all None", _md(entropy_decay=None, turn_index=None), True, {}),
    # numbers
    ("entropy_decay int", _md(entropy_decay=1), True, {"entropy_decay": 1}),
    ("entropy_decay bool", _md(entropy_decay=True), False, None),
    ("entropy_decay str", _md(entropy_decay="0.5"), False, None),
    ("entropy_decay NaN", _md(entropy_decay=float("nan")), True, {"entropy_decay": NAN}),
    ("entropy_decay Decimal", _md(entropy_decay=Decimal("0.5")), True, {"entropy_decay": 0.5}),
    ("entropy_decay Fraction", _md(entropy_decay=Fraction(1, 2)), True, {"entropy_decay": 0.5}),
    ("entropy_decay float subclass", _md(entropy_decay=_Float(0.5)), True, {"entropy_decay": 0.5}),
    ("entropy_decay int subclass", _md(entropy_decay=_Int(1)), True, {"entropy_decay": 1.0}),
    ("entropy_decay complex", _md(entropy_decay=1j), False, None),
    ("drift_slope negative", _md(drift_slope=-1), True, {"drift_slope": -1}),
    ("turn_index 0", _md(turn_index=0), True, {"turn_index": 0}),
    ("turn_index negative", _md(turn_index=-1), False, None),
    ("turn_index float", _md(turn_index=3.0), False, None),
    ("turn_index bool", _md(turn_index=True), False, None),
    ("turn_index int subclass", _md(turn_index=_Int(3)), True, {"turn_index": 3}),
    ("turn_index Decimal", _md(turn_index=Decimal(3)), False, None),
    ("duration_ms inf", _md(duration_ms=float("inf")), True, {"duration_ms": float("inf")}),
    ("duration_ms -inf", _md(duration_ms=float("-inf")), False, None),
    ("duration_ms negative", _md(duration_ms=-1), False, None),
    ("duration_ms -0.0", _md(duration_ms=-0.0), True, {"duration_ms": -0.0}),
    ("duration_ms bool", _md(duration_ms=False), False, None),
    ("latency NaN entry", _md(latency_window_stats=[NAN]), True, {"latency_window_stats": [NAN]}),
    ("latency empty", _md(latency_window_stats=[]), True, {"latency_window_stats": []}),
    ("latency tuple", _md(latency_window_stats=(1.0,)), False, None),
    (
        "latency list subclass",
        _md(latency_window_stats=_List([1.0])),
        True,
        {"latency_window_stats": [1.0]},
    ),
    ("latency bool entry", _md(latency_window_stats=[True]), False, None),
    ("latency str entry", _md(latency_window_stats=["1"]), False, None),
]


def _shape(value: Any) -> Any:
    """Values with their exact types, NaN made comparable."""
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value]
    if isinstance(value, float) and value != value:
        return ("float", "nan")
    return (type(value).__name__, repr(value))


@pytest.mark.parametrize(
    ("payload", "accepted", "dumped"),
    [pytest.param(p, a, d, id=name) for name, p, a, d in REFERENCE],
)
def test_verdicts_match_the_pydantic_reference(payload: Any, accepted: bool, dumped: Any) -> None:
    if not accepted:
        with pytest.raises(ValidationError) as excinfo:
            SignalPayload.model_validate(payload)
        assert excinfo.value.errors()
        assert score_payload(payload) is None
        return
    validated = SignalPayload.model_validate(payload)
    assert type(validated.prompt) is str and type(validated.response) is str
    dump = validated.metadata.model_dump(exclude_none=True) if validated.metadata else None
    if dumped is None:
        assert dump in (None, {})
    else:
        assert _shape(dump) == _shape(dumped)
    assert score_payload(payload) is not None


def test_errors_carry_locations_but_never_the_raw_text() -> None:
    secret = "synthetic reply text \ud800"
    with pytest.raises(ValidationError) as excinfo:
        SignalPayload.model_validate(
            {"prompt": "", "response": secret, "metadata": {"turn_index": -1}}
        )
    errors = excinfo.value.errors()
    assert [(e["loc"], e["type"]) for e in errors] == [
        (("prompt",), "string_too_short"),
        (("response",), "string_unicode"),
        (("metadata", "turn_index"), "greater_than_equal"),
    ]
    assert "synthetic reply text" not in repr(errors)
    assert "synthetic reply text" not in str(excinfo.value)


_CHILD = r"""
import json
import sys

sys.path.insert(0, sys.argv[1])
if sys.argv[2] == "block":
    sys.modules["pydantic"] = None  # any import of pydantic now raises ImportError
if len(sys.argv) > 3:
    sys.path.insert(0, sys.argv[3])

from lionlock.core.scoring import score_payload

cases = {
    "surrogate": {"prompt": "hi there", "response": "ok \ud800 ok."},
    "nan_duration": {"prompt": "p", "response": "r", "metadata": {"duration_ms": float("nan")}},
    "negative_latency": {"prompt": "p", "response": "r",
                         "metadata": {"latency_window_stats": [-1.0, 2.0]}},
    "plain": {"prompt": "synthetic prompt words", "response": "synthetic reply words"},
}
verdicts = {name: score_payload(payload) is not None for name, payload in cases.items()}
seen = []
try:
    import spyplugin
except ImportError:
    pass
else:
    seen = spyplugin.SEEN
print(json.dumps({
    "verdicts": verdicts,
    "pydantic_loaded": bool(sys.modules.get("pydantic")) or "pydantic_core" in sys.modules,
    "plugin_saw": seen,
}))
"""


def _child(mode: str, *extra: str) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _CHILD, str(SRC_DIR), mode, *extra],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])
    return result


def test_same_verdicts_with_and_without_pydantic_importable() -> None:
    expected = {"surrogate": False, "nan_duration": False, "negative_latency": True, "plain": True}
    available = _child("allow")
    blocked = _child("block")
    assert available["verdicts"] == expected
    assert blocked["verdicts"] == expected
    assert available["pydantic_loaded"] is False


def test_pydantic_plugins_never_see_the_prompt_or_reply(tmp_path: Path) -> None:
    """A package registering a pydantic plugin used to receive every payload, text included."""
    site = tmp_path / "site"
    dist = site / "spyplugin-0.1.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: spyplugin\nVersion: 0.1\n")
    (dist / "entry_points.txt").write_text("[pydantic]\nspy = spyplugin:plugin\n")
    (site / "spyplugin.py").write_text(
        "SEEN = []\n"
        "class _Handler:\n"
        "    def on_enter(self, input, **kwargs):\n"
        "        SEEN.append(repr(input)[:200])\n"
        "class _Plugin:\n"
        "    def new_schema_validator(self, schema, schema_type, schema_type_path, schema_kind,\n"
        "                             config, plugin_settings):\n"
        "        return _Handler(), None, None\n"
        "plugin = _Plugin()\n"
    )
    result = _child("allow", str(site))
    assert result["verdicts"]["plain"] is True
    assert result["plugin_saw"] == []
    assert result["pydantic_loaded"] is False
