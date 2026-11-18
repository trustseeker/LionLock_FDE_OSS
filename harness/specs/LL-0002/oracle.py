"""LL-0002 oracle: what the gate should decide under D1, computed without calling the gate.

``expected(apply_rule=False)`` mirrors ``evaluate_policy``/``decide_gate`` as they were before
LL-0002, and ``make golden`` checks that it reproduces the library exactly before writing the
golden.
``expected(apply_rule=True)`` is the D1 rule as SPEC.md states it. The two differ only in the
decision; scoring is out of scope, so signal scores, derived signals and the aggregate come from the
real scorer in both.

Nothing here imports a gating function. Constants are imported because they are what the policy is
expressed in, not how a decision is made.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

from lionlock.core.gating import (
    DEFAULT_THRESHOLDS,
    DERIVED_RISK_KEYS,
    REASON_CODE_MAP,
    TRIGGER_SIGNAL_ORDER,
)
from lionlock.core.scoring import (
    DEFAULT_SIGNAL_WEIGHTS,
    aggregate_score,
    low_conf_halluc_score,
    score_payload,
)

# Deliberately not imported from product.py: an oracle that shares its subject's helpers can agree
# with it for the wrong reason, and specs are loaded by path, so relative imports would not resolve.
CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"
INVALID_PROBE_ID = "19-banana-loop-off-topic"
FATIGUE_INPUT_KEYS = ("entropy_decay", "turn_index", "drift_slope")
NO_METADATA_MISSING = (
    "entropy_decay",
    "turn_index",
    "drift_slope",
    "duration_ms",
    "latency_window_stats",
)
SIGNALS = (
    "repetition_loopiness",
    "novelty_entropy_proxy",
    "coherence_structure",
    "context_adherence",
    "hallucination_risk",
)
HALLUCINATION_EVIDENCE = ("hallucination_risk", "low_conf_halluc")
MODES = ("warn_only", "block")
NAN = float("nan")

HALLUCINATION_WEIGHTED = {
    "repetition_loopiness": 0.25,
    "novelty_entropy_proxy": 0.20,
    "coherence_structure": 0.20,
    "context_adherence": 0.15,
    "hallucination_risk": 0.20,
}
POLICIES: Dict[str, Dict[str, Any]] = {
    "default": {},
    "block_mode": {"hallucination_mode": "block"},
    "context_only": {"enabled_signals": ["context_adherence"]},
    "hallucination_weighted": {"weights": HALLUCINATION_WEIGHTED},
    "repetition_not_hard_gated": {
        "hard_gate_reasons_enabled": [
            "low_novelty",
            "low_coherence",
            "context_drift",
            "hallucination_risk",
        ]
    },
    "log_only": {"gating_enabled": False},
}
INVALID_POLICIES: Dict[str, Callable[[], Dict[str, Any]]] = {
    "nan_weight": lambda: {"weights": {**DEFAULT_SIGNAL_WEIGHTS, "repetition_loopiness": NAN}},
    "negative_weight": lambda: {"weights": {**DEFAULT_SIGNAL_WEIGHTS, "context_adherence": -0.2}},
    "all_zero_weights": lambda: {"weights": {key: 0.0 for key in DEFAULT_SIGNAL_WEIGHTS}},
    "unknown_enabled_signal": lambda: {"enabled_signals": ["no_such_signal"]},
    "unordered_thresholds": lambda: {"thresholds": {"yellow": 0.7, "orange": 0.65, "red": 0.8}},
    "missing_red_threshold": lambda: {"thresholds": {"yellow": 0.45, "orange": 0.65}},
    "nan_red_threshold": lambda: {"thresholds": {"yellow": 0.45, "orange": 0.65, "red": NAN}},
    "misspelt_mode": lambda: {"hallucination_mode": "warn_onyl"},
}
DEFAULT_ACTION = {"red": "BLOCK", "orange": "REFRESH", "yellow": "REFRESH", "green": "ALLOW"}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _unit(value: Any) -> float:
    if value is None or isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return _clamp(float(value))
    return 0.0


def _band(score: float, thresholds: Dict[str, float]) -> str:
    # Same check order as before LL-0002; a missing key raises KeyError, as it did.
    if score >= thresholds["red"]:
        return "red"
    if score >= thresholds["orange"]:
        return "orange"
    if score >= thresholds["yellow"]:
        return "yellow"
    return "green"


def _pick(values: Dict[str, float]) -> str:
    if not values:
        return "unknown"
    best = max(values[key] for key in TRIGGER_SIGNAL_ORDER if key in values)
    for key in TRIGGER_SIGNAL_ORDER:
        if values.get(key) == best:
            return key
    return "unknown"


def _admitted(missing_inputs: Iterable[str]) -> tuple[str, ...]:
    """LL-0001: fatigue_risk_index is withheld while any fatigue input is missing."""
    if set(missing_inputs) & set(FATIGUE_INPUT_KEYS):
        return tuple(key for key in DERIVED_RISK_KEYS if key != "fatigue_risk_index")
    return DERIVED_RISK_KEYS


def _finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _validate(
    *,
    weights: Optional[Dict[str, Any]],
    enabled: Optional[list[str]],
    thresholds: Optional[Dict[str, Any]],
    mode: str,
    check_weights: bool,
) -> None:
    """R7, written independently of the library."""
    if mode not in MODES:
        raise ValueError("hallucination_mode")
    if thresholds:
        for key in ("yellow", "orange", "red"):
            if key not in thresholds or not _finite_number(thresholds[key]):
                raise ValueError(f"thresholds[{key}]")
        if not 0.0 <= thresholds["yellow"] < thresholds["orange"] < thresholds["red"] <= 1.0:
            raise ValueError("thresholds order")
    if not check_weights:
        return
    resolved = weights or DEFAULT_SIGNAL_WEIGHTS
    for key, value in resolved.items():
        if not _finite_number(value) or value < 0:
            raise ValueError(f"weights[{key}]")
    if enabled is not None:
        for key in enabled:
            if key not in SIGNALS:
                raise ValueError("enabled_signals")
    if not any(resolved.get(key, 0.0) > 0 for key in SIGNALS if enabled is None or key in enabled):
        raise ValueError("no enabled signal has a positive weight")


def _before(
    *,
    aggregate: float,
    scores: Dict[str, Any],
    derived: Dict[str, Any],
    missing: Iterable[str],
    thresholds: Optional[Dict[str, Any]],
    gating_enabled: bool,
    mode: str,
    hard_gate: Optional[Iterable[str]],
    **_: Any,
) -> Dict[str, Any]:
    """The gate as it was before LL-0002."""
    resolved = thresholds or DEFAULT_THRESHOLDS
    safe_scores = {key: _unit(value) for key, value in scores.items()}
    safe_derived = {key: _unit(value) for key, value in derived.items()}
    raw = _unit(aggregate)
    derived_map = {key: safe_derived.get(key, 0.0) for key in _admitted(missing)}
    derived_channel = max(derived_map.values()) if derived_map else 0.0
    risk = _clamp(max(raw, derived_channel))
    severity = _band(risk, resolved)
    trigger = _pick(derived_map) if derived_channel >= raw else _pick(safe_scores)
    reason = REASON_CODE_MAP.get(trigger, "policy_violation")
    if severity == "red" and mode == "warn_only" and reason == "hallucination_risk":
        severity = "orange"
    if severity == "red" and hard_gate is not None and reason not in set(hard_gate):
        severity = "orange"
    action = DEFAULT_ACTION[severity] if gating_enabled else "ALLOW"
    return {
        "decision_risk_score": risk,
        "severity": severity,
        "gating_decision": action,
        "trigger_signal": trigger,
        "reason_code": reason,
        "policy_adjustment": None,
    }


def _d1(
    *,
    aggregate: float,
    scores: Dict[str, Any],
    derived: Dict[str, Any],
    missing: Iterable[str],
    thresholds: Optional[Dict[str, Any]],
    gating_enabled: bool,
    mode: str,
    hard_gate: Optional[Iterable[str]],
    weights: Optional[Dict[str, Any]],
    enabled: Optional[list[str]],
) -> Dict[str, Any]:
    """The gate under D1, as SPEC.md states it."""
    resolved = thresholds or DEFAULT_THRESHOLDS
    resolved_weights = weights or DEFAULT_SIGNAL_WEIGHTS
    safe_scores = {key: _unit(value) for key, value in scores.items()}
    safe_derived = {key: _unit(value) for key, value in derived.items()}
    raw = _unit(aggregate)
    derived_map = {key: safe_derived.get(key, 0.0) for key in _admitted(missing)}
    derived_channel = max(derived_map.values()) if derived_map else 0.0
    risk = _clamp(max(raw, derived_channel))
    severity = _band(risk, resolved)

    enabled_keys = [key for key in safe_scores if enabled is None or key in enabled]
    contributions = {
        key: resolved_weights.get(key, 0.0) * safe_scores[key]
        for key in enabled_keys
        if resolved_weights.get(key, 0.0) > 0
    }
    trigger = _pick(derived_map) if derived_channel >= raw else _pick(contributions)

    action = DEFAULT_ACTION[severity]
    adjustment = None
    if severity == "red" and mode == "warn_only":
        weighted = 0.0
        total = 0.0
        for key in enabled_keys:
            if key == "hallucination_risk":
                continue
            weight = resolved_weights.get(key, 0.0)
            weighted += safe_scores[key] * weight
            total += weight
        non_raw = _unit(weighted / total if total else 0.0)
        non_derived = {k: v for k, v in derived_map.items() if k not in HALLUCINATION_EVIDENCE}
        non_derived_channel = max(non_derived.values()) if non_derived else 0.0
        if _band(_clamp(max(non_raw, non_derived_channel)), resolved) == "red":
            non_contributions = {
                k: v for k, v in contributions.items() if k not in HALLUCINATION_EVIDENCE
            }
            if non_derived_channel >= non_raw:
                trigger = _pick(non_derived)
            else:
                trigger = _pick(non_contributions)
        else:
            action = "REFRESH"
            adjustment = "warn_only_hallucination"
            trigger = "low_conf_halluc" if derived_channel >= raw else "hallucination_risk"
    reason = REASON_CODE_MAP.get(trigger, "policy_violation")
    if action == "BLOCK" and hard_gate is not None and reason not in set(hard_gate):
        action = "REFRESH"
        adjustment = "hard_gate_reason_disabled"
    if not gating_enabled and action != "ALLOW":
        action = "ALLOW"
        adjustment = "gating_disabled"
    return {
        "decision_risk_score": risk,
        "severity": severity,
        "gating_decision": action,
        "trigger_signal": trigger,
        "reason_code": reason,
        "policy_adjustment": adjustment,
    }


def _decide(apply_rule: bool, *, check_weights: bool, **kwargs: Any) -> Dict[str, Any]:
    try:
        if apply_rule:
            _validate(
                weights=kwargs["weights"],
                enabled=kwargs["enabled"],
                thresholds=kwargs["thresholds"],
                mode=kwargs["mode"],
                check_weights=check_weights,
            )
            if not check_weights and not _finite_number(kwargs["aggregate"]):
                raise ValueError("aggregate_score")
            return _d1(**kwargs)
        return _before(**kwargs)
    except (ValueError, KeyError) as error:
        return {"raises": type(error).__name__}


def _evaluate(bundle: Any, policy: Dict[str, Any], apply_rule: bool) -> Dict[str, Any]:
    weights = policy.get("weights")
    enabled = policy.get("enabled_signals")
    # Scoring is out of scope: the aggregate comes from the real scorer. Under the rule, an invalid
    # policy is refused before the aggregate is used.
    aggregate = aggregate_score(bundle, weights=weights, enabled_signals=enabled)
    return _decide(
        apply_rule,
        check_weights=True,
        aggregate=aggregate,
        scores=bundle.signal_scores.as_dict(),
        derived=bundle.derived_signals.as_dict(),
        missing=bundle.missing_inputs,
        thresholds=policy.get("thresholds"),
        gating_enabled=policy.get("gating_enabled", True),
        mode=policy.get("hallucination_mode", "warn_only"),
        hard_gate=policy.get("hard_gate_reasons_enabled"),
        weights=weights,
        enabled=enabled,
    )


def _gate(aggregate: float, scores_obj: Any, apply_rule: bool) -> Dict[str, Any]:
    scores = scores_obj.as_dict()
    derived = {
        "fatigue_risk_index": 0.0,
        "fatigue_risk_25t": 0.0,
        "fatigue_risk_50t": 0.0,
        "low_conf_halluc": low_conf_halluc_score(scores_obj),
        "congestion_signature": 0.0,
    }
    return _decide(
        apply_rule,
        check_weights=False,
        aggregate=aggregate,
        scores=scores,
        derived=derived,
        missing=NO_METADATA_MISSING,
        thresholds=None,
        gating_enabled=True,
        mode="warn_only",
        hard_gate=None,
        weights=None,
        enabled=None,
    )


def _payload_for(entry: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"prompt": entry["prompt"], "response": entry["response"]}
    if entry.get("metadata") is not None:
        payload["metadata"] = entry["metadata"]
    return payload


def expected(*, apply_rule: bool = True) -> Dict[str, Any]:
    cases = []
    probe = None
    for entry in json.loads(CORPUS_PATH.read_text(encoding="utf-8"))["payloads"]:
        bundle = score_payload(_payload_for(entry))
        if bundle is None:
            cases.append({"id": entry["id"], "rejected": True})
            continue
        if entry["id"] == INVALID_PROBE_ID:
            probe = bundle
        aggregate = aggregate_score(bundle)
        cases.append(
            {
                "id": entry["id"],
                "evidence": {
                    "signal_scores": bundle.signal_scores.as_dict(),
                    "derived_signals": bundle.derived_signals.as_dict(),
                    "missing_inputs": list(bundle.missing_inputs),
                    "aggregate_score": aggregate,
                },
                "evaluate_policy": {
                    name: _evaluate(bundle, policy, apply_rule) for name, policy in POLICIES.items()
                },
                "decide_gate": _gate(aggregate, bundle.signal_scores, apply_rule),
            }
        )
    assert probe is not None
    invalid = {
        name: _evaluate(probe, make(), apply_rule) for name, make in INVALID_POLICIES.items()
    }
    invalid["decide_gate_nan_aggregate"] = _gate(NAN, probe.signal_scores, apply_rule)
    return {"spec": "LL-0002", "cases": cases, "invalid_policies": invalid}
