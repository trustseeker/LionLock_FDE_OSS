"""LL-0002 product: the gate's observable output under the policies D1 is about.

``product()`` runs the real pipeline over the corpus under several valid policies, and a set of
invalid policies on one probe case. It reads nothing but the corpus and the library, so it can be
run against the code before and after the change: ``policy_adjustment`` is read with a default of
``None`` because the field does not exist before LL-0002.

This file is part of the harness contract. An agent working LL-0002 must not edit it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict

from lionlock.core.gating import decide_gate, evaluate_policy
from lionlock.core.scoring import DEFAULT_SIGNAL_WEIGHTS, aggregate_score, score_payload

CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"

DECISION_FIELDS = (
    "decision_risk_score",
    "severity",
    "gating_decision",
    "trigger_signal",
    "reason_code",
)

HALLUCINATION_WEIGHTED = {
    "repetition_loopiness": 0.25,
    "novelty_entropy_proxy": 0.20,
    "coherence_structure": 0.20,
    "context_adherence": 0.15,
    "hallucination_risk": 0.20,
}

# Valid policies. Each is a set of keyword arguments for evaluate_policy.
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

NAN = float("nan")

# Invalid policies, applied to one probe case. Built as functions so no NaN sits in module state.
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

INVALID_PROBE_ID = "19-banana-loop-off-topic"


def load_payloads() -> list[dict[str, Any]]:
    return list(json.loads(CORPUS_PATH.read_text(encoding="utf-8"))["payloads"])


def _payload_for(entry: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"prompt": entry["prompt"], "response": entry["response"]}
    if entry.get("metadata") is not None:
        payload["metadata"] = entry["metadata"]
    return payload


def _view(decision: Any) -> dict[str, Any]:
    view = {field: getattr(decision, field) for field in DECISION_FIELDS}
    view["policy_adjustment"] = getattr(decision, "policy_adjustment", None)
    return view


def _attempt(call: Callable[[], Any]) -> dict[str, Any]:
    """The decision, or the kind of error raised. Messages are not recorded: they are prose."""
    try:
        return _view(call())
    except (ValueError, KeyError) as error:
        return {"raises": type(error).__name__}


def _evaluate(bundle: Any, policy: Dict[str, Any]) -> dict[str, Any]:
    return _attempt(lambda: evaluate_policy(bundle, **policy))


def product() -> dict[str, Any]:
    cases = []
    probe = None
    for entry in load_payloads():
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
                    name: _evaluate(bundle, policy) for name, policy in POLICIES.items()
                },
                "decide_gate": _attempt(lambda: decide_gate(aggregate, bundle.signal_scores)),
            }
        )

    assert probe is not None, f"{INVALID_PROBE_ID} must be in the corpus and must validate"
    invalid = {name: _evaluate(probe, make()) for name, make in INVALID_POLICIES.items()}
    invalid["decide_gate_nan_aggregate"] = _attempt(lambda: decide_gate(NAN, probe.signal_scores))
    return {"spec": "LL-0002", "cases": cases, "invalid_policies": invalid}


if __name__ == "__main__":
    print(json.dumps(product(), indent=2, sort_keys=True))
