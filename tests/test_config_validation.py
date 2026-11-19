"""Gating and signal settings are validated when they are loaded, not trusted until they fail open.

Every setting checked here used to fail *open*: TOML accepts ``nan`` and ``inf``, a NaN weight made
the aggregate NaN, gating read NaN as risk 0.0, and a response that should have been blocked was
allowed. The tests load real TOML files, because that is where these values come from.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lionlock import config as lionlock_config
from lionlock.config import DEFAULT_CONFIG, load_config
from lionlock.core.gating import evaluate_policy
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores
from lionlock.replay import policy_registry

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LIONLOCK_GATING_ENABLED", raising=False)
    monkeypatch.chdir(tmp_path)


def _toml(tmp_path: Path, body: str) -> str:
    path = tmp_path / "lionlock.toml"
    path.write_text(body, encoding="utf-8")
    return str(path)


def _red_bundle() -> SignalBundle:
    """A bundle the default policy blocks on its raw signals alone."""
    return SignalBundle(
        signal_schema_version="SE-0.4.0",
        signal_scores=SignalScores(
            repetition_loopiness=0.9,
            novelty_entropy_proxy=0.9,
            coherence_structure=0.9,
            context_adherence=0.9,
            hallucination_risk=0.0,
        ),
        derived_signals=DerivedSignals(0.0, 0.0, 0.0, 0.0, 0.0),
        missing_inputs=(),
    )


def _decide(config: dict) -> str:
    return evaluate_policy(
        _red_bundle(),
        thresholds=config["gating"]["thresholds"],
        gating_enabled=config["gating"]["enabled"],
        hallucination_mode=config["gating"]["hallucination_mode"],
        weights=config["signals"]["weights"],
        enabled_signals=config["signals"]["enabled"],
    ).gating_decision


def test_defaults_and_shipped_example_are_valid() -> None:
    assert lionlock_config.policy_config_problems(DEFAULT_CONFIG) == []
    config = load_config(str(REPO_ROOT / "lionlock.toml.example"))
    assert _decide(config) == "BLOCK"


def test_nan_weight_is_rejected_instead_of_turning_block_into_allow(tmp_path: Path) -> None:
    path = _toml(tmp_path, "[signals.weights]\nrepetition_loopiness = nan\n")
    with pytest.raises(ValueError) as excinfo:
        load_config(path)
    message = str(excinfo.value)
    # The error names the key, the value and the rule.
    assert "signals.weights.repetition_loopiness = nan" in message
    assert "must be a finite number >= 0" in message
    assert "lionlock.toml" in message


@pytest.mark.parametrize(
    ("body", "key", "rule"),
    [
        (
            "[signals.weights]\ncontext_adherence = inf\n",
            "signals.weights.context_adherence = inf",
            "finite number >= 0",
        ),
        (
            "[signals.weights]\ncontext_adherence = -0.5\n",
            "signals.weights.context_adherence = -0.5",
            "finite number >= 0",
        ),
        (
            "[signals.weights]\ncontext_adherence = true\n",
            "signals.weights.context_adherence = True",
            "finite number >= 0",
        ),
        ("[gating.thresholds]\nred = nan\n", "gating.thresholds.red = nan", "finite number"),
        (
            "[gating.thresholds]\nyellow = -inf\n",
            "gating.thresholds.yellow = -inf",
            "finite number",
        ),
        ('[gating.thresholds]\nred = "0.8"\n', "gating.thresholds.red = '0.8'", "finite number"),
        (
            "[gating.thresholds]\nyellow = 0.7\n",
            "gating.thresholds = {'yellow': 0.7",
            "0 <= yellow < orange < red <= 1",
        ),
        ("[gating.thresholds]\nred = 1.5\n", "'red': 1.5}", "0 <= yellow < orange < red <= 1"),
        ("[gating.thresholds]\nyellow = -0.1\n", "'yellow': -0.1", "0 <= yellow < orange < red"),
        ("[gating.thresholds]\norange = 0.8\n", "'orange': 0.8", "yellow < orange < red"),
        ("[gating]\nthresholds = 0.5\n", "gating.thresholds = 0.5", "must be a table"),
        (
            '[gating]\nhallucination_mode = "warn_onyl"\n',
            "gating.hallucination_mode = 'warn_onyl'",
            "must be one of 'warn_only', 'block'",
        ),
        ('[gating]\nhallucination_mode = ""\n', "gating.hallucination_mode = ''", "must be one of"),
        ('[gating]\nenabled = "false"\n', "gating.enabled = 'false'", "must be a boolean"),
        ("[gating]\nenabled = 0\n", "gating.enabled = 0", "must be a boolean"),
        (
            '[signals]\nenabled = ["repetition_loopyness"]\n',
            "signals.enabled = 'repetition_loopyness'",
            "unknown signal",
        ),
        (
            '[signals]\nenabled = "repetition_loopiness"\n',
            "signals.enabled = 'repetition_loopiness'",
            "must be a list",
        ),
        (
            "[signals]\nenabled = []\n",
            "signals = {'enabled': []",
            "at least one enabled signal must have a weight > 0",
        ),
        (
            '[signals]\nenabled = ["hallucination_risk"]\n',
            "signals = {'enabled': ['hallucination_risk']",
            "at least one enabled signal must have a weight > 0",
        ),
        (
            "[signals.weights]\nrepetition_loopiness = 0\nnovelty_entropy_proxy = 0\n"
            "coherence_structure = 0\ncontext_adherence = 0\n",
            "signals = {",
            "at least one enabled signal must have a weight > 0",
        ),
    ],
)
def test_each_rule_names_key_value_and_rule(tmp_path: Path, body: str, key: str, rule: str) -> None:
    path = _toml(tmp_path, body)
    with pytest.raises(ValueError) as excinfo:
        load_config(path)
    message = str(excinfo.value)
    assert key in message
    assert rule in message


def test_supported_hallucination_modes_load(tmp_path: Path) -> None:
    for mode in ("warn_only", "block"):
        config = load_config(_toml(tmp_path, f'[gating]\nhallucination_mode = "{mode}"\n'))
        assert config["gating"]["hallucination_mode"] == mode


def test_a_valid_custom_policy_loads_and_still_gates(tmp_path: Path) -> None:
    body = (
        "[gating]\nenabled = true\n"
        "[gating.thresholds]\nyellow = 0.3\norange = 0.5\nred = 0.7\n"
        '[signals]\nenabled = ["repetition_loopiness", "context_adherence"]\n'
        "[signals.weights]\nrepetition_loopiness = 1\ncontext_adherence = 0.0\n"
    )
    config = load_config(_toml(tmp_path, body))
    assert _decide(config) == "BLOCK"


def test_every_problem_is_reported_at_once(tmp_path: Path) -> None:
    body = (
        '[gating]\nhallucination_mode = "warn_onyl"\n'
        "[signals.weights]\nrepetition_loopiness = nan\n"
    )
    with pytest.raises(ValueError) as excinfo:
        load_config(_toml(tmp_path, body))
    message = str(excinfo.value)
    assert "gating.hallucination_mode" in message
    assert "signals.weights.repetition_loopiness" in message


def test_env_override_still_applies_to_live_config_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LIONLOCK_GATING_ENABLED", "false")
    config = load_config(_toml(tmp_path, "[gating]\nenabled = true\n"))
    assert config["gating"]["enabled"] is False


def test_missing_red_threshold_is_a_validation_error_not_a_later_key_error(tmp_path: Path) -> None:
    """A policy registry merged over a base config that has no ``red`` band.

    Before validation this resolved happily and the first replayed event raised ``KeyError: 'red'``
    from inside ``severity_band``.
    """
    registry = tmp_path / "policies.toml"
    registry.write_text('[policies."P-1"]\ngating.enabled = true\n', encoding="utf-8")
    base = {"gating": {"thresholds": {"yellow": 0.45, "orange": 0.65}}, "signals": {}}
    with pytest.raises(ValueError) as excinfo:
        policy_registry.resolve_policy("P-1", registry_path=str(registry), base_config=base)
    message = str(excinfo.value)
    assert "gating.thresholds.red is missing" in message
    assert "yellow, orange and red are all required" in message


def test_policy_registry_entries_are_validated(tmp_path: Path) -> None:
    registry = tmp_path / "policies.toml"
    registry.write_text(
        '[policies."P-1"]\ngating.hallucination_mode = "warn_onyl"\n'
        '[policies."P-1".signals.weights]\nrepetition_loopiness = nan\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as excinfo:
        policy_registry.resolve_policy("P-1", registry_path=str(registry))
    message = str(excinfo.value)
    assert "P-1" in message
    assert "gating.hallucination_mode = 'warn_onyl'" in message
    assert "signals.weights.repetition_loopiness = nan" in message
