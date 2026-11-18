from __future__ import annotations

import copy
import math
import os
import warnings
from pathlib import Path
from typing import Any, Dict, List, Mapping

from lionlock.core.scoring import DEFAULT_SIGNAL_WEIGHTS
from lionlock.logging.connection import build_postgres_dsn
try:
    import tomllib  # py>=3.11
except ModuleNotFoundError:  # pragma: no cover - fallback for older runtimes
    import tomli as tomllib

DEFAULT_CONFIG: Dict[str, Any] = {
    "llm": {
        "base_url": "http://localhost:11434",
        "model": "llama3.1:8b",
        "preferred_api": "openai_compat",
        "fallback_api": "ollama_native",
        "timeout_s": 60,
        "api_key_env": "",
    },
    "gating": {
        "enabled": True,
        "thresholds": {"yellow": 0.45, "orange": 0.65, "red": 0.80},
        "hallucination_mode": "warn_only",
        "hard_gate_show_reason": True,
        "show_disable_warning": True,
    },
    "signals": {
        "enabled": [
            "repetition_loopiness",
            "novelty_entropy_proxy",
            "coherence_structure",
            "context_adherence",
            "hallucination_risk",
        ],
        "weights": {
            "repetition_loopiness": 0.30,
            "novelty_entropy_proxy": 0.25,
            "coherence_structure": 0.25,
            "context_adherence": 0.20,
            "hallucination_risk": 0.00,
        },
    },
    "ui": {
        "show_dev_panel": False,
        "show_soft_gate_details": False,
        "graph_history_points": 40,
        "buffered_scoring": True,
        "buffered_chunk_chars": 80,
        "buffered_tick_ms": 50,
    },
    "trust_overlay": {
        "profile": "STANDARD",
        "trust_logic_version": "TO-0.1.0",
        "runtime_mode": "oss",
        "score_window_n": 50,
        "volatility_window_n": 20,
        "drift_lookback_days": 30,
        "drift_min_points": 20,
        "volatility_spike_threshold": 0.2,
        "sql": {
            "enabled": False,
            "backend": "sqlite3",
            "dsn": "",
            "sqlite_path": "",
            "table": "trust_overlay_records",
            "batch_size": 50,
            "flush_interval_ms": 1000,
            "connect_timeout_s": 5,
        },
    },
    "telemetry": {
        "sessions_table": "lionlock_sessions",
        "version_mode": "package",
        "lionlock_version": "",
    },
    "logging": {
        "enabled": True,
        "backend": "sqlite",
        "path": "logs/lionlock_events.jsonl",
        "sqlite_path": "logs/lionlock.db",
        "sqlite_max_rows": 100000,
        "verbosity": "normal",
        "retention_events": 2000,
        "content_policy": "signals_only",
        "notes_allowlist": [],
        "notes_max_length": 120,
    },
    "logging_sql": {
        "enabled": False,
        "token": "",
        "uri": "",
        "table": "lionlock_signals",
        "batch_size": 50,
        "flush_interval_ms": 1000,
        "connect_timeout_s": 5,
        "failsafe": False,
        "token_auth": {
            "enabled": False,
            "mode": "required",
            "required": False,
            "token_env": "LIONLOCK_LOG_TOKEN",
            "token_path": "",
            "token_hashes": [],
            "token_hashes_path": "",
            "token_db_uri": "",
            "refresh_interval_s": 60,
        },
    },
    "telemetry_upload": {
        "enabled": False,
        "endpoint": "",
        "token_env": "LIONLOCK_UPLOAD_TOKEN",
        "token_path": "",
        "ca_file": "",
        "outbox_dir": "",
        "interval_hours": 24,
        "rows_per_snapshot": 20000,
        "timeout_s": 30,
    },
    "failsafe": {
        "enabled": False,
        "trigger_mode": "catastrophic_only",
        "encrypt": True,
        "key_env": "LIONLOCK_FAILSAFE_KEY_B64",
        "storage": "file",
        "file_path": "logs/failsafe_events.encjsonl",
        "sql_table": "lionlock_failsafe",
    },
    "anomaly": {
        "enabled": True,
        "db_uri": "sqlite:///logs/lionlock_anomalies.db",
        "table": "lionlock_anomalies",
        "diagnostics_table": "lionlock_session_diagnostics",
        "user_escalation_threshold": 3,
        "repeat_type_threshold": 3,
        "fatigue_spike_delta": 0.25,
        "hallucination_jump_delta": 0.3,
        "minor_signal_threshold": 0.75,
        "congestion_signature_threshold": 0.6,
        "congestion_window_n": 20,
        "degradation_window_n": 20,
        "degradation_min_points": 12,
        "degradation_delta": 0.08,
        "missed_warn_threshold": 0.75,
        "missed_block_threshold": 0.9,
        "weights": {
            "minor_signal_drift": 0.20,
            "fatigue_spike": 0.40,
            "hallucination_jump": 0.50,
            "scoring_nan": 0.60,
            "gate_mismatch": 0.70,
            "prompt_injection_suspected": 0.80,
            "gate_override_failure": 1.00,
            "model_degradation": 0.55,
            "model_congestion": 0.45,
            "missed_signal_event": 0.90,
        },
        "severity_bands": {"normal_max": 0.30, "unstable_max": 0.60, "critical_min": 0.61},
    },
}


def _merge_dict(default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for key, default_value in default.items():
        if key not in override:
            merged[key] = copy.deepcopy(default_value)
            continue
        override_value = override[key]
        if isinstance(default_value, dict) and isinstance(override_value, dict):
            merged[key] = _merge_dict(default_value, override_value)
        else:
            merged[key] = override_value
    for key, value in override.items():
        if key not in merged:
            merged[key] = value
    return merged


def _parse_env_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "f", "no", "n", "off"}:
        return False
    return None


def resolve_gating_enabled(config: Dict[str, Any]) -> bool:
    """Resolve gating enablement from environment override or config defaults."""
    override = _parse_env_bool(os.getenv("LIONLOCK_GATING_ENABLED", ""))
    if override is not None:
        return override
    gating_cfg = config.get("gating", {}) if isinstance(config, dict) else {}
    if isinstance(gating_cfg, dict):
        return bool(gating_cfg.get("enabled", True))
    return True


# Every value core/gating.py acts on. gating.py compares the mode with "warn_only" and treats any
# other string as "block", so without this list a misspelling such as "warn_onyl" would silently
# switch hallucination-risk demotion off.
SUPPORTED_HALLUCINATION_MODES = ("warn_only", "block")
THRESHOLD_KEYS = ("yellow", "orange", "red")
KNOWN_SIGNALS = tuple(DEFAULT_SIGNAL_WEIGHTS)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_finite_number(value: Any) -> bool:
    if not _is_number(value):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:  # an int too large for a float is not a usable setting either
        return False


def policy_config_problems(config: Mapping[str, Any]) -> List[str]:
    """Return every reason the gating and signal settings in ``config`` cannot be used.

    Each entry names the key, the offending value and the rule it breaks. A key that is absent
    means "use the gating default", exactly as ``evaluate_policy`` treats it, except that a
    thresholds table must be complete: ``severity_band`` indexes all three bands.

    The rules exist because every one of these settings fails *open* when it is wrong. TOML
    accepts ``nan`` and ``inf``; a NaN weight makes the aggregate NaN, which gating reads as risk
    0.0, so a response that should be blocked is allowed. A NaN or inverted threshold, an
    all-zero weight vector and an unknown mode name all lower or remove a gate the same way.
    """
    problems: List[str] = []

    def problem(key: str, value: Any, rule: str) -> None:
        problems.append(f"{key} = {value!r}: {rule}")

    gating = config.get("gating", {})
    if not isinstance(gating, Mapping):
        problem("gating", gating, "must be a table")
        gating = {}
    signals = config.get("signals", {})
    if not isinstance(signals, Mapping):
        problem("signals", signals, "must be a table")
        signals = {}

    if "enabled" in gating and not isinstance(gating["enabled"], bool):
        problem("gating.enabled", gating["enabled"], "must be a boolean (true or false)")

    if "hallucination_mode" in gating:
        mode = gating["hallucination_mode"]
        if mode not in SUPPORTED_HALLUCINATION_MODES:
            problem(
                "gating.hallucination_mode",
                mode,
                "must be one of " + ", ".join(repr(m) for m in SUPPORTED_HALLUCINATION_MODES),
            )

    if "thresholds" in gating:
        thresholds = gating["thresholds"]
        if not isinstance(thresholds, Mapping):
            problem("gating.thresholds", thresholds, "must be a table of yellow, orange and red")
        else:
            usable = True
            for band in THRESHOLD_KEYS:
                key = f"gating.thresholds.{band}"
                if band not in thresholds:
                    problems.append(f"{key} is missing: yellow, orange and red are all required")
                    usable = False
                elif not _is_finite_number(thresholds[band]):
                    problem(key, thresholds[band], "must be a finite number")
                    usable = False
            if usable:
                yellow, orange, red = (thresholds[band] for band in THRESHOLD_KEYS)
                if not 0.0 <= yellow < orange < red <= 1.0:
                    problem(
                        "gating.thresholds",
                        {band: thresholds[band] for band in THRESHOLD_KEYS},
                        "must satisfy 0 <= yellow < orange < red <= 1",
                    )

    enabled = signals.get("enabled")
    enabled_names: List[str] | None = None
    if "enabled" in signals:
        if not isinstance(enabled, list) or not all(isinstance(n, str) for n in enabled):
            problem("signals.enabled", enabled, "must be a list of signal names")
        else:
            enabled_names = list(enabled)
            for name in enabled_names:
                if name not in KNOWN_SIGNALS:
                    problem(
                        "signals.enabled",
                        name,
                        "unknown signal; known signals are " + ", ".join(KNOWN_SIGNALS),
                    )

    weights = signals.get("weights")
    weight_map: Mapping[str, Any] | None = None
    if "weights" in signals:
        if not isinstance(weights, Mapping):
            problem("signals.weights", weights, "must be a table of signal weights")
        else:
            weight_map = weights
            for name, value in weights.items():
                if not _is_finite_number(value) or value < 0:
                    problem(f"signals.weights.{name}", value, "must be a finite number >= 0")

    # The aggregate is a weighted mean over the enabled signals. If no enabled signal carries
    # weight it is 0.0 for every response, so the raw-signal channel can never gate anything.
    # Mirror aggregate_score: an absent or empty weights table means the default weights, and an
    # absent enabled list means every signal.
    if not problems:
        effective_weights = weight_map if weight_map else DEFAULT_SIGNAL_WEIGHTS
        effective_enabled = enabled_names if enabled_names is not None else list(KNOWN_SIGNALS)
        if not any(effective_weights.get(name, 0.0) > 0 for name in effective_enabled):
            problem(
                "signals",
                {"enabled": effective_enabled, "weights": dict(effective_weights)},
                "at least one enabled signal must have a weight > 0",
            )
    return problems


def validate_policy_config(config: Mapping[str, Any], *, source: str = "config") -> None:
    """Raise ``ValueError`` listing every problem ``policy_config_problems`` finds."""
    problems = policy_config_problems(config)
    if problems:
        raise ValueError(f"invalid {source}: " + "; ".join(problems))


def load_config(path: str = "lionlock.toml") -> Dict[str, Any]:
    """Load config with safe defaults; missing files are non-fatal, invalid settings are not.

    ``LIONLOCK_GATING_ENABLED`` overrides ``gating.enabled`` here, for live use. Replay does not
    go through this override; it uses the ``gating.enabled`` its policy records.
    """
    config = copy.deepcopy(DEFAULT_CONFIG)
    config_path = Path(path)
    if config_path.exists():
        try:
            with config_path.open("rb") as handle:
                raw = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            # Never fall back to defaults silently: a typo would quietly switch off token auth,
            # failsafe and custom thresholds while the operator believes they are on.
            raise ValueError(f"cannot load {config_path}: {exc}") from exc
        config = _merge_dict(config, raw)

    validate_policy_config(config, source=f"config {config_path}")
    config.setdefault("gating", {})
    config["gating"]["enabled"] = resolve_gating_enabled(config)

    logging_cfg = config.get("logging", {})
    sql_cfg = config.get("logging_sql", {})
    env_token = os.getenv("LIONLOCK_TELEMETRY_TOKEN", "").strip() or os.getenv(
        "LIONLOCK_SQL_TOKEN", ""
    ).strip()
    if env_token:
        sql_cfg["token"] = env_token
    # The SQL sink is opt-in: the environment may say where the database is, never whether to use
    # it. Credentials present for some other tool must not switch it on (or crash startup).
    if sql_cfg.get("enabled"):
        telemetry_db_uri = os.getenv("LIONLOCK_TELEMETRY_DB_URI", "").strip()
        if not telemetry_db_uri and not str(sql_cfg.get("uri", "")).strip():
            try:
                telemetry_db_uri = build_postgres_dsn("writer")
            except Exception:
                telemetry_db_uri = ""
        if telemetry_db_uri:
            sql_cfg["uri"] = telemetry_db_uri
    backend = str(logging_cfg.get("backend") or "sqlite").lower()
    if sql_cfg.get("enabled") and backend not in {"sql", "both"}:
        raise RuntimeError("SQL telemetry requires logging.backend to be 'sql' or 'both'.")
    if sql_cfg.get("enabled") and not (
        str(sql_cfg.get("token", "")).strip() or str(sql_cfg.get("uri", "")).strip()
    ):
        raise RuntimeError("logging_sql.token or uri is required when SQL telemetry is enabled.")
    if sql_cfg.get("enabled") and logging_cfg.get("content_policy") != "signals_only":
        logging_cfg["content_policy"] = "signals_only"
        warnings.warn(
            "logging.content_policy forced to signals_only for public SQL telemetry.",
            RuntimeWarning,
        )
    return config
