# LionLock FDE – Beta Source (1.0.0b2)

**LionLock_FDE** scores LLM replies with fixed, deterministic rules and turns those scores into a gate decision. It also provides a hash-chained local log to record those decisions in.

No AI model is involved in scoring or deciding: the same input always gives the same output. This is the **beta source** of open-source LionLock (version `1.0.0b2`), suitable for developers, researchers, and AI safety teams. Interfaces may change before 1.0.0. No premium modules or proprietary datasets are included.

---

## What it does, and what it doesn't

- **Scores** a prompt and reply with lexical heuristics: repetition, low novelty, sentence structure, and drift from the prompt's words.
- **Decides** a severity band (green, yellow, orange, red) and a suggested action (`ALLOW`, `REFRESH`, `BLOCK`), with the signal and reason that triggered it.
- **Logs** decisions you record to a local, hash-chained SQLite file you can verify. Scoring and deciding do not write the log themselves; [`examples/quickstart.py`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/examples/quickstart.py) shows the logging calls. The chain shows edited, reordered or removed rows. It cannot show that a whole log was rewritten unless you compare it with a copy of its latest hash kept somewhere the writer cannot change.

LionLock **does not stop a model call by itself**: it returns a decision, and your code acts on it (see [`docs/GATING_POLICY.md`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/docs/GATING_POLICY.md)). Its signals are text heuristics, not fact-checking: they catch loops and some structural problems but can miss a fluent, off-topic answer, and no accuracy figures have been published yet. The fatigue score is uncalibrated: LionLock does not claim to detect model fatigue, and the score is kept out of the decision when its inputs are missing.

**Language support: English only.** Scoring in 1.0 is built and checked for English text. The tokenizer matches `[A-Za-z0-9']+`, so accented and non-Latin scripts score differently from English, and their decisions are not meaningful. Other languages are planned for later releases: first a Unicode-aware tokenizer, then per-language test sets, and a language will be listed as supported only once its own results are published.

---

## 🔍 Modules Included

### ✅ Module 01 – Trust Overlay
Captures inbound signal data and emits trust records for analysis. Trust Overlay supports SQL sinks when configured; default behavior uses local file/JSONL logging.

### ✅ Module 02 – Signal Scoring Engine
Computes deterministic signal scores from a prompt and response: repetition, novelty, sentence structure, and context adherence.

### ✅ Module 03 – Drift and fatigue signals (experimental)
Flags score patterns across turns, such as rising risk and decisions that disagree with their severity. The fatigue risk index is experimental and uncalibrated; it is a heuristic, not a fatigue detector.

### ✅ Module 04 – Telemetry Logging
Logs decisions and trust records to a local, hash-chained SQLite file by default. Opt-in uploads send only allowlisted, pseudonymized fields to a receiver you run. SQL-backed telemetry remains available when explicitly enabled in config.

### ✅ Module 05 – Gating Core & Policy Engine
Computes deterministic gate decisions from trust signals. `gating.enabled` / `LIONLOCK_GATING_ENABLED` controls suggested actions versus log-only (`ALLOW`) for config-driven evaluation. Direct `evaluate_policy` calls use the `gating_enabled` argument, which defaults to `True`. Acting on the decision is up to the caller.
### ✅ Module 06 – Replay Evaluation Layer
Re-evaluates logged decisions under a chosen policy to check missed signals, drift accumulation, and gate performance.

### ✅ Module 07 – Simulation Harness
Runs generated sessions through a policy to compare profiles and gating thresholds. The sessions are synthetic, so results show how the rules behave, not how any real model performs.

---

## 🚀 Get Started

Install from [PyPI](https://pypi.org/project/lionlock/) into a fresh virtual environment
(Python 3.10 or newer). This installs the library and both commands, `lionlock-telemetry` and
`lionlock-sim`:

```bash
python -m pip install lionlock==1.0.0b2
python -c "import lionlock; print(lionlock.__version__)"
```

The version check should print `1.0.0b2`. If you use `1.0.0b1`, upgrade: b1 lacks the fixes in
the [b2 changelog](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/CHANGELOG.md).
If [PyPI's release history](https://pypi.org/project/lionlock/#history) does not list `1.0.0b2`
yet, install the same release from its tag instead (this needs Git). Release tags are never moved.

```bash
python -m pip install "lionlock @ git+https://github.com/trustseeker/LionLock_FDE_OSS.git@v1.0.0b2"
```

**Existing installations:** back up telemetry data before upgrading and **upgrade the receiver
before its clients**. Older receivers reject the b2 version label. Native `sqlite:///...` sinks
with extra custom columns now refuse startup without removing data; review the
[compatibility notes](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/CHANGELOG.md#compatibility) before proceeding. Do not delete or rebuild a
database to make an upgrade pass. Internet-facing receivers must require tokens.

Maintainers: see the [release checklist](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/docs/RELEASING.md) for the protected publishing process.

```python
from lionlock.core.scoring import score_response
from lionlock.core.gating import evaluate_policy

prompt = "What is the capital of France?"
reply = "The capital of France is Paris."

decision = evaluate_policy(score_response(prompt, reply))
print(decision.severity, decision.gating_decision, decision.reason_code)
```

For the quickstart with sample sessions, the tests, and the developer tools, clone the repository:

```bash
git clone https://github.com/trustseeker/LionLock_FDE_OSS.git
cd LionLock_FDE_OSS
bash tools/dev_setup.sh
```

Config templates: [`lionlock.toml.example`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/lionlock.toml.example) and, for database connection settings only, [`.env.example`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/.env.example). Gating is set in `lionlock.toml` or the real environment. A `.env` that LionLock finds by itself never sets gating; one you load explicitly with `load_dotenv(path)` can.

Five-minute walkthrough: [`docs/QUICKSTART.md`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/docs/QUICKSTART.md).

Audit log details: [`docs/AUDIT_LOGGING.md`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/docs/AUDIT_LOGGING.md).

---

## 📡 Telemetry

LionLock writes its telemetry to one local SQLite file, `logs/lionlock.db`, and **uploads nothing unless you opt in**. If you enable uploads, only the allowlisted, pseudonymized fields documented in [`docs/TELEMETRY.md`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/docs/TELEMETRY.md) are sent, over HTTPS, to a receiver you run. Prompts, responses, raw identifiers, and hostnames are never included, and `DO_NOT_TRACK=1` turns uploads off.

```bash
lionlock-telemetry status    # where the log is and whether uploads are enabled
lionlock-telemetry preview   # exactly what an upload would contain, without sending it
```

---

## 🤝 Contributing and security

See [`docs/CONTRIBUTING.md`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/docs/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [`SECURITY.md`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/SECURITY.md).

## License

Apache License 2.0. See [`LICENSE`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/LICENSE) and [`NOTICE`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/NOTICE).

The licence covers the code. Use of the LionLock name and logo is covered by [`TRADEMARK.md`](https://github.com/trustseeker/LionLock_FDE_OSS/blob/main/TRADEMARK.md).
