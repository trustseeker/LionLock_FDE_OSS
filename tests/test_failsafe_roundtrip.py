"""The failsafe extra encrypts an event that only the configured key can read back.

Skipped when ``cryptography`` (the ``failsafe`` extra) is not installed.
"""

import json
from pathlib import Path

import pytest

from lionlock.logging import failsafe

fernet = pytest.importorskip("cryptography.fernet")


def test_file_event_round_trips_and_is_not_plain_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = fernet.Fernet.generate_key()
    monkeypatch.setenv("LIONLOCK_TEST_FAILSAFE_KEY", key.decode("utf-8"))
    path = tmp_path / "events.encjsonl"
    config = {
        "failsafe": {
            "enabled": True,
            "trigger_mode": "catastrophic_only",
            "key_env": "LIONLOCK_TEST_FAILSAFE_KEY",
            "storage": "file",
            "file_path": str(path),
        }
    }
    payload = {"request_id": "synthetic-event", "decision": "BLOCK"}

    ok, _ = failsafe.record_failsafe_event(config, payload)

    assert ok
    (line,) = path.read_text(encoding="utf-8").splitlines()
    assert "synthetic-event" not in line
    assert json.loads(fernet.Fernet(key).decrypt(line.encode("utf-8"))) == payload
    other = fernet.Fernet(fernet.Fernet.generate_key())
    with pytest.raises(fernet.InvalidToken):
        other.decrypt(line.encode("utf-8"))
