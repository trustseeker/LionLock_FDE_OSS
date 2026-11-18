"""Hash-chain verification helpers for append-only LionLock logs.

Two entry formats exist, and one chain may hold both:

- **Format 2** (written since 1.0.0b2) carries ``"format": 2``. Its hash is SHA-256 over the
  strict canonical JSON of the entry without ``sha256`` (RFC 8785, see ``lionlock.utils.jcs``
  and ``docs/AUDIT_LOGGING.md``), so any language can verify it.
- **Legacy** entries have no ``format`` member. Their hash is SHA-256 over Python's
  ``json.dumps(..., sort_keys=True, separators=(",", ":"))``. They are verified exactly as before,
  including their known false mismatches (see ``legacy_entry_hash``); old logs are never rewritten.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from lionlock.utils.jcs import CanonicalFormError, canonical_bytes

GENESIS_HASH = "0" * 64

FORMAT_KEY = "format"
CURRENT_FORMAT = 2
FORMAT_2_FIELDS = frozenset({"ts", "event", FORMAT_KEY, "payload", "prev_hash", "sha256"})


class TamperDetectedError(RuntimeError):
    """Raised when a hash chain break indicates probable tampering."""


def canonical_serialize(entry: dict[str, Any]) -> str:
    """The legacy (unmarked) serialization: Python ``json.dumps`` with sorted keys.

    Not portable: it writes Python's float repr and ``NaN``/``Infinity``, and it sorts integer
    keys numerically although they are read back as text. Kept only to verify legacy entries.
    """
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def legacy_entry_hash(entry: dict[str, Any]) -> str:
    """Hash of an unmarked entry, computed exactly as before format 2 existed."""
    payload = {key: value for key, value in entry.items() if key != "sha256"}
    return hashlib.sha256(canonical_serialize(payload).encode("utf-8")).hexdigest()


def is_format_2(entry: dict[str, Any]) -> bool:
    """True for an entry marked ``"format": 2``. A JSON number equal to 2 counts, as it would in
    any other language; ``true`` does not."""
    marker = entry.get(FORMAT_KEY)
    return (
        isinstance(marker, (int, float))
        and not isinstance(marker, bool)
        and marker == CURRENT_FORMAT
    )


def format_2_hash(entry: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of a format 2 entry without its ``sha256`` member.

    Raises ``CanonicalFormError`` if the entry holds a value with no canonical form.
    """
    body = {key: value for key, value in entry.items() if key != "sha256"}
    return hashlib.sha256(canonical_bytes(body, exact_integers=False)).hexdigest()


def entry_hash(entry: dict[str, Any]) -> str:
    """The hash an entry must carry: format 2 rule if it is marked, the legacy rule otherwise."""
    if FORMAT_KEY not in entry:
        return legacy_entry_hash(entry)
    if not is_format_2(entry):
        raise ValueError("unsupported entry format")
    return format_2_hash(entry)


def _expected_hash(entry: dict[str, Any], number: int) -> str:
    if FORMAT_KEY not in entry:
        return legacy_entry_hash(entry)
    if not is_format_2(entry):
        marker = repr(entry.get(FORMAT_KEY))[:40]
        raise TamperDetectedError(f"Entry #{number} has unsupported format {marker}")
    if set(entry) != FORMAT_2_FIELDS:
        raise TamperDetectedError(
            f"Entry #{number} does not have exactly the format 2 fields "
            f"({', '.join(sorted(FORMAT_2_FIELDS))})"
        )
    try:
        return format_2_hash(entry)
    except CanonicalFormError as exc:
        raise TamperDetectedError(
            f"Entry #{number} is not in canonical form ({exc.path}: {exc.problem})"
        ) from exc


def verify_chain(
    entries: Iterable[dict[str, Any]],
    *,
    expected_head: str | None = None,
    expected_count: int | None = None,
) -> None:
    """Validate prev_hash links and hashes for each chain entry.

    The chain alone detects edited, inserted, reordered and leading-removed entries. Removing the
    newest entries, or rewriting the whole log, is detected only against a head recorded outside
    the log: pass it as ``expected_head`` (last ``sha256``) and/or ``expected_count``. A log that
    has grown since the head was recorded passes as long as the recorded head is still in it.

    Each entry is checked by its own format's rule, so a legacy log that later gained format 2
    entries verifies as one chain.
    """
    previous_hash = GENESIS_HASH
    seen_head = expected_head is None or expected_head == GENESIS_HASH
    count = 0
    for count, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise TamperDetectedError(f"Entry #{count} is not an object")
        expected_prev = entry.get("prev_hash")
        if expected_prev != previous_hash:
            raise TamperDetectedError(f"Entry #{count} prev_hash mismatch")
        current_hash = str(entry.get("sha256") or "")
        expected_hash = _expected_hash(entry, count)
        if current_hash != expected_hash:
            raise TamperDetectedError(f"Entry #{count} hash mismatch")
        previous_hash = current_hash
        if expected_count is not None and count == expected_count and expected_head is not None:
            if current_hash != expected_head:
                raise TamperDetectedError(f"Entry #{count} is not the recorded head")
        if current_hash == expected_head:
            seen_head = True
    if expected_count is not None and count < expected_count:
        raise TamperDetectedError(
            f"Log holds {count} entries but {expected_count} were recorded (truncated)"
        )
    if not seen_head:
        raise TamperDetectedError("Recorded head is not in the log (truncated or rewritten)")


def verify_chain_file(
    path: str | Path,
    *,
    expected_head: str | None = None,
    expected_count: int | None = None,
) -> None:
    """Load JSONL entries from disk and validate their hash chain (see ``verify_chain``)."""
    log_path = Path(path)
    if not log_path.exists():
        raise TamperDetectedError(f"Log file does not exist: {log_path}")
    entries: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise TamperDetectedError(f"Invalid JSON at line {line_number}") from exc
            if not isinstance(parsed, dict):
                raise TamperDetectedError(f"Invalid JSON object at line {line_number}")
            entries.append(parsed)
    verify_chain(entries, expected_head=expected_head, expected_count=expected_count)
