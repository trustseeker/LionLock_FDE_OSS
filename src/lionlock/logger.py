from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Dict, Iterator

from lionlock.utils.chain_verifier import (
    CURRENT_FORMAT,
    FORMAT_KEY,
    GENESIS_HASH,
    TamperDetectedError,
    format_2_hash,
    verify_chain_file,
)
from lionlock.utils.jcs import canonical_bytes
from lionlock.utils.private_files import (
    PRIVATE_FILE_MODE,
    ensure_private_dir,
    open_private_append,
)

try:  # POSIX: an advisory lock shared by every process appending to the same file.
    import fcntl
except ImportError:  # pragma: no cover - Windows; the in-process lock still applies.
    fcntl = None  # type: ignore[assignment]

_TAIL_BLOCK = 64 * 1024
_PROCESS_LOCK = threading.Lock()


@contextmanager
def _locked(handle: IO[Any]) -> Iterator[None]:
    with _PROCESS_LOCK:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _last_line(handle: IO[bytes]) -> bytes:
    """The last line of the file, read backwards from the end so appends stay O(1)."""
    handle.seek(0, os.SEEK_END)
    end = handle.tell()
    data = b""
    position = end
    while position > 0:
        step = min(_TAIL_BLOCK, position)
        position -= step
        handle.seek(position)
        data = handle.read(step) + data
        # Trailing whitespace-only lines are not entries; skip them as the original reader did.
        if data.rstrip().count(b"\n") >= 1:
            break
    return data.rstrip().rsplit(b"\n", 1)[-1]


class TrustVaultLogger:
    """Minimal append-only logger with tamper-evident hash chaining.

    Appends are serialized across threads, and across processes on POSIX, so the chain head read
    and the append happen atomically. A damaged last line stops further writes instead of silently
    starting a new chain.

    Entries are written in format 2: strict canonical JSON (``docs/AUDIT_LOGGING.md``), hashed and
    written in the same encoding. A new log file is created owner-only (0600), and new parent
    directories 0700; an existing file keeps its mode.
    """

    def __init__(self, path: str | Path = "trustvault.log") -> None:
        self.path = Path(path)

    def _head_from(self, handle: IO[bytes]) -> str:
        line = _last_line(handle)
        if not line.strip():
            return GENESIS_HASH
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TamperDetectedError(
                f"last entry of {self.path} is damaged (partial or invalid JSON); "
                "refusing to append, run verify_chain()"
            ) from exc
        digest = parsed.get("sha256") if isinstance(parsed, dict) else None
        if not isinstance(digest, str) or len(digest) != 64:
            raise TamperDetectedError(
                f"last entry of {self.path} has no valid sha256; refusing to append"
            )
        return digest

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        with self.path.open("rb") as handle:
            return self._head_from(handle)

    def record(self, event: str, payload: Dict[str, Any]) -> None:
        """Append one entry.

        ``event`` and ``payload`` must have a canonical form: text keys only, finite numbers
        only, integers within +/-(2**53 - 1), and only dicts, lists, tuples, strings, numbers,
        booleans and None. Otherwise ``ValueError`` (``CanonicalFormError``) names the offending
        path, and nothing is created or written.
        """
        # Checked before any file or directory is touched, so a refused call changes nothing.
        canonical_bytes({"event": event, "payload": payload})
        ensure_private_dir(self.path.parent)
        with open_private_append(self.path, binary=True, readable=True) as handle, _locked(handle):
            entry = {
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "event": event,
                FORMAT_KEY: CURRENT_FORMAT,
                "payload": payload,
                "prev_hash": self._head_from(handle),
            }
            entry["sha256"] = format_2_hash(entry)
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_bytes(entry) + b"\n")
            handle.flush()

    def head(self) -> tuple[int, str]:
        """``(entry_count, last_sha256)``. Store it outside the log to detect truncation later."""
        count = 0
        last = GENESIS_HASH
        if self.path.exists():
            # Under the append lock, so count and hash describe one state of the file.
            with self.path.open("rb") as handle, _locked(handle):
                for line in handle:
                    if line.strip():
                        count += 1
                last = self._head_from(handle) if count else GENESIS_HASH
        return count, last

    def verify_chain(
        self, *, expected_head: str | None = None, expected_count: int | None = None
    ) -> None:
        """Verify the on-disk chain; raises if tampering is detected.

        A self-contained hash chain cannot tell that its newest entries were removed. Pass a
        ``head()`` recorded elsewhere as ``expected_head``/``expected_count`` to detect that too.
        """
        if not self.path.exists() and expected_count == 0 and expected_head in (None, GENESIS_HASH):
            # head() of a log that was never written is (0, GENESIS_HASH); that state verifies.
            return
        verify_chain_file(self.path, expected_head=expected_head, expected_count=expected_count)

    def flush(self) -> None:
        """Synchronous logger; nothing buffered, but ensure file exists for readers."""
        ensure_private_dir(self.path.parent)
        self.path.touch(mode=PRIVATE_FILE_MODE, exist_ok=True)

    def close(self) -> None:
        """Idempotent close for API symmetry; delegates to flush."""
        self.flush()
