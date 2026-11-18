"""Create local log files and directories that only their owner can read.

A new file gets mode 0600 and a new directory 0700 from the ``open``/``mkdir`` call that creates
it, so it is never visible to other users, whatever the umask, not even briefly. Files and
directories that already exist keep their modes: nothing here calls ``chmod``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO, Any

PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700

# Windows opens descriptors in text mode unless told otherwise; the file objects below do their
# own newline handling, exactly as the open() calls they replace did.
_BINARY = getattr(os, "O_BINARY", 0)


def ensure_private_dir(path: str | os.PathLike[str]) -> None:
    """Create ``path`` and any missing parents with mode 0700; existing ones keep their modes."""
    directory = Path(path)
    try:
        os.mkdir(directory, PRIVATE_DIR_MODE)
    except FileNotFoundError:
        parent = directory.parent
        if parent == directory:
            raise
        ensure_private_dir(parent)
        try:
            os.mkdir(directory, PRIVATE_DIR_MODE)
        except FileExistsError:
            if not directory.is_dir():
                raise
    except FileExistsError:
        if not directory.is_dir():
            raise


def open_private_append(
    path: str | os.PathLike[str], *, binary: bool = False, readable: bool = False
) -> IO[Any]:
    """Open ``path`` for appending, creating it with mode 0600 if it does not exist.

    ``binary`` returns a bytes file object, otherwise UTF-8 text. ``readable`` also allows reads
    (``"a+"``). The parent directory must exist (see ``ensure_private_dir``).
    """
    access = os.O_RDWR if readable else os.O_WRONLY
    fd = os.open(path, access | os.O_APPEND | os.O_CREAT | _BINARY, PRIVATE_FILE_MODE)
    mode = ("a+" if readable else "a") + ("b" if binary else "")
    try:
        if binary:
            return os.fdopen(fd, mode)
        return os.fdopen(fd, mode, encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
