"""Lazy access to the optional SQLAlchemy dependency.

LionLock's SQL sinks and readers use SQLAlchemy only for non-SQLite URIs, and only when it is
installed. Importing it at module import time loads a large package even when SQL is disabled, so
the modules call :func:`load_sqlalchemy` at the point a SQLAlchemy code path actually runs.
"""

from __future__ import annotations

import sys
from typing import Any, Tuple


def load_sqlalchemy() -> Tuple[Any, Any]:
    """Return ``(create_engine, text)``, or ``(None, None)`` when SQLAlchemy cannot be imported.

    Python caches a successful import, so repeated calls are cheap.
    """
    try:
        from sqlalchemy import create_engine, text
    except Exception:
        return None, None
    return create_engine, text


def loaded_sqlalchemy_exc() -> Any:
    """Return ``sqlalchemy.exc`` if SQLAlchemy is already loaded, else ``None``; never imports it.

    Any exception SQLAlchemy raised means the package is loaded, so error classification does not
    need to import it.
    """
    return sys.modules.get("sqlalchemy.exc")
