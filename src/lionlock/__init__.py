"""
LionLock public API surface.
Apache License 2.0; see the LICENSE file at the project root.
"""

from typing import Any

from .logger import TrustVaultLogger

__all__ = ["TrustVaultLogger", "__version__"]


def __getattr__(name: str) -> Any:
    # ``__version__`` is looked up on first use, not at import. ``importlib.metadata`` pulls in
    # zipfile and, through it, ``random``; importing it here would put both on the scoring core's
    # import path, which tests/test_offline_runtime_guarantees.py keeps free of them.
    if name == "__version__":
        from importlib import metadata

        try:
            return metadata.version("lionlock")
        except metadata.PackageNotFoundError:  # a source tree that was never installed
            return "0+unknown"
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
