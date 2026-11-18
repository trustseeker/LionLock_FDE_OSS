"""
LionLock public API surface.
Apache License 2.0; see the LICENSE file at the project root.
"""

from importlib import metadata as _metadata

from .logger import TrustVaultLogger

try:
    __version__: str = _metadata.version("lionlock")
except _metadata.PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"

__all__ = ["TrustVaultLogger", "__version__"]
