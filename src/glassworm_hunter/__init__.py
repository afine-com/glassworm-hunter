"""GlassWorm Scanner - detect GlassWorm supply chain attack payloads."""

from __future__ import annotations

try:
    from importlib.metadata import version as _pkg_version
except ImportError:  # pragma: no cover
    # Not expected with requires-python >=3.10, but harmless to keep.
    from importlib_metadata import version as _pkg_version  # type: ignore

__version__ = _pkg_version("glassworm-hunter")
