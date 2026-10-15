"""Native engine binding (cffi) for freetls.

See :mod:`freetls.engine._cffi` for the implementation. This package exposes a
small, stable surface: the library version, preset helpers, and the session
handle wrapper.
"""
from ._cffi import (
    EngineSession,
    EngineState,
    chlo_raw,
    preset_list,
    preset_raw,
    preset_raw_opts,
    version,
)

__all__ = [
    "EngineSession",
    "EngineState",
    "version",
    "preset_list",
    "preset_raw",
    "preset_raw_opts",
    "chlo_raw",
]
