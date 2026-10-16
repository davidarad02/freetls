"""Native engine binding (cffi) for freetls.

See :mod:`freetls.engine._cffi` for the implementation. This package exposes a
small, stable surface: the library version, preset helpers, and the session
handle wrapper.
"""

from ._cffi import (
    EngineSession,
    EngineState,
    abi_version,
    active_sessions,
    chlo_raw,
    preset_list,
    preset_raw,
    preset_raw_opts,
    spec_raw,
    supported_ciphers,
    supported_extensions,
    version,
)

__all__ = [
    "EngineSession",
    "EngineState",
    "version",
    "abi_version",
    "preset_list",
    "preset_raw",
    "preset_raw_opts",
    "chlo_raw",
    "spec_raw",
    "supported_ciphers",
    "supported_extensions",
    "active_sessions",
]
