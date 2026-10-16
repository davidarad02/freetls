"""Native engine binding (cffi) for freetls.

See :mod:`freetls.engine._cffi` for the implementation. This package exposes a
small, stable surface: the library version, preset helpers, and the session
handle wrapper.
"""

from ._cffi import (
    Engine,
    EngineInfo,
    EngineSession,
    EngineState,
    abi_version,
    active_sessions,
    chlo_raw,
    current_engine,
    engine_context,
    preset_list,
    preset_raw,
    preset_raw_opts,
    quic_id_list,
    quic_id_raw,
    spec_raw,
    supported_ciphers,
    supported_extensions,
    use_engine,
    use_engine_file,
    version,
)

__all__ = [
    "Engine",
    "EngineInfo",
    "EngineSession",
    "EngineState",
    "version",
    "abi_version",
    "preset_list",
    "preset_raw",
    "preset_raw_opts",
    "chlo_raw",
    "spec_raw",
    "quic_id_list",
    "quic_id_raw",
    "supported_ciphers",
    "supported_extensions",
    "active_sessions",
    "use_engine",
    "use_engine_file",
    "current_engine",
    "engine_context",
]
