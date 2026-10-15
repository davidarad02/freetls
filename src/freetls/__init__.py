"""freetls: an HTTPS/TLS client with highly controllable JA4 fingerprints."""

from __future__ import annotations

from . import modes, sse, verify
from .constants import Cipher, ExtensionType, NamedGroup, SignatureScheme
from .context import TLSContext
from .engine import version as engine_version
from .errors import (
    EngineError,
    FingerprintError,
    FreeTLSError,
    HandshakeError,
    SpecError,
)
from .fingerprint import (
    ja3_from_bytes,
    ja4_from_bytes,
    ja4h,
    ja4h_from_request,
    ja4l,
    ja4s_from_bytes,
    ja4t,
    ja4ts,
    ja4x,
    ja4x_from_cert,
    parse_client_hello,
    parse_server_hello,
)
from .model import (
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    Extension,
    FingerprintSpec,
    get_default_verify,
    set_default_verify,
)
from .session import TLSSession

__version__ = "0.0.1"

__all__ = [
    "__version__",
    "engine_version",
    "FingerprintSpec",
    "Extension",
    "set_default_verify",
    "get_default_verify",
    "Cipher",
    "ExtensionType",
    "SignatureScheme",
    "NamedGroup",
    "TLSSession",
    "TLSContext",
    "modes",
    "verify",
    "sse",
    "JA4Adapter",
    "transport",
    "ja4_from_bytes",
    "ja3_from_bytes",
    "ja4s_from_bytes",
    "parse_client_hello",
    "parse_server_hello",
    "ja4x",
    "ja4x_from_cert",
    "ja4t",
    "ja4ts",
    "ja4l",
    "ja4h",
    "ja4h_from_request",
    "FreeTLSError",
    "EngineError",
    "SpecError",
    "HandshakeError",
    "FingerprintError",
    "TLS10",
    "TLS11",
    "TLS12",
    "TLS13",
]


def __getattr__(name):
    """Lazily expose HTTP transports so the core needs no requests/httpx."""
    if name in ("transport", "JA4Adapter"):
        import importlib

        mod = importlib.import_module(f"{__name__}.transport")
        return mod if name == "transport" else mod.JA4Adapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
