"""Exception types for freetls."""

from __future__ import annotations


class FreeTLSError(Exception):
    """Base class for all freetls errors."""


class EngineError(FreeTLSError):
    """The native engine failed to load, or a native call failed."""


class SpecError(FreeTLSError):
    """An invalid fingerprint specification."""


class HandshakeError(FreeTLSError):
    """The TLS handshake failed."""

    def __init__(self, message: str, state: dict | None = None):
        super().__init__(message)
        self.state = state or {}


class FingerprintError(FreeTLSError):
    """A fingerprint could not be computed."""
