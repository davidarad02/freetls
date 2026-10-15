"""An ``ssl.SSLContext``-style wrapper API for freetls.

``TLSContext`` mirrors the ergonomics of :mod:`ssl`: build a context, then
``wrap_socket()`` an already-connected socket. The difference is that the
handshake is fully described by a :class:`~freetls.model.FingerprintSpec`, so
every JA4-relevant field is under your control.
"""
from __future__ import annotations

from typing import Optional, Sequence

from .model import (
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    Extension,
    FingerprintSpec,
)
from . import modes
from .session import TLSSession


class TLSContext:
    """A reusable, configurable context for wrapping sockets with TLS."""

    def __init__(self, spec: Optional[FingerprintSpec] = None):
        self.spec = spec if spec is not None else modes.baseline_spec()

    # -- constructors --------------------------------------------------------
    @classmethod
    def baseline(cls, **kwargs) -> "TLSContext":
        return cls(modes.baseline_spec(**kwargs))

    @classmethod
    def specific(cls, **kwargs) -> "TLSContext":
        return cls(modes.specific(**kwargs))

    @classmethod
    def partial_random(cls, **kwargs) -> "TLSContext":
        return cls(modes.partial_random(**kwargs))

    @classmethod
    def true_random(cls, **kwargs) -> "TLSContext":
        return cls(modes.true_random(**kwargs))

    # -- ssl.SSLContext-like configuration ----------------------------------
    def set_ciphers(self, ciphers: Sequence[int]) -> None:
        self.spec.ciphers = list(ciphers)

    def set_alpn_protocols(self, protocols: Sequence[str]) -> None:
        existing = self.spec.find("alpn")
        if existing is not None:
            existing.strings = list(protocols)
        else:
            self.spec.extensions.append(Extension.alpn(*protocols))

    def set_alpn(self, protocols: Sequence[str]) -> None:
        self.set_alpn_protocols(protocols)

    def set_versions(self, minimum: int, maximum: int) -> None:
        self.spec.vers_min = minimum
        self.spec.vers_max = maximum
        sv = self.spec.find("supported_versions")
        if sv is not None:
            order = [TLS13, TLS12, TLS11, TLS10]
            sv.values = [v for v in order if minimum <= v <= maximum]

    def set_server_name(self, name: Optional[str]) -> None:
        self.spec.server_name = name
        sni = self.spec.find("sni")
        if name is None:
            self.spec.extensions = [e for e in self.spec.extensions if e.kind != "sni"]
        elif sni is not None:
            sni.server_name = name
        else:
            self.spec.extensions.insert(0, Extension.sni(name))

    def set_verify(self, verify: bool, root_ca: Optional[str] = None) -> None:
        self.spec.verify = verify
        self.spec.root_ca = root_ca

    def load_verify_locations(self, cafile: str) -> None:
        self.spec.verify = True
        self.spec.root_ca = cafile

    # -- wrapping ------------------------------------------------------------
    def wrap_socket(
        self,
        sock,
        server_hostname: Optional[str] = None,
        do_handshake_on_connect: bool = True,
    ) -> TLSSession:
        """Wrap an already-connected socket, performing the freetls handshake.

        Returns a socket-like :class:`~freetls.TLSSession`.
        """
        session = TLSSession(self.spec.copy())
        if do_handshake_on_connect:
            session.wrap_socket(sock, server_hostname or self.spec.server_name or "")
            return session
        # Deferred handshake: remember the socket for a later wrap_socket() call.
        session._sock = sock
        return session

    def __enter__(self) -> "TLSContext":
        return self

    def __exit__(self, *exc) -> None:
        return None
