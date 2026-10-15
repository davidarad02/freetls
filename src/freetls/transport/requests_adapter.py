"""requests integration: a drop-in HTTPAdapter using the freetls engine."""

from __future__ import annotations

from typing import Callable

from requests.adapters import HTTPAdapter

from ..model import FingerprintSpec
from .urllib3_conn import make_pool_manager


class JA4Adapter(HTTPAdapter):
    """A requests transport adapter that emits a chosen JA4 fingerprint.

    ``spec`` is a fixed :class:`FingerprintSpec`, or ``spec_factory`` is a
    callable returning a fresh spec for every connection (used by the random
    modes). Exactly one of them must be provided.
    """

    def __init__(
        self,
        spec: FingerprintSpec | None = None,
        spec_factory: Callable[[], FingerprintSpec] | None = None,
        **kwargs,
    ) -> None:
        if spec is None and spec_factory is None:
            raise ValueError("JA4Adapter requires spec= or spec_factory=")
        if spec is not None and spec_factory is not None:
            raise ValueError("provide only one of spec= or spec_factory=")
        self._spec = spec
        self._spec_factory = spec_factory
        self._last_session = None
        super().__init__(**kwargs)

    def _factory(self) -> FingerprintSpec:
        if self._spec_factory is not None:
            return self._spec_factory()
        return self._spec  # type: ignore[return-value]

    def _record_session(self, session) -> None:
        self._last_session = session

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        manager_cls = make_pool_manager(self._factory, on_session=self._record_session)
        self.poolmanager = manager_cls(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
        )

    @property
    def last_session(self):
        """The most recent :class:`~freetls.TLSSession` (or None)."""
        return self._last_session

    @property
    def last_ja4(self):
        s = self._last_session
        return s.ja4 if s is not None else None

    @property
    def last_ja3(self):
        s = self._last_session
        return s.ja3 if s is not None else None

    @property
    def last_ja4s(self):
        s = self._last_session
        return s.ja4s if s is not None else None

    def cert_verify(self, conn, url, verify, cert) -> None:
        # Certificate verification is delegated to the native engine.
        return None

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(
            request, verify, cert
        )
        # We do not use urllib3's ssl_context; drop TLS-specific pool kwargs so
        # connections are not keyed/pooled by an unused context.
        pool_kwargs.pop("ssl_context", None)
        return host_params, pool_kwargs
