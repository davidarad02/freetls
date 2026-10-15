"""HTTP transports that use the freetls engine."""

from __future__ import annotations

import importlib

from .requests_adapter import JA4Adapter

__all__ = ["JA4Adapter"]

# Submodules are exposed lazily so that importing freetls.transport does not
# require the optional HTTP libraries (httpx/aiohttp). Attribute access such as
# ``freetls.transport.httpx_transport`` imports the submodule on demand.
_LAZY_SUBMODULES = {
    "requests_adapter",
    "urllib3_conn",
    "httpx_transport",
    "aiohttp_connector",
    "websocket",
    "retry",
    "proxy",
    "_http2",
    "_content",
}


def __getattr__(name: str):
    if name in _LAZY_SUBMODULES:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
