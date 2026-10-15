"""End-to-end tests for the requests adapter."""

from __future__ import annotations

import warnings

import pytest

requests = pytest.importorskip("requests")
import freetls
from freetls.transport import JA4Adapter


def _session(spec):
    s = requests.Session()
    s.mount("https://", JA4Adapter(spec=spec))
    return s


def test_requests_get(tls_server_13):
    spec = freetls.modes.baseline_spec(server_name="localhost")
    s = _session(spec)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = s.get(f"https://127.0.0.1:{tls_server_13.port}/", verify=False)
    assert r.status_code == 200
    assert "HTML" in r.text


def test_adapter_reports_last_ja4(tls_server_13):
    spec = freetls.modes.baseline_spec(server_name="localhost")
    adapter = JA4Adapter(spec=spec)
    s = requests.Session()
    s.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = s.get(f"https://127.0.0.1:{tls_server_13.port}/", verify=False)
    assert r.status_code == 200
    assert adapter.last_ja4 is not None
    assert adapter.last_ja4.startswith("t13d")
    assert adapter.last_ja3 and len(adapter.last_ja3) == 32


def test_adapter_random_mode_factory(tls_server_13):
    adapter = JA4Adapter(
        spec_factory=lambda: freetls.modes.true_random(
            server_name="localhost", seed=None, n_ciphers=70, n_extensions=30
        )
    )
    s = requests.Session()
    s.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = s.get(f"https://127.0.0.1:{tls_server_13.port}/", verify=False)
    assert r.status_code == 200
    assert adapter.last_ja4.startswith("t13")


def test_adapter_requires_spec():
    with pytest.raises(ValueError):
        JA4Adapter()
    with pytest.raises(ValueError):
        JA4Adapter(spec=freetls.modes.baseline_spec(), spec_factory=lambda: None)


def test_pooling_reuses_connection(tls_server_13):
    spec = freetls.modes.baseline_spec(server_name="localhost")
    adapter = JA4Adapter(spec=spec)
    s = requests.Session()
    s.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s.get(f"https://127.0.0.1:{tls_server_13.port}/", verify=False)
        ja4_a = adapter.last_ja4
        s.get(f"https://127.0.0.1:{tls_server_13.port}/", verify=False)
        ja4_b = adapter.last_ja4
    assert ja4_a == ja4_b
