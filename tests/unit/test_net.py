"""Happy Eyeballs connect helper."""

from __future__ import annotations

import socket

import pytest

from freetls.net import happy_eyeballs


def test_happy_eyeballs_connects():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        # 'localhost' may resolve to ::1 first; HE must still reach 127.0.0.1.
        sock = happy_eyeballs("localhost", port, timeout=5)
        assert sock.fileno() >= 0
        sock.close()
    finally:
        srv.close()


def test_happy_eyeballs_unresolvable():
    with pytest.raises(OSError):
        happy_eyeballs("no-such-host.invalid", 443, timeout=1)
