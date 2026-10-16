"""Happy Eyeballs (RFC 8305) TCP connect.

``socket.create_connection`` tries addresses sequentially, so a dual-stack host
whose first address is unreachable stalls until the timeout. This helper starts
the next address a short delay after the previous one (alternating address
families) and returns the first connection that completes.
"""

from __future__ import annotations

import select
import socket
import time

__all__ = ["happy_eyeballs"]

# RFC 8305 §5 recommends a short delay between connection attempts.
HE_DELAY = 0.25


def _interleave(infos: list) -> list:
    """Order addresses so families alternate, preferring IPv6 first."""
    v6 = [i for i in infos if i[0] == socket.AF_INET6]
    v4 = [i for i in infos if i[0] == socket.AF_INET]
    other = [i for i in infos if i[0] not in (socket.AF_INET6, socket.AF_INET)]
    ordered = []
    while v6 or v4:
        if v6:
            ordered.append(v6.pop(0))
        if v4:
            ordered.append(v4.pop(0))
    return ordered + other


def happy_eyeballs(
    host: str,
    port: int,
    timeout: float | None = None,
    *,
    delay: float = HE_DELAY,
) -> socket.socket:
    """Connect to ``(host, port)``, racing addresses (RFC 8305)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ordered = _interleave(infos)
    if not ordered:
        raise OSError(f"could not resolve {host!r}")

    deadline = None if timeout is None else time.monotonic() + timeout
    pending: list[tuple[socket.socket, tuple]] = []
    idx = 0
    next_start = time.monotonic()
    last_err: OSError | None = None

    while idx < len(ordered) or pending:
        now = time.monotonic()
        if idx < len(ordered) and now >= next_start:
            af, stype, proto, _, addr = ordered[idx]
            idx += 1
            sock = socket.socket(af, stype, proto)
            sock.setblocking(False)
            try:
                sock.connect(addr)
            except BlockingIOError:
                pass
            except OSError as exc:
                last_err = exc
                sock.close()
                continue
            pending.append((sock, addr))
            next_start = now + delay
            continue

        if not pending:
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(0.01)
            continue

        writable, errored, _ = select.select(
            [], [s for s, _ in pending], [s for s, _ in pending], 0.05
        )
        for sock, addr in list(pending):
            if sock in writable or sock in errored:
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    for other, _ in pending:
                        if other is not sock:
                            other.close()
                    sock.setblocking(True)
                    return sock
                last_err = OSError(err, f"connect {addr}")
                pending.remove((sock, addr))
                sock.close()

        if deadline is not None and time.monotonic() >= deadline:
            break

    for sock, _ in pending:
        sock.close()
    if last_err is not None:
        raise last_err
    raise OSError(f"could not connect to {host}:{port}")
