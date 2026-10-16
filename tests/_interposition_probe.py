"""Subprocess probe: run Python's ssl and freetls concurrently in one process.

Used by the Route B interposition test. ``FREETLS_LIB`` points at a
statically-linked, symbol-hidden engine; Python's ``_ssl`` links the system
``libcrypto.so.3``. If the embedded libcrypto interposed, this would crash or
corrupt one of the handshakes.

Usage: python tests/_interposition_probe.py <host> <port> <name>
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import threading


def main() -> int:
    host, port, name = sys.argv[1:4]

    import freetls

    freetls.set_default_verify(False)
    from freetls import TLSSession, modes

    results: dict[str, str] = {}
    errors: list[str] = []

    def ssl_handshake() -> None:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, int(port)), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=name) as ss:
                    results.setdefault("ssl", ss.version())
        except Exception as exc:  # noqa: BLE001
            errors.append(f"ssl: {exc}")

    def freetls_handshake() -> None:
        try:
            spec = modes.baseline_spec(server_name=name, verify=False)
            with TLSSession(spec) as s:
                s.connect(host, int(port), server_hostname=name)
                results.setdefault("freetls", s.state.version)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"freetls: {exc}")

    threads = [threading.Thread(target=ssl_handshake) for _ in range(3)]
    threads += [threading.Thread(target=freetls_handshake) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(json.dumps({"results": results, "errors": errors}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
