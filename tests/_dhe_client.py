"""Standalone DHE client, run as a subprocess by the FFDHE suite tests.

Offers a DHE cipher suite together with the RFC 7919 ``ffdhe2048`` group so the
server can complete a finite-field DH key exchange. Loads the wide engine via
``FREETLS_LIB`` in a separate process (the cffi binding loads one engine per
process).

Usage: python tests/_dhe_client.py <host> <port> <ciphers-hex-csv> <vmin> <vmax> <name>
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    host, port, ciphers_csv, vmin, vmax, name = sys.argv[1:7]
    ciphers = [int(c, 16) for c in ciphers_csv.split(",") if c]

    import freetls

    freetls.set_default_verify(False)
    from freetls import TLSSession, modes

    spec = modes.specific(
        ciphers=ciphers,
        groups=[0x001D, 0x0017, 0x0018, 0x0100],  # include ffdhe2048
        vers_min=int(vmin),
        vers_max=int(vmax),
        server_name=name or None,
    )
    out: dict[str, object] = {"ok": False}
    try:
        with TLSSession(spec) as s:
            s.connect(host, int(port), server_hostname=name or None)
            cipher = s.cipher()
            out = {
                "ok": True,
                "ja4": s.ja4,
                "version": s.state.version,
                "cipher_suite": s.state.cipher_suite,
                "cipher": cipher[0] if cipher else None,
            }
    except Exception as exc:  # noqa: BLE001
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
