#!/usr/bin/env python3
"""Test-only MIT GSSAPI peer. Binary frames on private pipes, never diagnostics.

Reviewed krb5 1.0.0 scripts/mit-gss.py and tests/kdc.rs. Unlike that fixture,
this peer never hex-prints tokens or exception details, requires SPNEGO and
mutual authentication, and has bounded frames/rounds. The caller owns its
process deadline. Requires the system python3-gssapi backed by MIT krb5.
"""
import struct
import sys

MAX_TOKEN = 1024 * 1024  # Fixture IPC budget, not a Kerberos protocol limit.


def read_exact(size):
    data = bytearray()
    while len(data) < size:
        part = sys.stdin.buffer.read(size - len(data))
        if not part:
            raise ValueError("peer closed")
        data.extend(part)
    return bytes(data)


def main():
    import gssapi

    mutual = gssapi.RequirementFlag.mutual_authentication
    name = gssapi.Name(sys.argv[1], gssapi.NameType.kerberos_principal)
    ctx = gssapi.SecurityContext(
        name=name,
        usage="initiate",
        mech=gssapi.OID.from_int_seq("1.3.6.1.5.5.2"),
        flags=[mutual, gssapi.RequirementFlag.integrity],
    )
    incoming = None
    for _ in range(4):  # Fixture budget; unexpected negotiation fails closed.
        outgoing = ctx.step(incoming) or b""
        if len(outgoing) > MAX_TOKEN:
            raise ValueError("oversized token")
        complete = ctx.complete
        if complete and mutual not in ctx.actual_flags:
            raise ValueError("mutual authentication missing")
        sys.stdout.buffer.write(struct.pack("!BI", int(complete), len(outgoing)))
        sys.stdout.buffer.write(outgoing)
        sys.stdout.buffer.flush()
        if complete:
            return
        size = struct.unpack("!I", read_exact(4))[0]
        if not 0 < size <= MAX_TOKEN:
            raise ValueError("invalid frame size")
        incoming = read_exact(size)
    raise ValueError("negotiation budget exhausted")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # GSS exceptions can include input-dependent details. Never print them.
        sys.exit(1)
