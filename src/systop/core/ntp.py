"""SNTP client — detecting clock skew. No root required.

Why this matters for a sysadmin: clock skew silently breaks a great many
things and the cause is never written down anywhere as "time" —

  * **Kerberos/AD** rejects authentication once the skew exceeds 5 minutes
    ("clock skew too great") — domain logon stops working;
  * **TLS** certificates look "not yet valid" or "expired", and the browser
    warns about them;
  * **logs** on different servers no longer line up — incident investigation
    becomes impossible;
  * **TOTP/2FA** codes are rejected.

Stdlib only: a 48-byte SNTP request is sent to UDP/123 (the client side does
not need a privileged port). Offset and round-trip delay are computed from the
server's reply with the RFC 4330 formula.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field

# Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
NTP_UNIX_DELTA = 2_208_988_800

# Servers checked by default. Local domain servers are supplied through the
# config (in an AD environment the domain controller is the NTP source).
DEFAULT_NTP_SERVERS: dict[str, str] = {
    "Cloudflare": "time.cloudflare.com",
    "Google": "time.google.com",
    "pool.ntp.org": "pool.ntp.org",
}

# Practical thresholds (Kerberos falls over at 300s, so we warn well before).
SKEW_WARN_S = 1.0
SKEW_HIGH_S = 30.0
SKEW_CRITICAL_S = 300.0


@dataclass(slots=True)
class NtpResult:
    """The result obtained from a single NTP server."""

    server: str
    label: str = ""
    ok: bool = False
    offset_s: float = 0.0  # how far the local clock differs from the server (+ = ahead)
    delay_ms: float = 0.0  # round-trip
    stratum: int = 0
    error: str | None = None

    @property
    def offset_ms(self) -> float:
        return self.offset_s * 1000.0

    @property
    def severity(self) -> str:
        """`ok` | `warn` | `high` | `critical` — the degree of skew."""
        a = abs(self.offset_s)
        if not self.ok:
            return "warn"
        if a >= SKEW_CRITICAL_S:
            return "critical"
        if a >= SKEW_HIGH_S:
            return "high"
        if a >= SKEW_WARN_S:
            return "warn"
        return "ok"


@dataclass(slots=True)
class NtpReport:
    """Summary across all servers."""

    results: list[NtpResult] = field(default_factory=list)

    @property
    def responded(self) -> list[NtpResult]:
        return [r for r in self.results if r.ok]

    @property
    def median_offset_s(self) -> float | None:
        """The median offset over the servers that responded.

        The median is deliberate: if a single server reports a bogus time the
        mean is ruined, whereas the median withstands it.
        """
        vals = sorted(r.offset_s for r in self.responded)
        if not vals:
            return None
        mid = len(vals) // 2
        if len(vals) % 2:
            return vals[mid]
        return (vals[mid - 1] + vals[mid]) / 2.0

    @property
    def worst_severity(self) -> str:
        order = {"ok": 0, "warn": 1, "high": 2, "critical": 3}
        if not self.results:
            return "warn"
        return max((r.severity for r in self.results), key=lambda s: order.get(s, 0))


def build_request() -> tuple[bytes, bytes]:
    """A 48-byte SNTP client request — returns `(packet, nonce)`.

    The nonce is 8 random bytes written into the Transmit Timestamp field
    (40:48). The server echoes them back verbatim in the **Originate
    Timestamp** field (24:32) of its reply (RFC 4330). That lets us verify the
    reply REALLY does belong to this request.

    This field used to be zero — meaning there was nothing to check against,
    and any stray UDP datagram that landed on the ephemeral port was accepted
    as "the server's reply" (a measurement reported `offset=-400s`,
    `severity=critical`).
    """
    packet = bytearray(48)
    packet[0] = 0x23  # 00 100 011 -> LI=0, VN=4, Mode=3 (client)
    nonce = secrets.token_bytes(8)
    packet[40:48] = nonce
    return bytes(packet), nonce


# When stratum=0 the Reference Identifier holds a "kiss code" (RFC 4330 §8).
KISS_CODES: dict[str, str] = {
    "DENY": "the server refused to serve us (DENY)",
    "RSTR": "access restricted (RSTR)",
    "RATE": "requests are too frequent (RATE) — increase the interval",
    "ACST": "anycast server",
    "AUTH": "authentication failure (AUTH)",
    "INIT": "the server is not synchronised yet (INIT)",
    "STEP": "the server is stepping its clock (STEP)",
}

# Slack for the delay envelope: a small negative value is normal because of
# clock granularity and scheduling latency.
_DELAY_SLACK_S = 0.05


def _ntp_to_unix(seconds: int, fraction: int) -> float:
    """Convert an NTP 32.32 fixed-point timestamp to Unix time — pure function.

    The RFC 4330 §3 "era" rule: if bit 0 (the most significant bit) is set the
    time lies between 1968 and 2036 and is counted from 1900; if it is not set
    the time lies between 2036 and 2104 and is counted from 7 February 2036.

    Mixing this up with an unconditional subtraction turns a post-2036 (or
    corrupt) timestamp into a **negative** Unix time, which throws `offset`
    off by ±2e9 seconds.
    """
    if seconds >= 0x8000_0000:
        base = seconds - NTP_UNIX_DELTA
    else:
        base = seconds + (2**32 - NTP_UNIX_DELTA)
    return base + fraction / 2**32


def parse_response(
    data: bytes,
    t1: float,
    t4: float,
    nonce: bytes | None = None,
) -> tuple[float, float, int]:
    """Compute (offset_s, delay_s, stratum) from an SNTP reply — pure function.

    RFC 4330:
        offset = ((T2 - T1) + (T3 - T4)) / 2
        delay  = (T4 - T1) - (T3 - T2)
    Here T1/T4 are the local send/receive times and T2/T3 are the server's
    times. The returned `offset` is **the local clock error relative to the
    server**.

    **Validation is deliberately strict.** This module produces the conclusion
    "the clock is correct" — and a wrong conclusion is more dangerous than a
    wrong clock (the sysadmin stops looking). The following are therefore
    rejected:

    * length < 48;
    * `Mode != 4` (not a server reply — a client or broadcast packet);
    * `LI == 3` (alarm — the server itself is unsynchronised);
    * `stratum == 0` (Kiss-of-Death; the reason is read from the kiss code);
    * `stratum > 15` (16 = unsynchronised, anything above that is invalid);
    * a nonce mismatch (the reply belongs to another request, or is forged);
    * T2 **or** T3 zero (a half-empty packet — this used to be rejected only
      when BOTH were zero);
    * a `delay` outside the causality envelope (below 0, or greater than the
      full round-trip measured locally) — that means the packet belongs to a
      different point in time.

    A bad packet raises `ValueError` (the caller turns it into `error` text).
    """
    if len(data) < 48:
        raise ValueError(f"SNTP reply too short: {len(data)} bytes (48 required)")

    li = (data[0] >> 6) & 0x3
    mode = data[0] & 0x7
    stratum = data[1]

    if mode != 4:
        raise ValueError(f"SNTP: not a server reply (Mode={mode}, 4 expected)")
    if li == 3:
        raise ValueError("SNTP: the server is not synchronised (LI=3, alarm)")
    if stratum == 0:
        kiss = data[12:16].decode("ascii", "replace").strip("\x00 ")
        raise ValueError(f"SNTP Kiss-of-Death: {KISS_CODES.get(kiss, kiss or 'unknown')}")
    if stratum > 15:
        raise ValueError(f"SNTP: invalid stratum {stratum} (1-15 expected)")

    if nonce is not None and data[24:32] != nonce:
        raise ValueError(
            "SNTP: the reply does not match the request (different originate timestamp)"
        )

    # Receive (T2) and Transmit (T3) timestamps: 32.32 fixed point.
    t2_int, t2_frac, t3_int, t3_frac = struct.unpack("!IIII", data[32:48])
    # `or` is DELIBERATE. With `and`, a half-filled packet slipped through and
    # the zero timestamp turned into the year 1900, producing a "skew" of
    # ±2e9 seconds.
    if t2_int == 0 or t3_int == 0:
        raise ValueError("no timestamp in the SNTP reply (empty or corrupt packet)")

    t2 = _ntp_to_unix(t2_int, t2_frac)
    t3 = _ntp_to_unix(t3_int, t3_frac)
    offset = ((t2 - t1) + (t3 - t4)) / 2.0
    delay = (t4 - t1) - (t3 - t2)

    # The causality envelope is applied to the RAW `delay`, BEFORE
    # `max(delay, 0)`. Otherwise a negative delay silently became zero and a
    # corrupt packet looked like a "perfect measurement".
    elapsed = t4 - t1
    if delay < -_DELAY_SLACK_S or delay > elapsed + _DELAY_SLACK_S:
        raise ValueError(
            f"SNTP: the reply timings are implausible (delay {delay:.3f}s, "
            f"local round-trip {elapsed:.3f}s) — the packet does not belong to this request"
        )
    return offset, max(delay, 0.0), stratum


async def query_server(server: str, timeout: float = 3.0, label: str = "") -> NtpResult:
    """Ask a single NTP server for the time. Never raises."""
    res = NtpResult(server=server, label=label or server)
    loop = asyncio.get_running_loop()
    sock = None
    try:
        infos = await loop.getaddrinfo(server, 123, type=socket.SOCK_DGRAM)
        if not infos:
            res.error = "could not resolve"
            return res
        family, socktype, proto, _, addr = infos[0]
        sock = socket.socket(family, socktype, proto)
        sock.setblocking(False)
        # `connect()` is REQUIRED: without it `sock_recv` accepts a datagram
        # from any source and we cannot see who sent it. Once connected, the
        # kernel discards anything arriving from other peers on its own.
        # For UDP this sends no packet — it merely binds a peer to the socket.
        sock.connect(addr)
        packet, nonce = build_request()

        t1 = time.time()
        # NOT `sock_sendto`: on a connected UDP socket that fails with `EISCONN`.
        await loop.sock_sendall(sock, packet)
        data = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=timeout)
        t4 = time.time()

        offset, delay, stratum = parse_response(data, t1, t4, nonce=nonce)
        # Flip the sign into the direction a user understands:
        # positive => the LOCAL clock is ahead of the server.
        res.offset_s = -offset
        res.delay_ms = delay * 1000.0
        res.stratum = stratum
        res.ok = True
    except TimeoutError:
        res.error = f"no reply ({timeout:.0f}s)"
    except (OSError, socket.gaierror) as exc:
        res.error = f"network error: {exc.strerror or exc}"
    except ValueError as exc:
        res.error = str(exc)
    finally:
        if sock is not None:
            sock.close()
    return res


async def check_time(
    servers: dict[str, str] | None = None,
    timeout: float = 3.0,
) -> NtpReport:
    """Query several NTP servers in parallel and return a summary.

    Several servers are queried — if one of them reports a bogus time the
    median absorbs it (so we never depend on a single source).
    """
    srv = servers or DEFAULT_NTP_SERVERS
    tasks = [query_server(host, timeout, label) for label, host in srv.items()]
    results = list(await asyncio.gather(*tasks))
    return NtpReport(results=results)
