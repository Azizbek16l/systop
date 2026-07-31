"""Active network connections view — a stand-in for the `ss`/`bandwhich` connection table.

`psutil.net_connections(kind='inet')` returns the sockets; whenever a
connection has a PID, the process name is added via `psutil.Process(pid).name()`.
Process names are kept in a short-lived cache (the same PID can show up many
times within a single call). If permissions are lacking (AccessDenied) it is
swallowed cleanly and whatever data we have is returned (on some systems the
full table requires root).

**On macOS `psutil.net_connections()` ALWAYS raises `AccessDenied` when not
running as root** — this is not a psutil bug: `_psosx.py` walks over every PID
and stops as soon as it reaches a process owned by someone else. As a result
`list_connections()` returns an empty list and the "exposed services" check goes
**silently dead**: even with the Docker API (2375), Redis or telnet left open it
would report "no problems found". That is why `scan_connections()` was added —
it falls back to `netstat -an -p tcp` and **states openly whether it had
permission** (`ConnScan.permitted`), so that the caller can distinguish
"checked" from "could not check".

Only stdlib + psutil; `_platform` is imported lazily, inside `scan_connections`
only (for running the command — to avoid duplicating that code).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import psutil

# psutil socket statuses are the same strings on Linux/macOS (CONN_*).
# A None status means UDP or a non-listening socket (psutil sometimes returns empty).


@dataclass(slots=True)
class ConnInfo:
    """Information about a single network connection (socket)."""

    proto: str  # "tcp" | "udp" | "tcp6" | "udp6"
    laddr: str  # "ip:port" (local)
    raddr: str  # "ip:port" (remote), or "" if there is none
    status: str  # ESTABLISHED, LISTEN, ... or "" (UDP)
    pid: int | None = None
    process: str | None = None


def _proto_name(family: int, kind: int) -> str:
    """Builds the name "tcp"/"udp"/"tcp6"/"udp6" from the socket family+type."""
    base = "tcp" if kind == socket.SOCK_STREAM else "udp"
    return base + "6" if family == socket.AF_INET6 else base


def _fmt_addr(addr: object) -> str:
    """Turns a psutil addr (ip, port) named tuple into an "ip:port" string."""
    if not addr:
        return ""
    ip = getattr(addr, "ip", "") or ""
    port = getattr(addr, "port", "") or ""
    if ip and ":" in ip:
        # IPv6 — bracket the address to separate it from the port.
        return f"[{ip}]:{port}" if port != "" else f"[{ip}]"
    return f"{ip}:{port}" if port != "" else ip


def list_connections(
    kind: str = "inet",
    states: list[str] | None = None,
) -> list[ConnInfo]:
    """Returns the active network connections together with the process name.

    kind — the psutil `net_connections` kind ('inet', 'tcp', 'udp', 'inet4', ...).
    states — if given, only connections in those states are returned
    (for example ['ESTABLISHED', 'LISTEN']); case is ignored.

    If permissions are lacking or the sockets cannot be read — an empty list
    (no exception is raised). For some sockets the PID/process may be unknown
    (because of permissions, or because the socket has no owner).
    """
    wanted = {s.upper() for s in states} if states else None
    name_cache: dict[int, str | None] = {}
    result: list[ConnInfo] = []

    try:
        conns = psutil.net_connections(kind=kind)
    except (psutil.AccessDenied, psutil.Error, OSError, PermissionError):
        # On some systems the full table requires root — swallow it cleanly.
        return result

    for c in conns:
        status = c.status if c.status and c.status != psutil.CONN_NONE else ""
        if wanted is not None and status.upper() not in wanted:
            continue

        pid = c.pid
        pname: str | None = None
        if pid is not None:
            if pid in name_cache:
                pname = name_cache[pid]
            else:
                try:
                    pname = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError):
                    pname = None
                name_cache[pid] = pname

        result.append(
            ConnInfo(
                proto=_proto_name(c.family, c.type),
                laddr=_fmt_addr(c.laddr),
                raddr=_fmt_addr(c.raddr),
                status=status,
                pid=pid,
                process=pname,
            )
        )

    # Stable ordering: by proto, then by local address.
    result.sort(key=lambda r: (r.proto, r.laddr))
    return result


# --------------------------------------------------------------------------- #
# netstat fallback path (macOS/BSD — psutil does not work without root)
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ConnScan:
    """Result of an attempt to read the connections — DATA + PERMISSION state.

    When `list_connections()` returns an empty list two situations get mixed
    up: "nothing is listening" and "we are not allowed to read". In a security
    check that difference is decisive — the first means "clean", the second
    means "don't know". `permitted` is exactly what separates them.
    """

    conns: list[ConnInfo] = field(default_factory=list)
    permitted: bool = True
    source: str = "psutil"  # psutil | netstat | none
    error: str | None = None


def _split_listen_addr(token: str) -> tuple[str, int] | None:
    """Splits a `netstat` address column into `(host, port)` — a pure function.

    The three operating systems use three different separators and they cannot
    be handled by a single rule:

    ===========  ==========================  ===========================
    OS           IPv4                        IPv6
    ===========  ==========================  ===========================
    macOS/BSD    ``127.0.0.1.7265``          ``::1.8443``  ``*.6379``
    Linux        ``127.0.0.1:7265``          ``:::8443``   ``0.0.0.0:6379``
    Windows      ``127.0.0.1:7265``          ``[::]:8443``
    ===========  ==========================  ===========================

    Therefore the **dot** is tried first (BSD), and if that fails the **colon**
    (Linux/Windows). The order matters: splitting `0.0.0.0:6379` on the dot
    yields `("0.0.0", "0:6379")` — the port is not a number, so it falls
    through to the next method. Conversely, splitting the BSD `::1.8443` on the
    colon yields `("::", "1.8443")` and the listener disappears entirely.

    If the port is not a number (`*.*`, `*:*` — the remote address column),
    `None`.
    """
    for sep in (".", ":"):
        host, found, port_s = token.rpartition(sep)
        if found and port_s.isdigit():
            return host.strip("[]"), int(port_s)
    return None


# Windows says "LISTENING", POSIX says "LISTEN" — normalised to one name.
_STATE_ALIASES = {"LISTENING": "LISTEN"}


def parse_netstat_listeners(text: str, states: list[str] | None = None) -> list[ConnInfo]:
    """Turns `netstat -an` output into a list of `ConnInfo` — a pure function.

    **All three operating systems in one function.** Both the number of columns
    and their order differ:

    * macOS/BSD — ``Proto Recv-Q Send-Q Local Foreign [(state)]`` (5-6 columns)
    * Linux — ``Proto Recv-Q Send-Q Local Foreign State`` (6 columns)
    * Windows — ``Proto Local Foreign State`` (4 columns; 3 for UDP)

    That is why the column **number** is not relied upon: every token on the
    line is tried as an address-port pair, and the first two are taken as the
    local and the remote address. `Recv-Q`/`Send-Q` (a bare `0`) naturally
    fails to parse, because they contain no separator. This is the same lesson
    as in `routes.parse_netstat`: expecting strict columns/regexes loses lines
    SILENTLY.

    Proto arrives as `tcp4`/`tcp6`/`tcp46`/`tcp`/`TCP`. `tcp46` is a dual-stack
    socket: it accepts over IPv4 and IPv6 at the same time, so it is marked as
    `tcp6` (the wider blast radius). On Windows the family is not shown in the
    proto — it is determined from the address itself.

    The wildcard `*` is expanded to `0.0.0.0` or `::` depending on the family —
    that way the "is it bound to a wildcard" logic in `evaluate_listeners`
    behaves identically to the psutil path.

    The PID/process name is **not provided** (`netstat -an` does not have it;
    `-v`/`-b` require root or admin). This is deliberate: the port and the
    address are enough to identify the risk.
    """
    wanted = {s.upper() for s in states} if states else None
    out: list[ConnInfo] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        proto_raw = parts[0].lower()
        if not proto_raw.startswith(("tcp", "udp")):
            continue  # header and "Active Internet connections" lines

        addrs: list[tuple[str, int]] = []
        state = ""
        for tok in parts[1:]:
            parsed = _split_listen_addr(tok)
            if parsed is not None:
                addrs.append(parsed)
            elif tok.isalpha():
                # The state column (LISTEN / ESTABLISHED / LISTENING / TIME_WAIT).
                # `isalpha()` drops statuses containing an underscore — those
                # are of no interest to us (we are looking for LISTEN).
                state = _STATE_ALIASES.get(tok.upper(), tok.upper())
        if not addrs:
            continue
        if wanted is not None and state not in wanted:
            continue

        host, port = addrs[0]
        base = "tcp" if proto_raw.startswith("tcp") else "udp"
        # Family: from the proto suffix (tcp6/tcp46) OR from the address shape.
        is_v6 = "6" in proto_raw[3:] or ":" in host
        if host == "*":
            host = "::" if is_v6 else "0.0.0.0"

        laddr = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        raddr = ""
        if len(addrs) > 1:
            rh, rp = addrs[1]
            raddr = f"[{rh}]:{rp}" if ":" in rh else f"{rh}:{rp}"

        out.append(
            ConnInfo(
                proto=base + "6" if is_v6 else base,
                laddr=laddr,
                raddr=raddr,
                status=state,
            )
        )
    out.sort(key=lambda r: (r.proto, r.laddr))
    return out


async def scan_connections(states: list[str] | None = None) -> ConnScan:
    """Reads the connections and also reports the PERMISSION state.

    Order: `psutil` first (with process names — more useful), and if it raises
    `AccessDenied`, `netstat -an -p tcp` (no process names, but the ports are
    complete).

    `lsof` is DELIBERATELY not used: it was measured — it does not show
    root-owned listeners (8021, 43434), that is, it misses exactly the services
    `RISKY_LISTENERS` targets. A security check that gives half an answer is
    worse than one that gives none.
    """
    from systop.core import _platform

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        denied: str | None = type(exc).__name__
    except (psutil.Error, OSError) as exc:
        denied = type(exc).__name__
    else:
        # psutil worked — return via the full path (with process names).
        del conns
        return ConnScan(conns=list_connections(states=states), permitted=True, source="psutil")

    # Windows `netstat` expects the protocol in UPPERCASE after `-p` and
    # rejects `-p tcp` as an "invalid argument"; `-an` on the other hand works
    # on all three operating systems. On POSIX `-p tcp` shortens the output
    # considerably.
    cmd = ["netstat", "-an"] if _platform.IS_WINDOWS else ["netstat", "-an", "-p", "tcp"]
    text = await _platform.run_command(cmd, timeout=8.0)
    if not text:
        return ConnScan(conns=[], permitted=False, source="none", error=denied)
    return ConnScan(
        conns=parse_netstat_listeners(text, states=states),
        permitted=True,
        source="netstat",
    )
