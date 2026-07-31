"""DNS diagnostics — name resolution + comparing the latency of DNS servers.

No extra dependencies: the A/AAAA records come from the system resolver via the
stdlib `socket`, while `subprocess` runs `dig` (or `nslookup`) against specific
DNS servers (8.8.8.8, 1.1.1.1, ...) so their response time can be measured.

If `dig` is unavailable the per-server latency cannot be measured, but the basic
resolution through the system resolver still works.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

from systop.core import _platform

# The public DNS servers we compare against.
PUBLIC_RESOLVERS: dict[str, str] = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

_DIG_ANSWER_RE = re.compile(r"^\S+\s+\d+\s+IN\s+(?:A|AAAA)\s+(\S+)", re.MULTILINE)
_NSLOOKUP_ADDR_RE = re.compile(r"^Address:\s*([0-9a-fA-F.:]+)", re.MULTILINE)

# macOS `scutil --dns`: "  nameserver[0] : 192.168.10.1"
_SCUTIL_NS_RE = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)", re.MULTILINE)
# Windows `ipconfig /all` — THE LABEL DEPENDS ON THE LANGUAGE:
#   English: "   DNS Servers . . . . . . . . . . . : 192.168.1.1"
#   Russian: "   DNS-серверы. . . . . . . . . . . : 192.168.1.1"
#   German:  "   DNS-Server  . . . . . . . . . . . : 192.168.1.1"
#
# That is why we DO NOT SEARCH for "DNS Servers". It is enough for the label to
# contain `DNS`; the rest is decided by THE SHAPE OF THE VALUE (it is taken when
# it is an IP). `DNS-суффикс` / `DNS Suffix` lines drop out naturally — their
# value is not an IP.
_IPCONFIG_DNS_RE = re.compile(r"^\s*[^:]*DNS[^:]*:\s*(\S*)\s*$", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Detecting the system resolvers — pure parsers + a thin async shell
# --------------------------------------------------------------------------- #
#
# Why it is needed: `doctor` used to test only the PUBLIC servers (8.8.8.8,
# 1.1.1.1...). On a corporate network outbound port 53 is often closed
# deliberately — so on a healthy network it produced the FALSE verdict "No DNS
# server is responding / check UDP/53 on the firewall" and exit 2. In reality
# the machine uses its own internal resolver perfectly happily.
#
# Now the resolver the machine ACTUALLY uses is asked first; the public ones are
# left as nothing more than a COMPARISON group.


def _is_ip(value: str) -> bool:
    """True when the string is an IP address (a zone suffix is fine) — a pure function."""
    try:
        ipaddress.ip_address(value.strip().split("%")[0])
    except ValueError:
        return False
    return True


def _dedupe_ips(values: list[str]) -> list[str]:
    """Removes duplicates, preserves the order, drops anything that is not an IP."""
    out: list[str] = []
    for v in values:
        bare = v.strip().strip(",").split("%")[0]
        if not bare:
            continue
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            continue
        if bare not in out:
            out.append(bare)
    return out


def parse_resolv_conf(text: str) -> list[str]:
    """Takes the `nameserver` lines out of `/etc/resolv.conf` — a pure function.

    The primary source on Linux. **On macOS this file is misleading** — it says
    "This file is not consulted for DNS hostname resolution" and usually holds
    `127.0.0.1`, or nothing at all. That is why `parse_scutil_dns` wins on macOS.

    On a Linux box running `systemd-resolved` this holds `127.0.0.53` — which is
    also the right answer: the machine really does talk to that stub.
    """
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0].lower() == "nameserver":
            out.append(parts[1])
    return _dedupe_ips(out)


def parse_scutil_dns(text: str) -> list[str]:
    """Takes the nameservers out of macOS `scutil --dns` — a pure function.

    The output holds `resolver #1`, `resolver #2`... blocks; only the
    `nameserver[N] : IP` lines interest us. The mDNS (`domain: local`) and
    reverse-lookup blocks carry no nameserver, so they drop out naturally.

    The output is repeated twice ("DNS configuration" and "(for scoped
    queries)") — the duplicates are removed and the order is preserved: the
    first resolver is the primary one.
    """
    return _dedupe_ips(_SCUTIL_NS_RE.findall(text))


def parse_ipconfig_all_dns(text: str) -> list[str]:
    """Takes the DNS servers out of Windows `ipconfig /all` — a pure function.

    The format is a trap: the second and later servers arrive **without a
    label**, on continuation lines indented with nothing but whitespace ::

        DNS Servers . . . . . . . . . . . : 192.168.1.1
                                            8.8.8.8
                                            fe80::1%12

    So we identify a "continuation line" not by the absence of a label but by
    the line itself being an IP address — the colons inside an IPv6 address make
    looking for a label unreliable.
    """
    out: list[str] = []
    in_dns = False
    for line in text.splitlines():
        m = _IPCONFIG_DNS_RE.match(line)
        if m:
            # The label contains `DNS` — but this could also be `DNS-суффикс`.
            # Only a line whose value is an IP is treated as the start of the
            # list; otherwise every IP following a `DNS Suffix` line (a `Default
            # Gateway`, say) would be collected by mistake.
            if _is_ip(m.group(1)):
                in_dns = True
                out.append(m.group(1))
            else:
                in_dns = False
            continue
        if not in_dns:
            continue
        stripped = line.strip()
        if not _is_ip(stripped):
            in_dns = False  # a new labelled line — the list is over
            continue
        out.append(stripped)
    return _dedupe_ips(out)


def _read_resolv_conf() -> str:
    """Reads `/etc/resolv.conf`; an empty string if it is missing/not permitted."""
    try:
        return Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


async def system_resolvers() -> list[str]:
    """Returns the DNS servers the machine ACTUALLY uses.

    The most reliable source for each OS:

    * **macOS** — `scutil --dns` (the only correct source; resolv.conf lies)
    * **Windows** — `ipconfig /all`
    * **Linux** — `/etc/resolv.conf`, and `resolvectl status` when that is empty

    If nothing is found, an empty list — no exception is raised (the same
    "silent default" rule as config.py).

    It is NOT TAKEN from `dhcp.py`: what DHCP announced and what the system is
    configured with are two different things (the user may have changed it by
    hand), and on top of that the Windows path does not return a `dns` list at
    all.
    """
    if _platform.IS_MACOS:
        out = await _platform.run_command(["scutil", "--dns"], timeout=5.0)
        return parse_scutil_dns(out) if out else []

    if _platform.IS_WINDOWS:
        # PowerShell first: `Get-DnsClientServerAddress` gives a STRUCTURED
        # answer and does not depend on the language at all. The `ipconfig`
        # label, by contrast, is localised (`DNS-серверы`, `DNS-Server`) — in
        # v0.3.2 exactly the same cause made every target look "dead" in ping on
        # a RUSSIAN Windows. We do not make the same mistake a second time.
        out = await _platform.run_command(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-DnsClientServerAddress -AddressFamily IPv4,IPv6"
                " -ErrorAction SilentlyContinue).ServerAddresses",
            ],
            timeout=15.0,
        )
        found = _dedupe_ips(out.splitlines()) if out else []
        if found:
            return found
        # PowerShell missing/restricted — the text path (a language-independent parse).
        out = await _platform.run_command(["ipconfig", "/all"], timeout=8.0)
        return parse_ipconfig_all_dns(out) if out else []

    # The file is read on a separate thread so the event loop is never blocked
    # (an /etc sitting on NFS/autofs can be slow to answer).
    found = parse_resolv_conf(await asyncio.to_thread(_read_resolv_conf))
    if found:
        return found
    out = await _platform.run_command(["resolvectl", "status"], timeout=5.0)
    if not out:
        return []
    # `resolvectl status`: "  DNS Servers: 192.168.1.1 8.8.8.8"
    servers: list[str] = []
    for line in out.splitlines():
        label, sep, rest = line.partition(":")
        if sep and "dns server" in label.strip().lower():
            servers.extend(rest.split())
    return _dedupe_ips(servers)


@dataclass(slots=True)
class ResolverResult:
    """The result of querying a single DNS server."""

    name: str
    server: str
    ok: bool = False
    rtt_ms: float = 0.0
    addresses: list[str] = field(default_factory=list)
    error: str | None = None
    is_system: bool = False
    """Whether this server is the resolver the machine itself uses.

    A decisive difference when judging: on many networks a public server being
    unreachable is **deliberate** (outbound port 53 is closed), whereas the
    system resolver being unreachable is always a genuine fault.
    """


@dataclass(slots=True)
class DnsResult:
    """The full DNS diagnostic result for a name."""

    name: str
    system_addresses: list[str] = field(default_factory=list)
    aaaa_addresses: list[str] = field(default_factory=list)
    system_error: str | None = None
    resolvers: list[ResolverResult] = field(default_factory=list)
    tool: str | None = None  # the external tool used: "dig" | "nslookup" | None


async def _system_resolve(name: str) -> tuple[list[str], str | None]:
    """Gets the A/AAAA addresses through the system resolver (error text on failure)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return [], f"The name '{name}' did not resolve (NXDOMAIN, or no DNS)."
    except OSError as exc:
        return [], f"Resolution error: {exc}"
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        # `::ffff:1.2.3.4` — an IPv4-mapped IPv6 address. This is NOT a REAL
        # AAAA record: when the network has no global IPv6, macOS filters the
        # AAAA out and hands back this shape instead. Presenting it as IPv6 in a
        # diagnostic is misleading, so it is dropped — the real AAAA lives in
        # `aaaa_addresses` (fetched via dig).
        if addr.startswith("::ffff:"):
            continue
        if addr not in seen:
            seen.append(addr)
    return seen, None


async def _query_aaaa(name: str, tool: str | None, timeout: float = 3.0) -> list[str]:
    """Fetches the real AAAA records straight from DNS (via dig/nslookup).

    Why not `getaddrinfo`: when the OS has no global IPv6 route, `getaddrinfo`
    hides the AAAA entirely (RFC 6724 address selection). But a diagnostic tool
    has to show **what DNS says**, not what the OS decided to use.

    If the tool is missing, or on any error, an empty list (no exception).
    """
    if not tool:
        return []
    if tool == "dig":
        cmd = ["dig", "+short", "AAAA", name]
    else:
        cmd = ["nslookup", "-type=AAAA", name]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=_platform.subprocess_flags(),
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
    except (TimeoutError, OSError, ValueError):
        return []
    out = _platform.decode_console(stdout)
    found: list[str] = []
    for line in out.splitlines():
        token = line.strip().split()[-1] if line.strip() else ""
        if ":" in token and not token.startswith("::ffff:"):
            try:
                ipaddress.IPv6Address(token)
            except ValueError:
                continue
            if token not in found:
                found.append(token)
    return found


def _parse_dig(out: str) -> list[str]:
    return _DIG_ANSWER_RE.findall(out)


def _parse_nslookup(out: str) -> list[str]:
    # The first "Address:" line is usually the server itself; the rest are the answer.
    addrs = _NSLOOKUP_ADDR_RE.findall(out)
    return addrs[1:] if len(addrs) > 1 else []


async def _query_resolver(
    name: str, server: str, tool: str, timeout: float, label: str | None = None
) -> ResolverResult:
    """Queries a specific DNS server and measures the response time."""
    label = label or next((k for k, v in PUBLIC_RESOLVERS.items() if v == server), server)
    if tool == "dig":
        cmd = [
            "dig",
            f"@{server}",
            name,
            "+tries=1",
            f"+time={int(max(timeout, 1))}",
            "+nocomments",
        ]
    else:  # nslookup
        cmd = ["nslookup", name, server]

    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=_platform.subprocess_flags(),
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
    except TimeoutError:
        return ResolverResult(name=label, server=server, error="timed out")
    except (OSError, ValueError) as exc:
        return ResolverResult(name=label, server=server, error=str(exc))

    rtt = (time.perf_counter() - start) * 1000.0
    # Windows nslookup writes in the OEM codepage (RU = cp866) -> decode_console.
    out = _platform.decode_console(stdout)
    addrs = _parse_dig(out) if tool == "dig" else _parse_nslookup(out)
    if not addrs:
        return ResolverResult(
            name=label, server=server, rtt_ms=rtt, error="empty answer (no record found)"
        )
    return ResolverResult(name=label, server=server, ok=True, rtt_ms=rtt, addresses=addrs)


def _pick_tool() -> str | None:
    """Picks an available DNS query tool: dig > nslookup > none."""
    if shutil.which("dig"):
        return "dig"
    if shutil.which("nslookup"):
        return "nslookup"
    return None


async def diagnose_dns(
    name: str,
    resolvers: dict[str, str] | None = None,
    timeout: float = 3.0,
    include_system: bool = True,
) -> DnsResult:
    """Resolves the name with the system resolver and compares the DNS servers.

    Arguments:
        name — the domain name to resolve.
        resolvers — the DNS servers to compare, as a `{name: server_ip}` dict.
            When None the standard :data:`PUBLIC_RESOLVERS` is used. The user may
            supply their own servers (from a config file, say, or corporate
            internal resolvers) — the function accepts a ready-made dict; reading
            the file is Layer 2's (CLI/TUI) job.
        timeout — the maximum wait for each server query (seconds).

    If `dig`/`nslookup` cannot be found, only the system resolution is returned
    (the `resolvers` list is empty and `tool` is None).
    """
    servers = dict(resolvers) if resolvers else dict(PUBLIC_RESOLVERS)
    sys_addrs, sys_err = await _system_resolve(name)

    # The system resolvers go at the HEAD of the list. Without them `doctor`
    # only sees the public servers and declares a corporate network whose
    # outbound port 53 is closed (entirely normal) to be "DNS completely dead".
    system_ips: set[str] = set()
    if include_system:
        try:
            found = await system_resolvers()
        except Exception:  # noqa: BLE001 — if detection fails, carry on with the public ones
            found = []
        already = set(servers.values())
        ordered: dict[str, str] = {}
        for ip in found:
            system_ips.add(ip)
            if ip in already:
                continue  # already in the user's list — we do not ask twice
            ordered[f"System ({ip})"] = ip
        servers = {**ordered, **servers}

    tool = _pick_tool()
    resolver_results: list[ResolverResult] = []
    aaaa: list[str] = []
    if tool is not None:
        tasks = [
            _query_resolver(name, srv, tool, timeout, label=lbl) for lbl, srv in servers.items()
        ]
        # The AAAA query runs in parallel with the resolvers — it costs no extra time.
        resolver_results_and_aaaa = await asyncio.gather(
            asyncio.gather(*tasks), _query_aaaa(name, tool, timeout)
        )
        resolver_results = list(resolver_results_and_aaaa[0])
        aaaa = resolver_results_and_aaaa[1]
        for r in resolver_results:
            r.is_system = r.server in system_ips

    return DnsResult(
        name=name,
        system_addresses=sys_addrs,
        aaaa_addresses=aaaa,
        system_error=sys_err,
        resolvers=resolver_results,
        tool=tool,
    )
