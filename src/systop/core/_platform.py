"""Platform-dependent shared helpers (the cross-platform layer).

This module gathers platform detection, Windows console encoding/Unicode issues
AND Windows ICMP (ping/traceroute) into one place. The other `core/` modules
(`netinfo`, `ping`, `topology`, `dns`) take their platform branch from here — so
the logic is not duplicated and can be tested offline.

Design decisions:

* **ICMP on Windows — Win32 IcmpSendEcho (the root fix).** Instead of parsing
  text, `iphlpapi.dll`'s `IcmpSendEcho`/`Icmp6SendEcho2` functions are called
  through ctypes. This requires no admin rights AND is completely independent of
  the system locale/codepage — a Russian or German Windows behaves identically.
  If `IcmpSendEcho` is unavailable (a very old/unusual environment), a
  language-independent fallback that parses `ping.exe`/`tracert.exe` output is
  used.
* **OEM codepage decode.** Subprocesses (route/arp/ip-neigh/dns) still return
  text; a Russian console writes cp866 (not UTF-8). `decode_console` reads the
  real console codepage (`GetConsoleOutputCP`) and decodes with it — which
  prevents Cyrillic mojibake.
* **Console init.** On Windows `init_console` switches the console into UTF-8
  (65001) + VT (virtual terminal) mode — so Textual's sparkline/braille/box
  characters also render correctly in legacy cmd.exe.
* **stdlib only.** `platform`, `subprocess`, `asyncio`, `re`, `ctypes`,
  `socket`, `os` — no extra dependencies.
* **The parse functions are pure.** They never touch the network, only
  string/bytes -> value; they are tested offline against real output samples
  (cp866 bytes included).

Note: these constants (`IS_WINDOWS` and so on) are module-level; tests may
replace them with `monkeypatch.setattr(_platform, "IS_WINDOWS", True)`, but
calling modules must read them through `_platform.IS_WINDOWS` (as an attribute)
— that is what makes the monkeypatch take effect.
"""

from __future__ import annotations

import asyncio
import ctypes
import functools
import os
import platform
import re
import shutil
import socket
import struct
import subprocess

# --- Platform constants (single source of truth) -----------------------------

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# Keeps the subprocess window from flashing on Windows (only exists on win32).
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def subprocess_flags() -> int:
    """Subprocess `creationflags` value: CREATE_NO_WINDOW on Windows, 0 elsewhere.

    Stops the console window from flashing. On other operating systems it is 0
    (`creationflags` is also accepted on POSIX, but has no effect there).
    """
    return _CREATE_NO_WINDOW if IS_WINDOWS else 0


# --- Console codepage and Unicode --------------------------------------------


def decode_console(data: bytes | str) -> str:
    """Decodes byte output correctly, honouring the Windows console OEM codepage.

    The Windows console (cmd.exe) does not write UTF-8, it writes in an OEM
    codepage (RU = cp866, DE = cp850 and so on). Decoding that as UTF-8 turns
    every non-Latin character into mojibake. This function asks
    `GetConsoleOutputCP` for the real codepage and decodes with `cp<N>`.

    On other operating systems (or when the codepage cannot be determined) UTF-8
    is used. In every case `errors="replace"` — a corrupt byte never raises. If a
    `str` arrives already (e.g. a `text=True` subprocess or a test fixture) it is
    returned unchanged.
    """
    if isinstance(data, str):
        return data
    if IS_WINDOWS:
        cp = _console_output_cp()
        if cp:
            try:
                return data.decode(f"cp{cp}", errors="replace")
            except LookupError:
                # Unknown/unsupported codepage — fall back to UTF-8.
                pass
    return data.decode("utf-8", errors="replace")


def _console_output_cp() -> int:
    """Returns the current console output codepage; 0 on any error."""
    try:
        return int(ctypes.windll.kernel32.GetConsoleOutputCP())  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        return 0


# ENABLE_VIRTUAL_TERMINAL_PROCESSING (makes the console understand ANSI/VT
# escape sequences).
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11
_STD_ERROR_HANDLE = -12
_CP_UTF8 = 65001


def init_console() -> None:
    """Switches the console into UTF-8 (65001) + VT mode (Windows only; else no-op).

    The Textual TUI and Rich output rely on Unicode (braille sparklines, box
    characters) and ANSI colours. Legacy cmd.exe defaults to an OEM codepage with
    no VT support — the result is mojibake. This function:

    * `SetConsoleOutputCP(65001)` + `SetConsoleCP(65001)` — UTF-8 input/output;
    * adds `ENABLE_VIRTUAL_TERMINAL_PROCESSING` to the stdout/stderr handles.

    Every step swallows its errors SILENTLY (with a redirected stream / an old
    Windows / no permission the application still carries on working). cli/app
    calls it once at start-up.
    """
    if not IS_WINDOWS:
        return
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return
    try:
        kernel32.SetConsoleOutputCP(_CP_UTF8)
        kernel32.SetConsoleCP(_CP_UTF8)
    except OSError:
        pass
    for std_handle in (_STD_OUTPUT_HANDLE, _STD_ERROR_HANDLE):
        try:
            handle = kernel32.GetStdHandle(std_handle)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                continue
            kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        except OSError:
            continue


def unicode_ok() -> bool:
    """Guesses whether the terminal can display Unicode blocks/emoji (a heuristic).

    * Windows: True under Windows Terminal (the `WT_SESSION` env var) OR when the
      console is UTF-8 (codepage 65001); otherwise (legacy raster cmd.exe) False.
    * Other operating systems (macOS/Linux): always True.

    Layer B (cli/app) uses this to pick the ASCII fallback (plain tables and
    characters) — so there is no mojibake on an old cmd.exe either.
    """
    if not IS_WINDOWS:
        return True
    if os.environ.get("WT_SESSION"):
        return True
    return _console_output_cp() == _CP_UTF8


# --- Windows ICMP: Win32 IcmpSendEcho (iphlpapi.dll) -------------------------
#
# The root fix, independent of language and codepage. The ICMP API in
# `iphlpapi.dll` requires no admin rights (ping.exe uses the same thing). The
# structs below match the Win32 SDK (ipexport.h) definitions.

# IP status codes (ipexport.h).
IP_SUCCESS = 0
IP_TTL_EXPIRED_TRANSIT = 11013  # TTL hit zero — an intermediate hop (for traceroute).
IP_REQ_TIMED_OUT = 11010


class _ICMP_ECHO_REPLY(ctypes.Structure):
    """ICMP_ECHO_REPLY (IPv4) — the structure `IcmpSendEcho` fills in.

    The only fields we read are `Status` (an IP_* code) and `RoundTripTime` (ms).
    The rest of the reply data (`Data`, `Options`) is of no use to us, but the
    struct size must still be correct (the API writes into the buffer).
    """

    _fields_ = (
        ("Address", ctypes.c_uint32),  # source IP that replied (network byte order)
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16),
        ("Data", ctypes.c_void_p),
        ("Options_Ttl", ctypes.c_uint8),
        ("Options_Tos", ctypes.c_uint8),
        ("Options_Flags", ctypes.c_uint8),
        ("Options_OptionsSize", ctypes.c_uint8),
        ("Options_OptionsData", ctypes.c_void_p),
    )


class _IP_OPTION_INFORMATION(ctypes.Structure):
    """IP_OPTION_INFORMATION — used to control the TTL (the traceroute hops).

    By sending `Ttl` as 1..max_hops in sequence we get back the IP of each
    intermediate router that answered with TTL_EXPIRED.
    """

    _fields_ = (
        ("Ttl", ctypes.c_uint8),
        ("Tos", ctypes.c_uint8),
        ("Flags", ctypes.c_uint8),
        ("OptionsSize", ctypes.c_uint8),
        ("OptionsData", ctypes.c_void_p),
    )


# The "payload" sent to IcmpSendEcho (an arbitrary 32 bytes — same as ping.exe).
_ICMP_PAYLOAD = b"systop-icmp-probe-padding-32byte"  # 32 bytes
# Reply buffer: ECHO_REPLY + payload + extra (8 bytes reserved for an ICMP header).
_ICMP_REPLY_BUF_SIZE = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(_ICMP_PAYLOAD) + 8

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _iphlpapi() -> ctypes.WinDLL | None:  # type: ignore[name-defined]
    """Loads `iphlpapi.dll`; None if it is not available (we fall back)."""
    try:
        return ctypes.WinDLL("iphlpapi.dll")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def _resolve_ipv4(address: str) -> str | None:
    """Turns an address into a dotted-decimal IPv4 string (resolving a name if given).

    IcmpSendEcho only accepts an IPv4 address (a DWORD), so we resolve the name
    ourselves. None if it does not resolve.
    """
    try:
        infos = socket.getaddrinfo(address, None, family=socket.AF_INET)
    except (OSError, UnicodeError):
        return None
    for info in infos:
        return str(info[4][0])
    return None


def _addr_to_dword(ipv4: str) -> int | None:
    """Converts an IPv4 string into the DWORD (network byte order) IcmpSendEcho wants."""
    try:
        packed = socket.inet_aton(ipv4)
    except OSError:
        return None
    return int(struct.unpack("<I", packed)[0])


def _dword_to_addr(dword: int) -> str:
    """ECHO_REPLY.Address (a network byte order DWORD) -> IPv4 string."""
    return socket.inet_ntoa(struct.pack("<I", dword & 0xFFFFFFFF))


def icmp_ping_ipv4(
    ipv4: str,
    timeout_ms: int,
    ttl: int | None = None,
) -> tuple[int, float, str | None]:
    """Sends a single IPv4 ICMP echo (Win32 IcmpSendEcho).

    Arguments:
        ipv4 — a dotted-decimal IPv4 address (already resolved).
        timeout_ms — how long to wait for the reply (milliseconds).
        ttl — None for the default; otherwise IP_OPTION_INFORMATION.Ttl
            (1..max_hops for a traceroute hop).

    Returns: `(status, rtt_ms, reply_source_ip)`.
        status — an IP_* code (0=SUCCESS, 11013=TTL_EXPIRED, 11010=TIMED_OUT, ...).
        rtt_ms — RoundTripTime (meaningful when the status is SUCCESS/TTL_EXPIRED).
        reply_source_ip — the source IP that replied (on TTL_EXPIRED, the
            intermediate router).

    If `iphlpapi` is missing / the handle will not open -> `(IP_REQ_TIMED_OUT,
    0.0, None)`.
    """
    dll = _iphlpapi()
    if dll is None:
        return IP_REQ_TIMED_OUT, 0.0, None

    dest = _addr_to_dword(ipv4)
    if dest is None:
        return IP_REQ_TIMED_OUT, 0.0, None

    dll.IcmpCreateFile.restype = ctypes.c_void_p
    handle = dll.IcmpCreateFile()
    if not handle or handle == _INVALID_HANDLE_VALUE:
        return IP_REQ_TIMED_OUT, 0.0, None

    try:
        reply_buf = ctypes.create_string_buffer(_ICMP_REPLY_BUF_SIZE)
        opt_ptr = None
        if ttl is not None:
            opts = _IP_OPTION_INFORMATION(Ttl=max(1, min(255, ttl)))
            opt_ptr = ctypes.byref(opts)

        dll.IcmpSendEcho.restype = ctypes.c_uint32
        n = dll.IcmpSendEcho(
            ctypes.c_void_p(handle),
            ctypes.c_uint32(dest),
            _ICMP_PAYLOAD,
            ctypes.c_uint16(len(_ICMP_PAYLOAD)),
            opt_ptr,
            reply_buf,
            ctypes.c_uint32(_ICMP_REPLY_BUF_SIZE),
            ctypes.c_uint32(max(1, timeout_ms)),
        )
        if n == 0:
            # No reply (timeout or error). GetLastError can also carry a status
            # (on some versions TTL_EXPIRED arrives as n=0 + LastError), but we
            # degrade that to "no reply" (simple and predictable).
            return IP_REQ_TIMED_OUT, 0.0, None
        reply = ctypes.cast(reply_buf, ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
        status = int(reply.Status)
        rtt = float(reply.RoundTripTime)
        src = _dword_to_addr(int(reply.Address)) if reply.Address else None
        return status, rtt, src
    except OSError:
        return IP_REQ_TIMED_OUT, 0.0, None
    finally:
        try:
            dll.IcmpCloseHandle(ctypes.c_void_p(handle))
        except OSError:
            pass


def win_icmp_ping(
    address: str,
    count: int,
    timeout: float,
) -> tuple[bool, list[float], float] | None:
    """Windows ICMP ping (IcmpSendEcho) — (alive, rtts_ms, loss) or None.

    Sends an IPv4 echo `count` times and collects the RTT of every SUCCESS reply.
    Loss = (sent - received) / sent.

    Returns None if:
      * the address does not resolve to IPv4 (the caller falls back to the
        name/IPv6 path),
      * `iphlpapi` is not available at all (no DLL).
    In that case the caller (`ping._win_ping`) falls back to parsing `ping.exe`.
    """
    if _iphlpapi() is None:
        return None
    ipv4 = _resolve_ipv4(address)
    if ipv4 is None:
        return None

    count = max(1, count)
    timeout_ms = max(1, int(timeout * 1000))
    rtts: list[float] = []
    received = 0
    for _ in range(count):
        status, rtt, _src = icmp_ping_ipv4(ipv4, timeout_ms)
        if status == IP_SUCCESS:
            received += 1
            rtts.append(rtt)
    loss = (count - received) / count if count else 1.0
    return (received > 0), rtts, loss


def win_icmp_traceroute(
    address: str,
    max_hops: int,
    timeout: float,
) -> list[tuple[int, str | None, float, bool]] | None:
    """Windows traceroute (IcmpSendEcho + TTL) — a list of hops, or None.

    Sends one echo per TTL (1..max_hops):
      * status SUCCESS  -> the target was reached (the last hop), we stop;
      * status TTL_EXPIRED -> an intermediate router (reply.Address), we go on;
      * no reply -> a `* * *` hop (addr=None, alive=False).

    Returns: each element is `(hop_index, address|None, rtt_ms, alive)` — the
    same shape as `parse_windows_tracert`. Returns None if the address does not
    resolve to IPv4 or `iphlpapi` is missing (the caller falls back to parsing
    `tracert`).
    """
    if _iphlpapi() is None:
        return None
    ipv4 = _resolve_ipv4(address)
    if ipv4 is None:
        return None

    timeout_ms = max(1, int(timeout * 1000))
    hops: list[tuple[int, str | None, float, bool]] = []
    for ttl in range(1, max(1, max_hops) + 1):
        status, rtt, src = icmp_ping_ipv4(ipv4, timeout_ms, ttl=ttl)
        if status == IP_SUCCESS:
            hops.append((ttl, src or ipv4, rtt, True))
            break
        if status == IP_TTL_EXPIRED_TRANSIT and src is not None:
            hops.append((ttl, src, rtt, True))
            continue
        # No reply / some other error -> a timeout hop.
        hops.append((ttl, None, 0.0, False))
    return hops


# --- Parsing Windows `ping` output (LANGUAGE-INDEPENDENT FALLBACK) -----------
#
# When IcmpSendEcho is not available (very rare) we parse `ping.exe` output. The
# regexes are NOT TIED TO A LANGUAGE: they understand ASCII 'ms' AND Cyrillic
# 'мс' (м=U+043C), and the decimal comma too (RU/DE `время=1,5 мс`).

# RTT: "time=12ms", "time<1ms", "время=84мс", "Zeit=12ms", "1,5 ms".
# "=" or "<" + a number (comma/dot decimal) + a unit (ascii m / Cyrillic м).
_WIN_PING_RTT_RE = re.compile(
    r"[=<]\s*([0-9]+(?:[.,][0-9]+)?)\s*(?:ms|мс|m|м)",
    re.IGNORECASE | re.UNICODE,
)
# "time<1ms" / "время<1мс" => less than 1ms -> 0.5ms (an approximation).
_WIN_PING_SUBMS_RE = re.compile(r"<\s*1\s*(?:ms|мс|m|м)", re.IGNORECASE | re.UNICODE)
# The closing statistics: "(0% loss)" / "(0% потерь)" / "(0% Verlust)" — a percentage.
_WIN_PING_LOSS_PCT_RE = re.compile(r"\(\s*([0-9]+)\s*%")
# The `Packets:` statistics line — Sent/Received (to tell it apart from the RTT
# lines). RU: "Отправлено = 4, получено = 4, потеряно = 0".
_WIN_PING_STATS_LINE_RE = re.compile(
    r"(?:Sent|Received|Lost|Отправлено|Получено|Потеряно|Gesendet|Empfangen|Verloren)"
    r"\s*=\s*\d",
    re.IGNORECASE | re.UNICODE,
)
_WIN_PING_SENT_RE = re.compile(
    r"(?:Sent|Отправлено|Gesendet)\s*=\s*([0-9]+)", re.IGNORECASE | re.UNICODE
)
_WIN_PING_RECV_RE = re.compile(
    r"(?:Received|Получено|Empfangen)\s*=\s*([0-9]+)", re.IGNORECASE | re.UNICODE
)
# The TTL label stays Latin "TTL" in every language (even Russian output says
# "TTL="). So we look for "ttl" to identify a reply line (language-independent).


def parse_windows_ping(output: str, expected_count: int) -> tuple[bool, list[float], float]:
    """Turns Windows `ping` output into (alive, rtts_ms, loss).

    LANGUAGE-INDEPENDENT: it understands English, Russian (decoded from cp866)
    and German output. This is the fallback path for when IcmpSendEcho is not
    available.

    Arguments:
        output — the full `ping ...` stdout text (already decoded).
        expected_count — the number of packets sent (for the fallback loss sum).

    Returns:
        alive — whether at least one reply arrived.
        rtts_ms — the RTT of each reply (ms); non-replies are not included.
        loss — the packet loss fraction (0.0..1.0).
    """
    rtts: list[float] = []
    for line in output.splitlines():
        # We identify a reply line by "TTL" (Russian output says "TTL=" too).
        low = line.lower()
        if "ttl=" not in low and "ttl =" not in low:
            continue
        if _WIN_PING_SUBMS_RE.search(line):
            rtts.append(0.5)
            continue
        m = _WIN_PING_RTT_RE.search(line)
        if m:
            rtts.append(float(m.group(1).replace(",", ".")))

    # Loss: first from the closing statistics percentage ("(25% loss)") —
    # language-independent.
    loss: float | None = None
    pct = _WIN_PING_LOSS_PCT_RE.search(output)
    if pct:
        loss = int(pct.group(1)) / 100.0
    else:
        for line in output.splitlines():
            if not _WIN_PING_STATS_LINE_RE.search(line):
                continue
            sent_m = _WIN_PING_SENT_RE.search(line)
            recv_m = _WIN_PING_RECV_RE.search(line)
            if sent_m and recv_m:
                sent = int(sent_m.group(1))
                received = int(recv_m.group(1))
                loss = (sent - received) / sent if sent else 1.0
                break

    alive = len(rtts) > 0
    if loss is None:
        count = expected_count if expected_count > 0 else 1
        loss = max(0.0, (count - len(rtts)) / count)
    return alive, rtts, loss


# --- Parsing Windows `tracert` output (LANGUAGE-INDEPENDENT FALLBACK) --------

_WIN_TRACERT_LINE_RE = re.compile(
    r"^\s*(\d+)\s+(.*?)\s*$",
)
# The RTT column: ascii "12 ms" or Cyrillic "12 мс" (decimal comma included).
_WIN_TRACERT_RTT_RE = re.compile(r"([0-9]+(?:[.,][0-9]+)?)\s*(?:ms|мс)", re.IGNORECASE | re.UNICODE)
_WIN_TRACERT_SUBMS_RE = re.compile(r"<\s*1\s*(?:ms|мс)", re.IGNORECASE | re.UNICODE)
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F:]{2,}:[0-9a-fA-F:]*)\b")


def parse_windows_tracert(output: str) -> list[tuple[int, str | None, float, bool]]:
    """Turns Windows `tracert -d` output into a list of hops (language-independent).

    Returns: each element is `(hop_index, address|None, avg_rtt_ms, alive)`.

    When no `address` is found (`* * *` / `Request timed out` / `Превышен
    интервал`) -> None, alive=False, rtt=0. The RTT is the average of the
    measurements on that line (ms). `<1 ms`/`<1 мс` => 0.5ms. This is the
    fallback for when IcmpSendEcho is missing.
    """
    hops: list[tuple[int, str | None, float, bool]] = []
    for line in output.splitlines():
        m = _WIN_TRACERT_LINE_RE.match(line)
        if not m:
            continue
        index = int(m.group(1))
        rest = m.group(2)

        addr: str | None = None
        ip4 = _IPV4_RE.search(rest)
        if ip4:
            addr = ip4.group(1)
        else:
            ip6 = _IPV6_RE.search(rest)
            if ip6 and ":" in ip6.group(1):
                addr = ip6.group(1)

        measure_part = rest
        if addr:
            measure_part = rest.replace(addr, " ")

        rtts: list[float] = []
        subms = len(_WIN_TRACERT_SUBMS_RE.findall(measure_part))
        rtts.extend([0.5] * subms)
        cleaned = _WIN_TRACERT_SUBMS_RE.sub(" ", measure_part)
        for rm in _WIN_TRACERT_RTT_RE.finditer(cleaned):
            rtts.append(float(rm.group(1).replace(",", ".")))

        alive = addr is not None
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
        hops.append((index, addr, avg_rtt, alive))
    return hops


# --- The default gateway from Windows `route print` output -------------------

_WIN_ROUTE_DEFAULT_RE = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.MULTILINE,
)
_WIN_NETROUTE_NEXTHOP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})",
)


def parse_windows_route_print(output: str) -> str | None:
    """Extracts the default (0.0.0.0/0) gateway IP from `route print -4` output."""
    m = _WIN_ROUTE_DEFAULT_RE.search(output)
    if m and m.group(1) != "0.0.0.0":
        return m.group(1)
    return None


# --- Shared async subprocess helper ------------------------------------------


# Most network commands live in directories that are NOT on PATH:
# `system_profiler`, `ndp`, `arp`, `route`, `ifconfig` -> /usr/sbin or /sbin.
# In an interactive shell they are on PATH, but `cron`, `systemd` and launchd
# normally hand over `PATH=/usr/bin:/bin` — EXACTLY where a sysadmin has
# automated the tool. Measured: with such a PATH `doctor` decided the link type
# was "wired" instead of "wifi" and picked the wrong thresholds.
_EXTRA_BIN_DIRS = ("/usr/sbin", "/sbin", "/usr/local/sbin")


@functools.lru_cache(maxsize=64)
def resolve_binary(name: str) -> str:
    """Turns a command name into a full path; returns the name if not found.

    PATH first, then `_EXTRA_BIN_DIRS`. If nothing is found the name is returned
    unchanged — `create_subprocess_exec` then raises `FileNotFoundError` itself
    and `run_command` turns that into an empty string (the existing behaviour is
    preserved).

    A path (containing `/` or `\\`) is left alone.
    """
    if os.sep in name or (os.altsep and os.altsep in name):
        return name
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_BIN_DIRS:
        candidate = os.path.join(d, name)
        if os.access(candidate, os.X_OK):
            return candidate
    return name


async def run_command(
    cmd: list[str],
    timeout: float,
    include_stderr: bool = False,
) -> str:
    """Runs a command asynchronously and returns its stdout text (never blocks).

    The output is decoded with `decode_console` — so a Windows OEM codepage
    (cp866/cp850) is read correctly (no Cyrillic mojibake). On Windows it starts
    with CREATE_NO_WINDOW (so no console window flashes up).

    `include_stderr=True` — stderr is included as well. Some diagnostic messages
    are written to stderr EXACTLY: macOS `ping` prints "Message too long" there,
    and throwing it away made path-MTU detection completely non-functional (the
    "too big" answer was never seen).

    On an error (command missing / timeout / OS) it returns an empty string — so
    the caller can degrade to "no result" (no exception is raised).
    """
    cmd = [resolve_binary(cmd[0]), *cmd[1:]] if cmd else cmd
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=(asyncio.subprocess.STDOUT if include_stderr else asyncio.subprocess.DEVNULL),
            creationflags=subprocess_flags(),
        )
    except (OSError, ValueError):
        return ""
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return ""
    except OSError:
        return ""
    return decode_console(stdout)
