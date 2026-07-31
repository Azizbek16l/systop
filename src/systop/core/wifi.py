"""Wi-Fi diagnostics — signal, channel, band, neighbours. No root required.

Why this matters for a sysadmin: a large share of "the internet is slow"
complaints are not about the internet at all but about the **radio**. Ping and
speedtest do not show it — they measure the outcome, not the cause. The most
common cases:

  * **strong signal but low throughput** — the device is sitting on 2.4 GHz
    while 5 GHz is available. On 2.4 GHz a 20 MHz channel caps you at
    ~144 Mbps;
  * **channel congestion** — 2.4 GHz has only 3 non-overlapping channels
    (1/6/11). If a neighbouring AP runs at 40 MHz width it covers two channels
    and throughput collapses even with a good SNR;
  * **PHY below the card's capability** — ax is supported but the link is on n
    (an old router or a wrong setting);
  * **weak signal** — below -70 RSSI retransmissions rise sharply.

On each platform a source that needs no root is used:
  macOS   — `system_profiler SPAirPortDataType` (`wdutil` requires sudo, and
            `airport -I` was removed in macOS 14.4 — so NEITHER of those)
  Linux   — `iw dev <iface> link` + `iw dev <iface> scan` (usually permitted)
  Windows — `netsh wlan show interfaces` / `show networks mode=bssid`

The parsers are pure functions and are tested offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from systop.core import _platform

# --- Signal thresholds (dBm) -------------------------------------------------
# Industry practice: above -50 excellent, -60 good, -70 workable, -80 marginal.
RSSI_EXCELLENT = -50
RSSI_GOOD = -60
RSSI_FAIR = -70
RSSI_POOR = -80

# SNR (signal - noise), dB. VoIP/video needs more than 25 dB.
SNR_EXCELLENT = 40
SNR_GOOD = 25
SNR_MARGINAL = 15

# The non-overlapping channels on 2.4 GHz. Picking any other one interferes
# both with the neighbours and with yourself.
NON_OVERLAPPING_24 = (1, 6, 11)


@dataclass(slots=True)
class WifiNetwork:
    """A single Wi-Fi network that was seen (a neighbouring AP, or our own)."""

    ssid: str | None = None
    channel: int | None = None
    band: str | None = None  # "2.4GHz" | "5GHz" | "6GHz"
    width_mhz: int | None = None
    rssi_dbm: int | None = None
    security: str | None = None
    phy_mode: str | None = None

    @property
    def is_24ghz(self) -> bool:
        return self.band == "2.4GHz"


@dataclass(slots=True)
class WifiStatus:
    """The current Wi-Fi connection plus the networks around it."""

    available: bool = False  # is there Wi-Fi hardware at all
    connected: bool = False
    interface: str | None = None
    ssid: str | None = None
    rssi_dbm: int | None = None
    noise_dbm: int | None = None
    channel: int | None = None
    band: str | None = None
    width_mhz: int | None = None
    phy_mode: str | None = None
    tx_rate_mbps: float | None = None
    security: str | None = None
    country_code: str | None = None
    supported_phy: str | None = None  # e.g. "802.11 a/b/g/n/ac/ax"
    supports_5ghz: bool = False
    neighbours: list[WifiNetwork] = field(default_factory=list)
    error: str | None = None

    @property
    def snr_db(self) -> int | None:
        """The signal-to-noise ratio — a more telling figure than the signal itself."""
        if self.rssi_dbm is None or self.noise_dbm is None:
            return None
        return self.rssi_dbm - self.noise_dbm

    @property
    def signal_quality(self) -> str | None:
        """`excellent` | `good` | `fair` | `poor` | `unusable`."""
        if self.rssi_dbm is None:
            return None
        if self.rssi_dbm >= RSSI_EXCELLENT:
            return "excellent"
        if self.rssi_dbm >= RSSI_GOOD:
            return "good"
        if self.rssi_dbm >= RSSI_FAIR:
            return "fair"
        if self.rssi_dbm >= RSSI_POOR:
            return "poor"
        return "unusable"

    @property
    def is_24ghz(self) -> bool:
        return self.band == "2.4GHz"

    @property
    def five_ghz_available(self) -> bool:
        """Is a 5 GHz AP visible nearby (i.e. is there anything to move to)."""
        return any(n.band == "5GHz" for n in self.neighbours)

    @property
    def phy_generation(self) -> str | None:
        """The current PHY generation: `ax` | `ac` | `n` | `legacy`."""
        return _phy_generation(self.phy_mode)

    @property
    def supported_generation(self) -> str | None:
        """The highest generation the card supports."""
        return _phy_generation(self.supported_phy)


def _phy_generation(text: str | None) -> str | None:
    """Extract the highest generation from a PHY string — pure function.

    `802.11 a/b/g/n/ac/ax` -> `ax`; `802.11n` -> `n`. The order matters: `ax`
    is checked before `ac`, otherwise `ac` swallows `ax`.
    """
    if not text:
        return None
    low = text.lower()
    for gen in ("be", "ax", "ac"):
        if gen in low:
            return gen
    if "n" in low.replace("802.11", ""):
        return "n"
    return "legacy"


def channel_to_band(channel: int) -> str:
    """Determine the band from a channel number — pure function."""
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    return "6GHz"


# On 5 GHz the channels do not "slide" into one another the way they do on
# 2.4 GHz — they are divided into fixed blocks. An 80 MHz channel occupies
# exactly four 20 MHz channels and the block boundaries are fixed
# (UNII-1/2/2e/3).
#
# It cannot be worked out arithmetically: the UNII-3 block (149+) does not
# start on the same step as the earlier blocks ((149-36)/4 is not an integer).
# The blocks are therefore given DELIBERATELY as a table.
_5GHZ_80MHZ_BLOCKS: tuple[tuple[int, ...], ...] = (
    (36, 40, 44, 48),
    (52, 56, 60, 64),
    (100, 104, 108, 112),
    (116, 120, 124, 128),
    (132, 136, 140, 144),
    (149, 153, 157, 161),
)
_5GHZ_40MHZ_BLOCKS: tuple[tuple[int, ...], ...] = (
    (36, 40),
    (44, 48),
    (52, 56),
    (60, 64),
    (100, 104),
    (108, 112),
    (116, 120),
    (124, 128),
    (132, 136),
    (140, 144),
    (149, 153),
    (157, 161),
)


def channel_span(channel: int, band: str | None, width_mhz: int | None) -> set[int]:
    """Return the set of 20 MHz channels an AP occupies — pure function.

    Why this is needed: the note "channel 64" does not tell you how much room
    the AP actually takes up. An AP at 80 MHz width occupies four 20 MHz
    channels, so an 80 MHz AP on channel 36 touches all of 36/40/44/48.
    Comparing channel numbers alone misses these collisions entirely.

    2.4 GHz is not handled here — there the channels sit 5 MHz apart and
    overlap continuously, so it has its own (±4/±8) rule.
    """
    if band == "2.4GHz":
        return {channel}
    width = width_mhz or 20
    if width <= 20:
        return {channel}

    if band == "6GHz":
        # The 6 GHz channels are 1, 5, 9, ... — a uniform step, so arithmetic works.
        count = min(width // 20, 8)
        idx = (channel - 1) // 4
        start = (idx // count) * count
        return {1 + 4 * (start + i) for i in range(count)}

    blocks = _5GHZ_80MHZ_BLOCKS if width >= 80 else _5GHZ_40MHZ_BLOCKS
    for block in blocks:
        if channel in block:
            return set(block)
    # An unknown channel (DFS/regional) — be cautious, take only itself.
    return {channel}


def overlapping_channels(
    channel: int,
    band: str | None,
    width_mhz: int | None,
    neighbours: list[WifiNetwork],
) -> list[WifiNetwork]:
    """Return the neighbours that REALLY intersect our channel.

    It works for both bands, and that matters: only 2.4 GHz used to be checked,
    so neighbours sitting on EXACTLY the same 5 GHz channel (the most serious
    case — full co-channel contention) were never mentioned at all.

    * **2.4 GHz** — the channels overlap continuously: a difference below ±4
      means interference, and ±8 for a 40 MHz AP.
    * **5/6 GHz** — interference when the blocks intersect (`channel_span`).

    A neighbour in the other band never interferes — 2.4 and 5 GHz are
    physically different frequencies.
    """
    out: list[WifiNetwork] = []
    if band == "2.4GHz":
        for n in neighbours:
            if not n.is_24ghz or n.channel is None:
                continue
            reach = 8 if (n.width_mhz or 20) >= 40 else 4
            if abs(n.channel - channel) <= reach:
                out.append(n)
        return out

    mine = channel_span(channel, band, width_mhz)
    for n in neighbours:
        if n.channel is None or n.band != band:
            continue
        if mine & channel_span(n.channel, n.band, n.width_mhz):
            out.append(n)
    return out


def overlapping_24ghz(channel: int, neighbours: list[WifiNetwork]) -> list[WifiNetwork]:
    """Return the neighbours that INTERFERE with the given 2.4 GHz channel.

    The 2.4 GHz channels sit 5 MHz apart while the channel width is 20 MHz —
    which means an adjacent channel **physically overlaps**. A difference below
    4 means interference. A 40 MHz AP occupies twice as much room, so its reach
    is wider (±8).

    This is not used for 5 GHz: there the channels do not overlap (only the
    exact same channel, or an intersecting wide channel, is a problem).
    """
    out: list[WifiNetwork] = []
    for n in neighbours:
        if not n.is_24ghz or n.channel is None:
            continue
        reach = 8 if (n.width_mhz or 20) >= 40 else 4
        if abs(n.channel - channel) <= reach:
            out.append(n)
    return out


# ===========================================================================
# macOS — `system_profiler SPAirPortDataType`
# ===========================================================================

# The key may be any character at all: macOS writes the SSID as "<redacted>"
# and that does not start with a letter.
_MAC_KV = re.compile(r"^\s*([^:]+?):\s*(.*?)\s*$")
_MAC_FIELDS = frozenset(
    {
        "PHY Mode",
        "Channel",
        "Network Type",
        "Security",
        "Signal / Noise",
        "Transmit Rate",
        "MCS Index",
        "Country Code",
        "Status",
    }
)
_MAC_CHANNEL = re.compile(r"^(\d+)\s*\(([\d.]+)GHz(?:,\s*(\d+)MHz)?\)")
_MAC_SIGNAL = re.compile(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm")


def _neighbour_has(n: WifiNetwork, key: str) -> bool:
    """Is this field already filled in on the neighbour object — pure function.

    Used to find block boundaries: in blocks without a header a repeated key
    means a new AP has started.
    """
    mapping = {
        "PHY Mode": n.phy_mode,
        "Channel": n.channel,
        "Security": n.security,
    }
    return mapping.get(key) is not None


def parse_macos_airport(text: str) -> WifiStatus:
    """Parse `system_profiler SPAirPortDataType` output — pure function.

    The output is hierarchical and relies on indentation:
        Interfaces: > en0: > Current Network Information: > <SSID>: > keys
        plus a separate "Other Local Wi-Fi Networks:" section (the neighbours).
    We track the section with the **header lines** rather than the indentation
    — the indentation has changed between macOS versions.
    """
    st = WifiStatus()
    section = None  # None | "current" | "others"
    pending_ssid: str | None = None
    current_neighbour: WifiNetwork | None = None

    def flush() -> None:
        nonlocal current_neighbour
        if current_neighbour is not None and current_neighbour.channel is not None:
            st.neighbours.append(current_neighbour)
        current_neighbour = None

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        stripped = line.strip()

        if stripped.startswith("Current Network Information"):
            section = "current"
            pending_ssid = None
            continue
        if stripped.startswith("Other Local Wi-Fi Networks"):
            flush()
            section = "others"
            continue
        if stripped.startswith("Interfaces:"):
            section = None
            continue

        m = _MAC_KV.match(line)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()

        # A key without a value = the header of a new block (an SSID or an
        # interface name).
        if not val:
            if section == "current":
                pending_ssid = key
                # macOS hides the SSID ("<redacted>") — we do not keep the name
                # but we do record that there is a connection.
                st.ssid = None if key.startswith("<") else key
                st.connected = True
            elif section == "others":
                flush()
                current_neighbour = WifiNetwork(ssid=None if key.startswith("<") else key)
            elif re.fullmatch(r"[a-z]+\d+", key):
                st.interface = key
                st.available = True
            continue

        # In the neighbours section some blocks have NO SSID header at all
        # (macOS removes it entirely). There we detect the block boundary from
        # a repeated key: a second "PHY Mode" means a new AP.
        if section == "others" and key in _MAC_FIELDS:
            if current_neighbour is None:
                current_neighbour = WifiNetwork()
            elif _neighbour_has(current_neighbour, key):
                flush()
                current_neighbour = WifiNetwork()

        target = current_neighbour if section == "others" else None

        if key == "Supported PHY Modes":
            st.supported_phy = val
            st.available = True
            st.supports_5ghz = "a" in val.lower()
        elif key == "Supported Channels":
            st.supports_5ghz = st.supports_5ghz or "5GHz" in val
        elif key == "Country Code" and section != "others":
            st.country_code = val
        elif key == "PHY Mode":
            if target is not None:
                target.phy_mode = val
            elif section == "current":
                st.phy_mode = val
        elif key == "Channel":
            cm = _MAC_CHANNEL.match(val)
            if cm:
                ch = int(cm.group(1))
                band = f"{cm.group(2)}GHz".replace("2GHz", "2.4GHz")
                width = int(cm.group(3)) if cm.group(3) else None
                if target is not None:
                    target.channel, target.band, target.width_mhz = ch, band, width
                elif section == "current":
                    st.channel, st.band, st.width_mhz = ch, band, width
        elif key == "Signal / Noise":
            sm = _MAC_SIGNAL.search(val)
            if sm and section == "current":
                st.rssi_dbm, st.noise_dbm = int(sm.group(1)), int(sm.group(2))
        elif key == "Transmit Rate" and section == "current":
            try:
                st.tx_rate_mbps = float(val)
            except ValueError:
                pass
        elif key == "Security":
            if target is not None:
                target.security = val
            elif section == "current":
                st.security = val
        elif key == "Status" and val.lower() == "connected":
            st.connected = True
        # `pending_ssid` is only needed to mark the first SSID block.
        _ = pending_ssid

    flush()
    return st


# ===========================================================================
# Linux — `iw dev <iface> link`
# ===========================================================================

_IW_SSID = re.compile(r"^\s*SSID:\s*(.+)$", re.MULTILINE)
_IW_SIGNAL = re.compile(r"^\s*signal:\s*(-?\d+)\s*dBm", re.MULTILINE)
_IW_FREQ = re.compile(r"^\s*freq:\s*(\d+)", re.MULTILINE)
_IW_TXRATE = re.compile(r"^\s*tx bitrate:\s*([\d.]+)\s*MBit/s", re.MULTILINE)
_IW_WIDTH = re.compile(r"(\d+)MHz")


def freq_to_channel(mhz: int) -> int | None:
    """Convert a frequency (MHz) into a channel number — pure function."""
    if 2412 <= mhz <= 2472:
        return (mhz - 2412) // 5 + 1
    if mhz == 2484:
        return 14
    if 5160 <= mhz <= 5885:
        return (mhz - 5000) // 5
    if 5955 <= mhz <= 7115:
        return (mhz - 5955) // 5 + 1
    return None


def parse_iw_link(text: str, interface: str | None = None) -> WifiStatus:
    """Parse Linux `iw dev <iface> link` output — pure function."""
    st = WifiStatus(interface=interface)
    if "Not connected" in text:
        st.available = True
        return st

    m = _IW_SSID.search(text)
    if m:
        st.ssid = m.group(1).strip()
        st.connected = True
        st.available = True
    m = _IW_SIGNAL.search(text)
    if m:
        st.rssi_dbm = int(m.group(1))
    m = _IW_FREQ.search(text)
    if m:
        freq = int(m.group(1))
        st.channel = freq_to_channel(freq)
        if st.channel is not None:
            st.band = channel_to_band(st.channel)
    m = _IW_TXRATE.search(text)
    if m:
        st.tx_rate_mbps = float(m.group(1))
        wm = _IW_WIDTH.search(m.group(0) if m.group(0) else "")
        if wm:
            st.width_mhz = int(wm.group(1))
    return st


# ===========================================================================
# Windows — `netsh wlan show interfaces`
# ===========================================================================

_NETSH_KV = re.compile(r"^\s*([^:]+?)\s*:\s*(.+?)\s*$")


def parse_netsh_interfaces(text: str) -> WifiStatus:
    """Parse Windows `netsh wlan show interfaces` output — pure function.

    The language-dependence problem: netsh is localised (on a Russian or Uzbek
    Windows the keys are translated). So we also search by the **shape of the
    value** rather than by key alone (dBm, %, a channel number).
    """
    st = WifiStatus()
    for line in text.splitlines():
        m = _NETSH_KV.match(line)
        if not m:
            continue
        key, val = m.group(1).strip().lower(), m.group(2).strip()
        if key in ("ssid",) and not st.ssid:
            st.ssid = val
            st.connected = True
            st.available = True
        elif key in ("channel", "канал"):
            try:
                st.channel = int(val)
                st.band = channel_to_band(st.channel)
            except ValueError:
                pass
        elif key in ("signal", "сигнал") and val.endswith("%"):
            try:
                # netsh reports a percentage; convert to an approximate dBm:
                # 100% ~ -50 dBm, 0% ~ -100 dBm (a linear approximation).
                pct = int(val.rstrip("%"))
                st.rssi_dbm = int(pct / 2 - 100)
            except ValueError:
                pass
        elif key in ("radio type", "тип радио"):
            st.phy_mode = val
        elif key in ("authentication", "проверка подлинности"):
            st.security = val
        elif "receive rate" in key or "transmit rate" in key:
            try:
                st.tx_rate_mbps = float(val.split()[0])
            except (ValueError, IndexError):
                pass
    return st


# ===========================================================================
# Orchestrator
# ===========================================================================


async def status() -> WifiStatus:
    """Get the current Wi-Fi state. `available=False` when there is no Wi-Fi.

    Never raises. On a machine with no Wi-Fi hardware (a server, a wired
    workstation) it MUST produce no warning at all — otherwise every Ethernet
    host reported a false "Wi-Fi problem".
    """
    if _platform.IS_MACOS:
        out = await _platform.run_command(["system_profiler", "SPAirPortDataType"], timeout=20.0)
        if not out:
            return WifiStatus(error="system_profiler returned nothing")
        return parse_macos_airport(out)

    if _platform.IS_WINDOWS:
        out = await _platform.run_command(["netsh", "wlan", "show", "interfaces"], timeout=15.0)
        if not out:
            return WifiStatus(error="netsh returned nothing")
        if "not running" in out.lower() or "no wireless" in out.lower():
            return WifiStatus(available=False)
        return parse_netsh_interfaces(out)

    # Linux: find the wireless interface first.
    dev = await _platform.run_command(["iw", "dev"], timeout=10.0)
    if not dev:
        return WifiStatus(available=False)
    m = re.search(r"Interface\s+(\S+)", dev)
    if not m:
        return WifiStatus(available=False)
    iface = m.group(1)
    link = await _platform.run_command(["iw", "dev", iface, "link"], timeout=10.0)
    if not link:
        return WifiStatus(available=True, interface=iface, error="iw link returned nothing")
    return parse_iw_link(link, interface=iface)
