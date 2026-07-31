"""Wi-Fi diagnostikasi — signal, kanal, diapazon, qo'shnilar. Root kerak emas.

Nima uchun sysadmin uchun muhim: "internet sekin" shikoyatlarining katta qismi
aslida internet emas, **radio** muammosi. Ping va speedtest buni ko'rsatmaydi —
ular faqat natijani o'lchaydi, sababini emas. Eng ko'p uchraydigan holatlar:

  * **Signal kuchli, lekin tezlik past** — qurilma 2.4 GHz da o'tirgan, holbuki
    5 GHz mavjud. 2.4 GHz da 20 MHz kanal ~144 Mbps bilan cheklaydi;
  * **Kanal tiqilinchi** — 2.4 GHz da atigi 3 ta ustma-ust tushmaydigan kanal
    bor (1/6/11). Qo'shni AP 40 MHz kenglikda ishlasa, u ikkita kanalni
    bosadi va SNR yaxshi bo'lsa ham tezlik yiqiladi;
  * **PHY karta imkoniyatidan past** — ax qo'llab-quvvatlanadi, lekin n da
    ulangan (eski router yoki noto'g'ri sozlama);
  * **Zaif signal** — RSSI -70 dan past bo'lsa retransmissiya keskin oshadi.

Har platformada root talab qilmaydigan manba ishlatiladi:
  macOS   — `system_profiler SPAirPortDataType` (`wdutil` sudo talab qiladi,
            `airport -I` esa macOS 14.4 dan olib tashlangan — shuning uchun
            ikkalasi ham EMAS)
  Linux   — `iw dev <iface> link` + `iw dev <iface> scan` (odatda ruxsat bor)
  Windows — `netsh wlan show interfaces` / `show networks mode=bssid`

Parse'lar sof funksiya — offline sinaladi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from systop.core import _platform

# --- Signal chegaralari (dBm) ------------------------------------------------
# Sanoat amaliyoti: -50 dan yuqori a'lo, -60 yaxshi, -70 ishlaydi, -80 chegara.
RSSI_EXCELLENT = -50
RSSI_GOOD = -60
RSSI_FAIR = -70
RSSI_POOR = -80

# SNR (signal - shovqin), dB. VoIP/video uchun 25 dB dan yuqori kerak.
SNR_EXCELLENT = 40
SNR_GOOD = 25
SNR_MARGINAL = 15

# 2.4 GHz da ustma-ust tushmaydigan kanallar. Boshqasi tanlansa qo'shnilarga
# ham, o'ziga ham xalaqit beradi.
NON_OVERLAPPING_24 = (1, 6, 11)


@dataclass(slots=True)
class WifiNetwork:
    """Ko'ringan bitta Wi-Fi tarmoq (qo'shni AP yoki o'zimiznikini)."""

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
    """Joriy Wi-Fi ulanishi + atrofdagi tarmoqlar."""

    available: bool = False  # umuman Wi-Fi apparati bormi
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
    supported_phy: str | None = None  # masalan "802.11 a/b/g/n/ac/ax"
    supports_5ghz: bool = False
    neighbours: list[WifiNetwork] = field(default_factory=list)
    error: str | None = None

    @property
    def snr_db(self) -> int | None:
        """Signal/shovqin nisbati — signalning o'zidan ko'ra muhimroq ko'rsatkich."""
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
        """Atrofda 5 GHz AP ko'rinyaptimi (ya'ni o'tish imkoni bormi)."""
        return any(n.band == "5GHz" for n in self.neighbours)

    @property
    def phy_generation(self) -> str | None:
        """Joriy PHY avlodi: `ax` | `ac` | `n` | `legacy`."""
        return _phy_generation(self.phy_mode)

    @property
    def supported_generation(self) -> str | None:
        """Karta qo'llab-quvvatlaydigan eng yuqori avlod."""
        return _phy_generation(self.supported_phy)


def _phy_generation(text: str | None) -> str | None:
    """PHY satridan eng yuqori avlodni ajratadi — SOF funksiya.

    `802.11 a/b/g/n/ac/ax` -> `ax`; `802.11n` -> `n`. Tartib muhim: `ax` ni
    `ac` dan oldin tekshiramiz, aks holda `ac` `ax` ni yutib yuboradi.
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
    """Kanal raqamidan diapazonni aniqlaydi — SOF funksiya."""
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    return "6GHz"


# 5 GHz da kanallar 2.4 GHz dagidek "surilib" ustma-ust tushmaydi — ular
# qat'iy bloklarga bo'lingan. 80 MHz kanal aynan to'rtta 20 MHz kanalni
# egallaydi va bloklar chegarasi belgilangan (UNII-1/2/2e/3).
#
# Arifmetika bilan hisoblab bo'lmaydi: UNII-3 (149+) blokining boshlanishi
# oldingi bloklar bilan bir xil qadamda emas ((149-36)/4 butun son emas).
# Shuning uchun bloklar ATAYLAB ro'yxat sifatida berilgan.
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
    """AP egallagan 20 MHz kanallar to'plamini qaytaradi — SOF funksiya.

    Nima uchun kerak: "kanal 64" degan yozuv AP aslida qancha joy egallashini
    aytmaydi. 80 MHz kenglikdagi AP to'rtta 20 MHz kanalni egallaydi, ya'ni
    kanal 36 dagi 80 MHz AP 36/40/44/48 ning hammasiga tegadi. Faqat kanal
    raqamini taqqoslash bu to'qnashuvlarni butunlay o'tkazib yuboradi.

    2.4 GHz bu yerda ishlatilmaydi — u yerda kanallar 5 MHz qadamda va
    uzluksiz ustma-ust tushadi, shuning uchun alohida (±4/±8) qoida bor.
    """
    if band == "2.4GHz":
        return {channel}
    width = width_mhz or 20
    if width <= 20:
        return {channel}

    if band == "6GHz":
        # 6 GHz kanallari 1, 5, 9, ... — qadam bir xil, arifmetika ishlaydi.
        count = min(width // 20, 8)
        idx = (channel - 1) // 4
        start = (idx // count) * count
        return {1 + 4 * (start + i) for i in range(count)}

    blocks = _5GHZ_80MHZ_BLOCKS if width >= 80 else _5GHZ_40MHZ_BLOCKS
    for block in blocks:
        if channel in block:
            return set(block)
    # Noma'lum kanal (DFS/mintaqaviy) — ehtiyotkor bo'lamiz, faqat o'zi.
    return {channel}


def overlapping_channels(
    channel: int,
    band: str | None,
    width_mhz: int | None,
    neighbours: list[WifiNetwork],
) -> list[WifiNetwork]:
    """Bizning kanalimiz bilan CHINDAN kesishadigan qo'shnilarni qaytaradi.

    Ikkala diapazon uchun ham ishlaydi va bu muhim: ilgari faqat 2.4 GHz
    tekshirilardi, natijada 5 GHz da AYNAN bir kanalda turgan qo'shnilar
    (eng jiddiy holat — to'liq co-channel raqobat) umuman aytilmasdi.

    * **2.4 GHz** — kanallar uzluksiz ustma-ust tushadi: farq ±4 dan kichik
      bo'lsa xalaqit bor, 40 MHz AP uchun ±8.
    * **5/6 GHz** — bloklar kesishsa xalaqit bor (`channel_span`).

    Boshqa diapazondagi qo'shni hech qachon xalaqit bermaydi — 2.4 va 5 GHz
    fizik jihatdan turli chastotalar.
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
    """2.4 GHz da berilgan kanalga XALAQIT beradigan qo'shnilarni qaytaradi.

    2.4 GHz kanallari 5 MHz oralig'ida, kanal kengligi esa 20 MHz — ya'ni
    qo'shni kanal **fizik ravishda ustma-ust tushadi**. Farq 4 dan kichik
    bo'lsa xalaqit bor. 40 MHz kenglikdagi AP esa ikki barobar keng joyni
    egallaydi, shuning uchun uning ta'sir radiusi kengroq (±8).

    Bu 5 GHz uchun ishlatilmaydi: u yerda kanallar ustma-ust tushmaydi
    (faqat aynan bir xil kanal yoki kesishuvchi keng kanal muammo qiladi).
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

# Kalit har qanday belgi bo'lishi mumkin: macOS SSID'ni "<redacted>" qilib
# yozadi va u harf bilan boshlanmaydi.
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
    """Qo'shni obyektida shu maydon allaqachon to'ldirilganmi — SOF funksiya.

    Blok chegarasini aniqlash uchun: sarlavhasiz bloklarda takroriy kalit
    yangi AP boshlanganini bildiradi.
    """
    mapping = {
        "PHY Mode": n.phy_mode,
        "Channel": n.channel,
        "Security": n.security,
    }
    return mapping.get(key) is not None


def parse_macos_airport(text: str) -> WifiStatus:
    """`system_profiler SPAirPortDataType` chiqishini parse qiladi — SOF funksiya.

    Chiqish ierarxik va indentatsiyaga tayanadi:
        Interfaces: > en0: > Current Network Information: > <SSID>: > kalitlar
        va alohida "Other Local Wi-Fi Networks:" bo'limi (qo'shnilar).
    Biz bo'lim holatini indentatsiya emas, **sarlavha qatorlari** bilan
    kuzatamiz — indentatsiya macOS versiyalari orasida o'zgargan.
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

        # Qiymatsiz kalit = yangi blok sarlavhasi (SSID yoki interfeys nomi).
        if not val:
            if section == "current":
                pending_ssid = key
                # macOS SSID'ni yashiradi ("<redacted>") — nomni saqlamaymiz,
                # lekin ulanish borligini belgilaymiz.
                st.ssid = None if key.startswith("<") else key
                st.connected = True
            elif section == "others":
                flush()
                current_neighbour = WifiNetwork(ssid=None if key.startswith("<") else key)
            elif re.fullmatch(r"[a-z]+\d+", key):
                st.interface = key
                st.available = True
            continue

        # Qo'shnilar bo'limida ba'zi bloklarda SSID sarlavhasi UMUMAN yo'q
        # (macOS uni butunlay olib tashlaydi). Bunda blok chegarasini takroriy
        # kalitdan aniqlaymiz: ikkinchi marta "PHY Mode" kelsa — yangi AP.
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
        # `pending_ssid` faqat birinchi SSID blokini belgilash uchun kerak.
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
    """Chastotani (MHz) kanal raqamiga aylantiradi — SOF funksiya."""
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
    """Linux `iw dev <iface> link` chiqishini parse qiladi — SOF funksiya."""
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
    """Windows `netsh wlan show interfaces` chiqishini parse qiladi — SOF funksiya.

    Til-bog'liqlik muammosi: netsh mahalliylashtirilgan (rus/o'zbek Windows'da
    kalitlar tarjima qilinadi). Shuning uchun kalitlar bo'yicha emas, **qiymat
    shakli** bo'yicha ham qidiramiz (dBm, %, kanal raqami).
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
                # netsh foizda beradi; taxminiy dBm ga o'giramiz:
                # 100% ~ -50 dBm, 0% ~ -100 dBm (chiziqli yaqinlashtirish).
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
# Orkestrator
# ===========================================================================


async def status() -> WifiStatus:
    """Joriy Wi-Fi holatini oladi. Wi-Fi yo'q bo'lsa `available=False`.

    Istisno ko'tarmaydi. Wi-Fi apparati yo'q mashinada (server, kabelli
    ish stansiyasi) hech qanday ogohlantirish bermasligi SHART — aks holda
    har Ethernet hostda soxta "Wi-Fi muammosi" chiqardi.
    """
    if _platform.IS_MACOS:
        out = await _platform.run_command(["system_profiler", "SPAirPortDataType"], timeout=20.0)
        if not out:
            return WifiStatus(error="system_profiler natija bermadi")
        return parse_macos_airport(out)

    if _platform.IS_WINDOWS:
        out = await _platform.run_command(["netsh", "wlan", "show", "interfaces"], timeout=15.0)
        if not out:
            return WifiStatus(error="netsh natija bermadi")
        if "not running" in out.lower() or "no wireless" in out.lower():
            return WifiStatus(available=False)
        return parse_netsh_interfaces(out)

    # Linux: avval simsiz interfeysni topamiz.
    dev = await _platform.run_command(["iw", "dev"], timeout=10.0)
    if not dev:
        return WifiStatus(available=False)
    m = re.search(r"Interface\s+(\S+)", dev)
    if not m:
        return WifiStatus(available=False)
    iface = m.group(1)
    link = await _platform.run_command(["iw", "dev", iface, "link"], timeout=10.0)
    if not link:
        return WifiStatus(available=True, interface=iface, error="iw link natija bermadi")
    return parse_iw_link(link, interface=iface)
