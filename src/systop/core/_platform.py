"""Platforma-bog'liq umumiy yordamchilar (cross-platform qatlam).

Bu modul platforma aniqlashni VA Windows tizim buyruqlari chiqishini (ping /
tracert / route / arp) parse qiluvchi sof funksiyalarni bitta joyga jamlaydi.
Boshqa `core/` modullari (`netinfo`, `ping`, `topology`) platforma shoxini shu
yerdan oladi — shunda regex va parse mantiqi takrorlanmaydi va offline sinaladi.

Dizayn qarorlari:

* **Windows'da ICMP admin'siz.** `icmplib` Windows'da unprivileged ICMP'ni
  qo'llamaydi (raw socket => admin kerak). Shuning uchun Windows'da tizimning
  `ping.exe` / `tracert.exe` buyruqlariga tushamiz — ular admin talab qilmaydi.
  Chiqishni regex bilan parse qilib, RTT (ms) va paket yo'qotishni olamiz.
* **Faqat stdlib.** `platform`, `subprocess`, `asyncio`, `re` — qo'shimcha
  bog'liqlik yo'q.
* **Parse funksiyalari sof.** Tarmoqqa chiqmaydi, faqat satr -> qiymat; shuning
  uchun real Windows chiqish namunalari bilan offline sinaladi.

Eslatma: bu konstantalar (`IS_WINDOWS` va h.k.) modul-darajasida; testlarda
`monkeypatch.setattr(_platform, "IS_WINDOWS", True)` bilan almashtirilishi
mumkin, lekin chaqiruvchi modullar ularni `_platform.IS_WINDOWS` orqali (atribut
sifatida) o'qishi shart — shunda monkeypatch ta'sir qiladi.
"""

from __future__ import annotations

import asyncio
import platform
import re

# --- Platforma konstantalari (bitta manba) ----------------------------------

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


# --- Windows `ping` chiqishini parse qilish ---------------------------------

# RTT'ni har bir javob qatoridan ajratamiz: "time=12ms", "time<1ms", "time=1.5 ms".
# Windows lokalizatsiyalangan bo'lishi mumkin ("Время=12мс"), shuning uchun
# raqam + "ms"/"мс" naqshiga emas, "<"/"=" + raqam + birlikka tayanamiz.
_WIN_PING_RTT_RE = re.compile(
    r"[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*m",
    re.IGNORECASE,
)
# "time<1ms" => RTT 1ms'dan kichik; biz uni 0.5ms deb hisoblaymiz (taxminiy).
_WIN_PING_SUBMS_RE = re.compile(r"<\s*1\s*m", re.IGNORECASE)
# Yakuniy statistika qatori: "Lost = 1 (25% loss)". Lokalizatsiyaga chidamliroq
# bo'lishi uchun foizni ham, jo'natilgan/qabul qilingan sonni ham qidiramiz.
_WIN_PING_LOSS_PCT_RE = re.compile(r"\(\s*([0-9]+)\s*%")
# `Packets:` statistika qatorini aniqlaymiz (RTT/`time=` qatorlaridan farqlash
# uchun) va undan Sent/Received sonini ajratamiz.
_WIN_PING_STATS_LINE_RE = re.compile(r"(?:Sent|Received|Lost)\s*=\s*\d", re.IGNORECASE)
_WIN_PING_SENT_RE = re.compile(r"Sent\s*=\s*([0-9]+)", re.IGNORECASE)
_WIN_PING_RECV_RE = re.compile(r"Received\s*=\s*([0-9]+)", re.IGNORECASE)


def parse_windows_ping(output: str, expected_count: int) -> tuple[bool, list[float], float]:
    """Windows `ping` chiqishini (alive, rtts_ms, loss) ga aylantiradi.

    Argumentlar:
        output — `ping -n <count> ...` to'liq stdout matni.
        expected_count — yuborilgan paketlar soni (loss zaxira hisobi uchun).

    Qaytaradi:
        alive — kamida bitta javob kelganmi.
        rtts_ms — har javob RTT'si (ms); javobsizlar kirmaydi.
        loss — paket yo'qotish ulushi (0.0..1.0).

    `time<1ms` holatida RTT 0.5ms deb olinadi (1ms'dan kichik). Statistika
    qatori topilsa loss aynan undan olinadi; aks holda RTT sonidan hisoblanadi.
    """
    rtts: list[float] = []
    for line in output.splitlines():
        # Statistika qatorlari ("Lost = ...") RTT regex'iga tushmasligi uchun
        # faqat haqiqiy javob qatorlarini ("Reply"/"bytes=") ko'rib chiqamiz —
        # lekin lokalizatsiyaga bog'lanmaslik uchun: qatorda "ttl" yo'q bo'lsa
        # ham RTT naqshi bo'lsa, uni javob deb qabul qilamiz. Statistika
        # qatorida "ms" oldidan "=" yoki "<" kelmaydi (u "Minimum = 1ms" kabi,
        # bu ham RTT — lekin biz statistika blokini alohida ushlaymiz).
        low = line.lower()
        if "ttl=" not in low and "ttl =" not in low:
            continue
        if _WIN_PING_SUBMS_RE.search(line):
            rtts.append(0.5)
            continue
        m = _WIN_PING_RTT_RE.search(line)
        if m:
            rtts.append(float(m.group(1)))

    # Loss: avval yakuniy statistika qatoridan ("(25% loss)") — til-mustaqil.
    loss: float | None = None
    pct = _WIN_PING_LOSS_PCT_RE.search(output)
    if pct:
        loss = int(pct.group(1)) / 100.0
    else:
        # Zaxira: faqat statistika qatorida (`time=` qatorlarida emas) Sent/Received.
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
        # Statistika topilmadi — RTT sonidan taxminiy hisoblaymiz.
        count = expected_count if expected_count > 0 else 1
        loss = max(0.0, (count - len(rtts)) / count)
    return alive, rtts, loss


# --- Windows `tracert` chiqishini parse qilish ------------------------------

# `tracert -d` qatori, masalan:
#   "  1     1 ms     1 ms     1 ms  192.168.1.1"
#   "  3     *        *        *     Request timed out."
#   "  5    11 ms    10 ms    12 ms  8.8.8.8"
# Boshida hop raqami, keyin 3 ta RTT ustuni (yoki "*"), oxirida IP (yoki yo'q).
_WIN_TRACERT_LINE_RE = re.compile(
    r"^\s*(\d+)\s+(.*?)\s*$",
)
_WIN_TRACERT_RTT_RE = re.compile(r"([0-9]+)\s*m", re.IGNORECASE)
_WIN_TRACERT_SUBMS_RE = re.compile(r"<\s*1\s*m", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F:]{2,}:[0-9a-fA-F:]*)\b")


def parse_windows_tracert(output: str) -> list[tuple[int, str | None, float, bool]]:
    """Windows `tracert -d` chiqishini hop ro'yxatiga aylantiradi.

    Qaytaradi: har element `(hop_index, address|None, avg_rtt_ms, alive)`.

    `address` topilmasa (`* * * Request timed out`) -> None, alive=False, rtt=0.
    RTT — qatordagi mavjud o'lchovlar o'rtachasi (ms). `<1 ms` => 0.5ms.
    """
    hops: list[tuple[int, str | None, float, bool]] = []
    for line in output.splitlines():
        m = _WIN_TRACERT_LINE_RE.match(line)
        if not m:
            continue
        index = int(m.group(1))
        rest = m.group(2)

        # Manzil: avval IPv4, keyin IPv6 (tracert -d resolve qilmaydi).
        addr: str | None = None
        ip4 = _IPV4_RE.search(rest)
        if ip4:
            addr = ip4.group(1)
        else:
            ip6 = _IPV6_RE.search(rest)
            if ip6 and ":" in ip6.group(1):
                addr = ip6.group(1)

        # RTT ustunlari: "<1 ms" yoki "N ms" lar. IP qismini olib tashlab,
        # faqat o'lchov qismidan o'qiymiz (IP raqamlari RTT bo'lib hisoblanmasin).
        measure_part = rest
        if addr:
            measure_part = rest.replace(addr, " ")

        rtts: list[float] = []
        # `<1 ms` larni avval sanaymiz, keyin oddiy `N ms` larni.
        subms = len(_WIN_TRACERT_SUBMS_RE.findall(measure_part))
        rtts.extend([0.5] * subms)
        # `<1 ms` ni o'chirib, qolgan `N ms` larni o'qiymiz.
        cleaned = _WIN_TRACERT_SUBMS_RE.sub(" ", measure_part)
        for rm in _WIN_TRACERT_RTT_RE.finditer(cleaned):
            rtts.append(float(rm.group(1)))

        alive = addr is not None
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
        hops.append((index, addr, avg_rtt, alive))
    return hops


# --- Windows `route print` chiqishidan default gateway ----------------------

# IPv4 marshrut jadvalida default qatori:
#   "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     35"
# Birinchi ustun 0.0.0.0 (Network Destination), ikkinchi 0.0.0.0 (Netmask),
# uchinchi — Gateway IP. "On-link" gateway (link-local) ni tashlaymiz.
_WIN_ROUTE_DEFAULT_RE = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.MULTILINE,
)
# PowerShell `Get-NetRoute` / `Get-NetIPConfiguration` zaxira: NextHop ustuni.
_WIN_NETROUTE_NEXTHOP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})",
)


def parse_windows_route_print(output: str) -> str | None:
    """`route print -4` chiqishidan default (0.0.0.0/0) gateway IP'ni oladi."""
    m = _WIN_ROUTE_DEFAULT_RE.search(output)
    if m and m.group(1) != "0.0.0.0":
        return m.group(1)
    return None


# --- Umumiy async subprocess yordamchisi ------------------------------------


async def run_command(
    cmd: list[str],
    timeout: float,
) -> str:
    """Buyruqni async ishga tushirib stdout matnini qaytaradi (bloklanmaydi).

    Xato (buyruq yo'q / timeout / OS) bo'lsa bo'sh satr qaytaradi — chaqiruvchi
    "natija yo'q" deb degrade qilaverishi uchun (istisno ko'tarilmaydi).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
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
    return stdout.decode(errors="replace")
