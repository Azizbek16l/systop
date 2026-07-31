"""SNTP mijoz — soat siljishini (clock skew) aniqlash. Root kerak emas.

Nima uchun sysadmin uchun muhim: soat siljishi juda ko'p narsani jimgina
buzadi va sababi hech qayerda "vaqt" deb yozilmaydi —

  * **Kerberos/AD** 5 daqiqadan katta siljishda autentifikatsiyani rad etadi
    ("clock skew too great") — domenga kirish ishlamaydi;
  * **TLS** sertifikat "hali kuchga kirmagan" yoki "muddati tugagan" deb
    ko'rinadi, brauzer ogohlantiradi;
  * **loglar** turli serverlarda mos kelmaydi — incident tekshirish imkonsiz;
  * **TOTP/2FA** kodlari rad etiladi.

Faqat stdlib: UDP/123 ga 48-baytli SNTP so'rovi yuboriladi (mijoz tomoni
privileged port talab qilmaydi). Server javobidan RFC 4330 formulasi bilan
offset va round-trip delay hisoblanadi.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field

# NTP epoch (1900-01-01) va Unix epoch (1970-01-01) orasidagi soniyalar.
NTP_UNIX_DELTA = 2_208_988_800

# Standart tekshiriladigan serverlar. Lokal domen serverlari config bilan
# beriladi (AD muhitida domen kontrolleri NTP manbasi bo'ladi).
DEFAULT_NTP_SERVERS: dict[str, str] = {
    "Cloudflare": "time.cloudflare.com",
    "Google": "time.google.com",
    "pool.ntp.org": "pool.ntp.org",
}

# Amaliy chegaralar (Kerberos 300s da yiqiladi, shuning uchun ancha oldin ogohlantiramiz).
SKEW_WARN_S = 1.0
SKEW_HIGH_S = 30.0
SKEW_CRITICAL_S = 300.0


@dataclass(slots=True)
class NtpResult:
    """Bitta NTP serveridan olingan natija."""

    server: str
    label: str = ""
    ok: bool = False
    offset_s: float = 0.0  # mahalliy soat serverdan qancha farq qiladi (+ = oldinda)
    delay_ms: float = 0.0  # round-trip
    stratum: int = 0
    error: str | None = None

    @property
    def offset_ms(self) -> float:
        return self.offset_s * 1000.0

    @property
    def severity(self) -> str:
        """`ok` | `warn` | `high` | `critical` — siljish darajasi."""
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
    """Barcha serverlar bo'yicha jamlanma."""

    results: list[NtpResult] = field(default_factory=list)

    @property
    def responded(self) -> list[NtpResult]:
        return [r for r in self.results if r.ok]

    @property
    def median_offset_s(self) -> float | None:
        """Javob berganlar bo'yicha mediana siljish.

        Mediana ataylab: bitta server yolg'on vaqt bersa o'rtacha buziladi,
        mediana esa bardosh beradi.
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
    """48-baytli SNTP client so'rovi — `(paket, nonce)` qaytaradi.

    Nonce — Transmit Timestamp maydoniga (40:48) yoziladigan 8 tasodifiy bayt.
    Server uni javobning **Originate Timestamp** maydonida (24:32) aynan
    qaytaradi (RFC 4330). Bu bizga javobning HAQIQATAN shu so'rovga tegishli
    ekanini tekshirish imkonini beradi.

    Ilgali bu maydon nol edi — ya'ni tekshirish uchun hech narsa yo'q edi va
    ephemeral portga tushgan har qanday begona UDP datagrammasi "server
    javobi" deb qabul qilinardi (o'lchovda `offset=-400s`, `severity=critical`
    berardi).
    """
    packet = bytearray(48)
    packet[0] = 0x23  # 00 100 011 -> LI=0, VN=4, Mode=3 (client)
    nonce = secrets.token_bytes(8)
    packet[40:48] = nonce
    return bytes(packet), nonce


# stratum=0 bo'lganda Reference Identifier "kiss code" bo'ladi (RFC 4330 §8).
KISS_CODES: dict[str, str] = {
    "DENY": "server xizmat ko'rsatishni rad etdi (DENY)",
    "RSTR": "kirish cheklangan (RSTR)",
    "RATE": "so'rovlar juda tez-tez (RATE) — intervalni oshiring",
    "ACST": "anycast server",
    "AUTH": "autentifikatsiya xatosi (AUTH)",
    "INIT": "server hali sinxronlanmagan (INIT)",
    "STEP": "server soatini sakrash bilan to'g'rilamoqda (STEP)",
}

# Delay konverti uchun bo'shashish: soat granularligi va planlashtirish
# kechikishi tufayli kichik manfiy qiymat normal.
_DELAY_SLACK_S = 0.05


def _ntp_to_unix(seconds: int, fraction: int) -> float:
    """NTP 32.32 fixed-point timestamp'ni Unix vaqtiga o'giradi — SOF funksiya.

    RFC 4330 §3 "era" qoidasi: agar 0-bit (eng katta bit) o'rnatilgan bo'lsa
    vaqt 1968-2036 oralig'ida va 1900-yildan sanaladi; o'rnatilmagan bo'lsa
    2036-2104 oralig'ida va 2036-yil 7-fevraldan sanaladi.

    Bu shartsiz ayirish bilan aralashtirilsa, 2036-dan keyingi (yoki buzuq)
    timestamp **manfiy** Unix vaqtiga aylanib, `offset` ni ±2e9 soniyaga
    olib chiqadi.
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
    """SNTP javobidan (offset_s, delay_s, stratum) hisoblaydi — SOF funksiya.

    RFC 4330:
        offset = ((T2 - T1) + (T3 - T4)) / 2
        delay  = (T4 - T1) - (T3 - T2)
    Bu yerda T1/T4 — lokal jo'natish/qabul vaqti, T2/T3 — server vaqtlari.
    Qaytarilgan `offset` **serverga nisbatan lokal soat xatosi**.

    **Validatsiya ataylab qat'iy.** Bu modul "soat to'g'ri" degan xulosani
    beradi — noto'g'ri xulosa soat noto'g'riligidan xavfliroq (sysadmin
    tekshirishni to'xtatadi). Shuning uchun quyidagilar rad etiladi:

    * uzunlik < 48;
    * `Mode != 4` (server javobi emas — mijoz yoki broadcast paketi);
    * `LI == 3` (alarm — server o'zi sinxronlanmagan);
    * `stratum == 0` (Kiss-of-Death; sabab kiss kodidan o'qiladi);
    * `stratum > 15` (16 = sinxronlanmagan, undan yuqorisi yaroqsiz);
    * nonce mos kelmasa (javob boshqa so'rovga tegishli yoki soxta);
    * T2 **yoki** T3 nol (yarim bo'sh paket — ilgari faqat IKKALASI nol
      bo'lganda rad etilardi);
    * `delay` sababiyat konvertidan chiqsa (0 dan kichik yoki lokal o'lchangan
      to'liq round-trip'dan katta) — bu paket boshqa vaqtga tegishli degani.

    Xato paket bo'lsa `ValueError` (chaqiruvchi uni `error` matniga aylantiradi).
    """
    if len(data) < 48:
        raise ValueError(f"SNTP javobi qisqa: {len(data)} bayt (48 kerak)")

    li = (data[0] >> 6) & 0x3
    mode = data[0] & 0x7
    stratum = data[1]

    if mode != 4:
        raise ValueError(f"SNTP: server javobi emas (Mode={mode}, 4 kutilgan)")
    if li == 3:
        raise ValueError("SNTP: server sinxronlanmagan (LI=3, alarm)")
    if stratum == 0:
        kiss = data[12:16].decode("ascii", "replace").strip("\x00 ")
        raise ValueError(f"SNTP Kiss-of-Death: {KISS_CODES.get(kiss, kiss or 'noma`lum')}")
    if stratum > 15:
        raise ValueError(f"SNTP: yaroqsiz stratum {stratum} (1-15 kutilgan)")

    if nonce is not None and data[24:32] != nonce:
        raise ValueError("SNTP: javob so'rovga mos kelmadi (originate timestamp boshqa)")

    # Receive (T2) va Transmit (T3) timestamp'lar: 32.32 fixed point.
    t2_int, t2_frac, t3_int, t3_frac = struct.unpack("!IIII", data[32:48])
    # `or` — ATAYLAB. `and` bo'lganda yarim to'ldirilgan paket o'tib ketardi va
    # nol timestamp 1900-yilga aylanib ±2e9 soniyalik "siljish" berardi.
    if t2_int == 0 or t3_int == 0:
        raise ValueError("SNTP javobida timestamp yo'q (bo'sh yoki buzuq paket)")

    t2 = _ntp_to_unix(t2_int, t2_frac)
    t3 = _ntp_to_unix(t3_int, t3_frac)
    offset = ((t2 - t1) + (t3 - t4)) / 2.0
    delay = (t4 - t1) - (t3 - t2)

    # Sababiyat konverti — XOM `delay` bo'yicha, `max(delay, 0)` dan OLDIN.
    # Aks holda manfiy delay jimgina nolga aylanib, buzuq paket "mukammal
    # o'lchov" bo'lib ko'rinardi.
    elapsed = t4 - t1
    if delay < -_DELAY_SLACK_S or delay > elapsed + _DELAY_SLACK_S:
        raise ValueError(
            f"SNTP: javob vaqtlari mantiqsiz (delay {delay:.3f}s, "
            f"lokal round-trip {elapsed:.3f}s) — paket shu so'rovga tegishli emas"
        )
    return offset, max(delay, 0.0), stratum


async def query_server(server: str, timeout: float = 3.0, label: str = "") -> NtpResult:
    """Bitta NTP serverdan vaqt so'raydi. Istisno ko'tarmaydi."""
    res = NtpResult(server=server, label=label or server)
    loop = asyncio.get_running_loop()
    sock = None
    try:
        infos = await loop.getaddrinfo(server, 123, type=socket.SOCK_DGRAM)
        if not infos:
            res.error = "resolve bo'lmadi"
            return res
        family, socktype, proto, _, addr = infos[0]
        sock = socket.socket(family, socktype, proto)
        sock.setblocking(False)
        # `connect()` SHART: usiz `sock_recv` istalgan manbadan kelgan
        # datagrammani qabul qiladi va biz uning kimdan kelganini ko'rmaymiz.
        # Ulangandan keyin yadro boshqa peer'lardan kelganini o'zi tashlaydi.
        # UDP'da bu paket yubormaydi — faqat socketga peer biriktiradi.
        sock.connect(addr)
        packet, nonce = build_request()

        t1 = time.time()
        # `sock_sendto` EMAS: ulangan UDP socketda u `EISCONN` bilan yiqiladi.
        await loop.sock_sendall(sock, packet)
        data = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=timeout)
        t4 = time.time()

        offset, delay, stratum = parse_response(data, t1, t4, nonce=nonce)
        # Belgini foydalanuvchi tushunadigan yo'nalishga o'giramiz:
        # musbat => LOKAL soat serverdan oldinda.
        res.offset_s = -offset
        res.delay_ms = delay * 1000.0
        res.stratum = stratum
        res.ok = True
    except TimeoutError:
        res.error = f"javob kelmadi ({timeout:.0f}s)"
    except (OSError, socket.gaierror) as exc:
        res.error = f"tarmoq xatosi: {exc.strerror or exc}"
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
    """Bir nechta NTP serverni parallel so'rab, jamlanma qaytaradi.

    Bir nechta server so'raladi — bitta server yolg'on vaqt bersa mediana
    uni yutib yuboradi (bitta manbaga ishonib qolmaslik uchun).
    """
    srv = servers or DEFAULT_NTP_SERVERS
    tasks = [query_server(host, timeout, label) for label, host in srv.items()]
    results = list(await asyncio.gather(*tasks))
    return NtpReport(results=results)
