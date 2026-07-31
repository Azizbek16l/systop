"""ncat/netcat uslubidagi xom TCP/TLS mijoz — qo'lda xizmat tekshirish uchun.

Nima uchun: `scan` "port ochiq" deydi, `web` HTTP tekshiradi. Lekin ba'zan
portga **xom ulanib**, o'zingiz nima yuborishni va nima kelishini ko'rish kerak
bo'ladi — SMTP salomlashishi, Redis `PING`, xom HTTP so'rovi, TLS handshake.
`nc` shu ishni qiladi.

nmap/ncat'dan farqi (halol chegara): bu **mijoz**, server rejimi (`-l` listen)
yo'q va root talab qiladigan xom paket funksiyalari yo'q. Faqat TCP connect +
ixtiyoriy TLS.

IPv6 to'liq qo'llab-quvvatlanadi: `family` bilan majburan tanlash mumkin, xom
IPv6 manzil qavssiz beriladi (`asyncio.open_connection` shunday kutadi).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import ssl
import time
from dataclasses import dataclass

from systop.core.ports import FAMILY_AUTO, _resolve

# `\r\n`, `\t`, `\x41`, `\\` kabi ketma-ketliklar.
_ESCAPE_RE = re.compile(r"\\(r|n|t|0|\\|x[0-9a-fA-F]{2})")

_ESCAPES: dict[str, bytes] = {
    "r": b"\r",
    "n": b"\n",
    "t": b"\t",
    "0": b"\x00",
    "\\": b"\\",
}


def unescape(text: str) -> bytes:
    """Matndagi `\\r\\n` kabi ketma-ketliklarni haqiqiy baytlarga aylantiradi.

    SOF funksiya (offline sinaladi). Kerak, chunki shellda `--send "GET /
    HTTP/1.0\\r\\n\\r\\n"` yozganda `\\r\\n` **matn** sifatida keladi, xizmat esa
    haqiqiy CRLF kutadi — aks holda HTTP so'rovi hech qachon yakunlanmaydi.

    Tanilmagan ketma-ketlik (`\\q`) o'z holida qoldiriladi.
    """
    out = bytearray()
    pos = 0
    for m in _ESCAPE_RE.finditer(text):
        out += text[pos : m.start()].encode("utf-8", "replace")
        token = m.group(1)
        if token.startswith("x"):
            out.append(int(token[1:], 16))
        else:
            out += _ESCAPES[token]
        pos = m.end()
    out += text[pos:].encode("utf-8", "replace")
    return bytes(out)


def to_hexdump(data: bytes, width: int = 16) -> str:
    """Baytlarni `hexdump -C` uslubida ko'rsatadi (ikkilik javob uchun)."""
    lines: list[str] = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexs}  |{text}|")
    return "\n".join(lines)


@dataclass(slots=True)
class NcResult:
    """Bitta `nc` ulanishi natijasi."""

    host: str
    port: int
    resolved_ip: str | None = None
    family: str | None = None
    connected: bool = False
    tls: bool = False
    tls_version: str | None = None
    tls_cipher: str | None = None
    # Sertifikat SHA-256 fingerprint'i. `subject` EMAS: bu yerda tekshiruv
    # o'chirilgan (`CERT_NONE`) va o'shanda `getpeercert()` bo'sh lug'at
    # qaytaradi — subject'ni ko'rsatib bo'lmaydi. Fingerprint esa DER'dan
    # to'g'ridan-to'g'ri hisoblanadi va qurilmani aniqlash uchun yetarli.
    # To'liq sertifikat tahlili uchun: `systop tls HOST`.
    peer_cert_sha256: str | None = None
    sent_bytes: int = 0
    received: bytes = b""
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def received_text(self) -> str:
        """Javobni matn sifatida (dekodlanmasa `?` bilan)."""
        return self.received.decode("utf-8", errors="replace")

    @property
    def received_bytes_count(self) -> int:
        return len(self.received)

    @property
    def is_binary(self) -> bool:
        """Javob ikkilikmi (chop etilmaydigan bayt ulushi yuqorimi)?"""
        if not self.received:
            return False
        printable = sum(1 for b in self.received if 32 <= b < 127 or b in (9, 10, 13))
        return printable / len(self.received) < 0.85


def _tls_context() -> ssl.SSLContext:
    """LAN qurilmalari uchun TLS konteksti — sertifikat TEKSHIRILMAYDI.

    Sabab: router/NVR/kamera panellarida deyarli har doim self-signed
    sertifikat bo'ladi va bu tool'ning maqsadi inventarizatsiya/diagnostika,
    ishonch zanjirini tasdiqlash emas. Sertifikat sifatini tekshirish uchun
    alohida `systop tls` buyrug'i bor.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def connect(
    host: str,
    port: int,
    send: bytes | None = None,
    tls: bool = False,
    timeout: float = 5.0,
    family: str = FAMILY_AUTO,
    read_bytes: int = 8192,
    wait_read: float | None = None,
) -> NcResult:
    """Portga xom TCP (yoki TLS) ulanadi, ixtiyoriy payload yuboradi, javob o'qiydi.

    Istisno ko'tarmaydi — xato `error` maydonida qaytadi.

    `wait_read` — javobni qancha kutish (None bo'lsa `timeout` ishlatiladi).
    Salomlashmaydigan xizmatda (masalan `send=None` bilan HTTP) javob kelmasa
    bu vaqt bekorga ketadi, shuning uchun qisqaroq qiymat berish mumkin.
    """
    result = NcResult(host=host, port=port, tls=tls)
    resolved, fam = await _resolve(host, family)
    if resolved is None:
        result.error = (
            f"'{host}' resolve bo'lmadi"
            + (" (IPv6 manzil yo'q?)" if family == "ipv6" else "")
        )
        return result
    result.resolved_ip = resolved
    result.family = fam

    start = time.perf_counter()
    writer = None
    try:
        ctx = _tls_context() if tls else None
        # server_hostname faqat TLS uchun va IP bo'lmagan nomda ma'noli.
        kwargs: dict[str, object] = {}
        if ctx is not None:
            kwargs["ssl"] = ctx
            kwargs["server_hostname"] = None if resolved == host else host
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved, port, **kwargs), timeout=timeout
        )
        result.connected = True

        if tls:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is not None:
                result.tls_version = sslobj.version()
                cipher = sslobj.cipher()
                result.tls_cipher = cipher[0] if cipher else None
                der = sslobj.getpeercert(binary_form=True)
                if der:
                    digest = hashlib.sha256(der).hexdigest()
                    # Ikki-ikki guruhlab o'qishli qilamiz (openssl uslubi).
                    result.peer_cert_sha256 = ":".join(
                        digest[i : i + 2] for i in range(0, len(digest), 2)
                    ).upper()

        if send:
            writer.write(send)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            result.sent_bytes = len(send)

        try:
            result.received = await asyncio.wait_for(
                reader.read(read_bytes), timeout=wait_read if wait_read else timeout
            )
        except TimeoutError:
            # Ulanish bo'ldi, lekin javob kelmadi — bu xato EMAS (ko'p xizmat
            # so'rovsiz jim turadi). `connected=True` qoladi.
            pass

    except TimeoutError:
        result.error = f"ulanish timeout ({timeout:.1f}s)"
    except ssl.SSLError as exc:
        result.error = f"TLS xatosi: {exc.reason or exc}"
    except ConnectionRefusedError:
        result.error = "ulanish rad etildi (port yopiq)"
    except OSError as exc:
        result.error = f"ulanish xatosi: {exc.strerror or exc}"
    finally:
        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError, TimeoutError):
                pass

    return result
