"""An ncat/netcat-style raw TCP/TLS client — for checking a service by hand.

Why: `scan` says "the port is open" and `web` checks HTTP. But sometimes you
need to connect to a port **raw** and see for yourself what you send and what
comes back — an SMTP greeting, a Redis `PING`, a raw HTTP request, a TLS
handshake. `nc` does that job.

How it differs from nmap/ncat (the honest boundary): this is a **client**; there
is no server mode (`-l` listen) and no raw-packet feature that would need root.
TCP connect plus optional TLS, and nothing else.

IPv6 is fully supported: the family can be forced with `family`, and a raw IPv6
address is given without brackets (that is what `asyncio.open_connection`
expects).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import ssl
import time
from dataclasses import dataclass

from systop.core.ports import FAMILY_AUTO, _resolve

# Sequences such as `\r\n`, `\t`, `\x41`, `\\`.
_ESCAPE_RE = re.compile(r"\\(r|n|t|0|\\|x[0-9a-fA-F]{2})")

_ESCAPES: dict[str, bytes] = {
    "r": b"\r",
    "n": b"\n",
    "t": b"\t",
    "0": b"\x00",
    "\\": b"\\",
}


def unescape(text: str) -> bytes:
    """Turns sequences such as `\\r\\n` in the text into the real bytes.

    A pure function (tested offline). It is needed because when you type
    `--send "GET / HTTP/1.0\\r\\n\\r\\n"` in a shell, the `\\r\\n` arrives as
    **text**, whereas the service expects a real CRLF — otherwise the HTTP
    request is never terminated.

    An unrecognised sequence (`\\q`) is left as it is.
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
    """Shows the bytes in `hexdump -C` style (for a binary answer)."""
    lines: list[str] = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexs}  |{text}|")
    return "\n".join(lines)


@dataclass(slots=True)
class NcResult:
    """The result of a single `nc` connection."""

    host: str
    port: int
    resolved_ip: str | None = None
    family: str | None = None
    connected: bool = False
    tls: bool = False
    tls_version: str | None = None
    tls_cipher: str | None = None
    # The certificate's SHA-256 fingerprint. NOT the `subject`: verification is
    # switched off here (`CERT_NONE`) and in that case `getpeercert()` returns an
    # empty dict — the subject cannot be shown. The fingerprint, on the other
    # hand, is computed straight from the DER and is enough to identify a device.
    # For a full certificate analysis: `systop tls HOST`.
    peer_cert_sha256: str | None = None
    sent_bytes: int = 0
    received: bytes = b""
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def received_text(self) -> str:
        """The answer as text (undecodable bytes become `?`)."""
        return self.received.decode("utf-8", errors="replace")

    @property
    def received_bytes_count(self) -> int:
        return len(self.received)

    @property
    def is_binary(self) -> bool:
        """Is the answer binary (is the share of non-printable bytes high)?"""
        if not self.received:
            return False
        printable = sum(1 for b in self.received if 32 <= b < 127 or b in (9, 10, 13))
        return printable / len(self.received) < 0.85


def _tls_context() -> ssl.SSLContext:
    """The TLS context for LAN devices — the certificate is NOT VERIFIED.

    The reason: router/NVR/camera panels almost always carry a self-signed
    certificate, and the purpose of this tool is inventory/diagnostics, not
    validating a chain of trust. There is a separate `systop tls` command for
    checking certificate quality.
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
    """Connects raw TCP (or TLS) to a port, optionally sends a payload, reads the answer.

    It never raises — the error comes back in the `error` field.

    `wait_read` — how long to wait for the answer (when None, `timeout` is used).
    With a service that does not greet (HTTP with `send=None`, say) no answer
    arrives and that time is spent for nothing, so a shorter value can be given.
    """
    result = NcResult(host=host, port=port, tls=tls)
    resolved, fam = await _resolve(host, family)
    if resolved is None:
        result.error = f"'{host}' did not resolve" + (
            " (no IPv6 address?)" if family == "ipv6" else ""
        )
        return result
    result.resolved_ip = resolved
    result.family = fam

    start = time.perf_counter()
    writer = None
    try:
        ctx = _tls_context() if tls else None
        # server_hostname only applies to TLS, and only means anything for a
        # name that is not an IP.
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
                    # Group it in pairs to make it readable (the openssl style).
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
            # The connection succeeded but no answer arrived — this is NOT an
            # error (many services stay silent until asked). `connected=True`
            # stands.
            pass

    except TimeoutError:
        result.error = f"connection timed out ({timeout:.1f}s)"
    except ssl.SSLError as exc:
        result.error = f"TLS error: {exc.reason or exc}"
    except ConnectionRefusedError:
        result.error = "connection refused (the port is closed)"
    except OSError as exc:
        result.error = f"connection error: {exc.strerror or exc}"
    finally:
        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError, TimeoutError):
                pass

    return result
