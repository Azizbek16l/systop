"""Internet bandwidth o'lchovi — Cloudflare speed test endpointlari orqali.

`speedtest-cli` eskirgan; uning o'rniga Cloudflare'ning ochiq endpointlaridan
foydalanamiz:
    download: GET  https://speed.cloudflare.com/__down?bytes=N
    upload:   POST https://speed.cloudflare.com/__up   (tana = N bayt)

O'lchov vaqt bilan chegaralangan (duration soniya): bir nechta parallel
ulanish ochib, shu vaqt ichida o'tgan baytlarni hisoblaymiz va Mbps chiqaramiz.
Har bir bosqich `on_progress(mbps)` callback orqali jonli yangilanadi.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

import httpx

DOWN_URL = "https://speed.cloudflare.com/__down"
UP_URL = "https://speed.cloudflare.com/__up"

# Cloudflare `__down` endpointi bitta so'rovda ~100 MB dan ortig'iga 403 qaytaradi.
# Shuning uchun har bir worker `stop` o'rnatilguncha shu hajmda qayta-qayta
# so'rov yuboradi (vaqt bilan chegaralangan o'lchov shu yo'l bilan saqlanadi).
DOWN_CHUNK_BYTES = 50 * 1024 * 1024  # 50 MB — limitdan past, xavfsiz
UP_CHUNK_BYTES = 25 * 1024 * 1024  # 25 MB — bitta POST tanasi

ProgressCb = Callable[[float], None] | None


@dataclass(slots=True)
class SpeedResult:
    """Tezlik testi natijasi."""

    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    bytes_down: int = 0
    bytes_up: int = 0


async def measure_latency(client: httpx.AsyncClient, samples: int = 8) -> tuple[float, float]:
    """Bo'sh (0 bayt) so'rovlar orqali latency va jitter (ms) o'lchaydi."""
    times: list[float] = []
    for _ in range(samples):
        start = time.perf_counter()
        try:
            resp = await client.get(DOWN_URL, params={"bytes": 0})
            resp.read()
            times.append((time.perf_counter() - start) * 1000.0)
        except httpx.HTTPError:
            continue
    if not times:
        return 0.0, 0.0
    avg = sum(times) / len(times)
    jitter = (sum(abs(t - avg) for t in times) / len(times)) if len(times) > 1 else 0.0
    return avg, jitter


async def _download_stream(
    client: httpx.AsyncClient, size: int, counter: list[int], stop: asyncio.Event
) -> None:
    # `size` — har bir so'rov hajmi (endpoint limitidan past). `stop` o'rnatilguncha
    # qayta-qayta so'rov yuboramiz; shunday qilib o'lchov vaqt bilan cheklanadi.
    try:
        while not stop.is_set():
            async with client.stream("GET", DOWN_URL, params={"bytes": size}) as resp:
                if resp.status_code != 200:
                    # Limitga urilsa yoki xato bo'lsa — qayta urinmaymiz.
                    await resp.aread()
                    return
                async for chunk in resp.aiter_bytes():
                    counter[0] += len(chunk)
                    if stop.is_set():
                        break
            # Har so'rovdan keyin event loop'ga nazoratni qaytaramiz — darhol
            # javob beruvchi transport (masalan test mock'i) monitor coroutine'ni
            # och qoldirib, `stop` o'rnatilmasligining oldini olamiz.
            await asyncio.sleep(0)
    except httpx.HTTPError:
        pass


async def _upload_gen(
    chunk: bytes, max_bytes: int, sent_box: list[int], stop: asyncio.Event
) -> AsyncIterator[bytes]:
    # Bu generator faqat httpx tarmoqqa yozish UCHUN so'ragan baytlarni ishlab
    # beradi. Yield'dan keyin `sent_box[0]` ni oshiramiz — chunk httpx'ga
    # uzatildi (ya'ni transport buferiga yozildi). Lekin BU hisoblagich umumiy
    # `counter` EMAS: agar POST yarmida uzilsa, yuborilmagan baytlar umumiy
    # o'lchovga kirmasligi uchun commit faqat POST muvaffaqiyatli tugaganda
    # (`_upload_stream`da) bo'ladi.
    sent = 0
    while sent < max_bytes and not stop.is_set():
        yield chunk
        sent += len(chunk)
        sent_box[0] = sent


async def _upload_stream(
    client: httpx.AsyncClient,
    chunk: bytes,
    max_bytes: int,
    counter: list[int],
    stop: asyncio.Event,
) -> None:
    # `stop` o'rnatilguncha qayta-qayta POST yuboramiz — tez kanallarda bitta
    # POST tugab qolmasligi va o'lchov to'liq vaqt davom etishi uchun.
    #
    # BUG TUZATILDI: ilgari baytlar generator ichida to'g'ridan-to'g'ri umumiy
    # `counter`ga qo'shilardi — POST xato bo'lsa (yoki uzilsa) tarmoqqa
    # yetmagan baytlar ham sanalib, Mbps shishardi. Endi har POST uchun
    # alohida `sent_box`da hisoblanadi va faqat POST MUVAFFAQIYATLI tugagach
    # umumiy `counter`ga commit qilinadi (xatoda rollback — hech narsa
    # qo'shilmaydi). Shunday qilib faqat haqiqatan yuborilgan baytlar o'lchanadi.
    try:
        while not stop.is_set():
            sent_box = [0]
            try:
                await client.post(UP_URL, content=_upload_gen(chunk, max_bytes, sent_box, stop))
            except httpx.HTTPError:
                # POST uzildi — bu so'rovning baytlari ishonchsiz, hisoblamaymiz.
                break
            # Faqat to'liq, muvaffaqiyatli POST baytlarini commit qilamiz.
            counter[0] += sent_box[0]
            await asyncio.sleep(0)  # event loop'ga nafas (starvation oldini olish)
    except httpx.HTTPError:
        pass


async def _run_phase(
    workers: list,
    counter: list[int],
    duration: float,
    stop: asyncio.Event,
    on_progress: ProgressCb,
    warmup: float = 0.0,
) -> tuple[float, int]:
    """Berilgan worker'larni `duration` soniya davomida ishlatib, Mbps qaytaradi.

    `stop` — worker'lar kuzatadigan event; vaqt tugaganda o'rnatamiz.
    `warmup` — boshlang'ich ramp-up soniyalari: shu vaqtgacha o'tgan baytlar
    o'lchovga kirmaydi (TCP slow-start tufayli past tezlik o'rtachani buzmasin).
    O'lchov oynasi warmup'dan keyin boshlanadi va `duration` soniya davom etadi.
    """
    start = time.perf_counter()
    base_bytes = 0  # warmup oxiridagi bayt hisoblagichi
    base_time = start  # o'lchov oynasi boshlangan vaqt
    warmed = warmup <= 0.0
    gather = asyncio.gather(*workers)
    try:
        while True:
            await asyncio.sleep(0.2)
            now = time.perf_counter()
            elapsed = now - start
            if not warmed and elapsed >= warmup:
                # Warmup tugadi — o'lchov oynasini shu nuqtadan boshlaymiz.
                base_bytes = counter[0]
                base_time = now
                warmed = True
            window = now - base_time
            measured_bytes = counter[0] - base_bytes
            mbps = (measured_bytes * 8) / window / 1e6 if window > 0 and warmed else 0.0
            if on_progress:
                on_progress(mbps)
            if elapsed >= warmup + duration or gather.done():
                stop.set()
                break
    finally:
        await gather
    if not warmed:
        # Worker'lar warmup tugashidan oldin yakunlandi — hammasini hisoblaymiz.
        base_bytes = 0
        base_time = start
    window = max(time.perf_counter() - base_time, 1e-6)
    measured = counter[0] - base_bytes
    return (measured * 8) / window / 1e6, counter[0]


async def measure_download(
    client: httpx.AsyncClient,
    duration: float = 5.0,
    parallel: int = 4,
    on_progress: ProgressCb = None,
    warmup: float = 1.0,
) -> tuple[float, int]:
    """Download tezligini (Mbps) o'lchaydi. Qaytaradi: (mbps, baytlar)."""
    counter = [0]
    stop = asyncio.Event()
    workers = [_download_stream(client, DOWN_CHUNK_BYTES, counter, stop) for _ in range(parallel)]
    return await _run_phase(workers, counter, duration, stop, on_progress, warmup=warmup)


async def measure_upload(
    client: httpx.AsyncClient,
    duration: float = 5.0,
    parallel: int = 4,
    on_progress: ProgressCb = None,
    warmup: float = 1.0,
) -> tuple[float, int]:
    """Upload tezligini (Mbps) o'lchaydi. Qaytaradi: (mbps, baytlar)."""
    counter = [0]
    chunk = b"\x00" * (64 * 1024)
    stop = asyncio.Event()
    workers = [
        _upload_stream(client, chunk, UP_CHUNK_BYTES, counter, stop) for _ in range(parallel)
    ]
    return await _run_phase(workers, counter, duration, stop, on_progress, warmup=warmup)


async def run_speedtest(
    duration: float = 5.0,
    parallel: int = 4,
    on_download: ProgressCb = None,
    on_upload: ProgressCb = None,
    warmup: float = 1.0,
) -> SpeedResult:
    """To'liq tezlik testi: latency -> download -> upload.

    `warmup` — har bir bosqichda TCP slow-start davridagi baytlarni o'lchovga
    kiritmaslik uchun boshlang'ich soniyalar (aniqroq Mbps).
    """
    limits = httpx.Limits(max_connections=parallel * 2)
    async with httpx.AsyncClient(http2=False, timeout=30.0, limits=limits) as client:
        latency, jitter = await measure_latency(client)
        down_mbps, bytes_down = await measure_download(
            client, duration=duration, parallel=parallel, on_progress=on_download, warmup=warmup
        )
        up_mbps, bytes_up = await measure_upload(
            client, duration=duration, parallel=parallel, on_progress=on_upload, warmup=warmup
        )
    return SpeedResult(
        download_mbps=down_mbps,
        upload_mbps=up_mbps,
        latency_ms=latency,
        jitter_ms=jitter,
        bytes_down=bytes_down,
        bytes_up=bytes_up,
    )
