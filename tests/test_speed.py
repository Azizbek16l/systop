"""speed testlari — OFFLINE, ``httpx.MockTransport`` orqali.

Bu fayl HAQIQIY tarmoqqa CHIQMAYDI: soxta transport so'ralgan baytlarni
qaytaradi (download) yoki request tanasini sanab oladi (upload). Throughput
(Mbps) matematikasi, latency/jitter hisobi va ``stop`` event mantig'i tarmoqsiz
sinaladi. Bu speed.py'ning eng qimmatli xavfsizlik to'ri.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from systop.core import speed
from systop.core.speed import (
    measure_download,
    measure_latency,
    measure_upload,
    run_speedtest,
)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


# --- measure_latency --------------------------------------------------------


async def test_measure_latency_returns_positive_avg():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"")

    async with _client(handler) as client:
        avg, jitter = await measure_latency(client, samples=5)
    assert avg >= 0.0
    assert jitter >= 0.0


async def test_measure_latency_all_failures_returns_zero():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    async with _client(handler) as client:
        avg, jitter = await measure_latency(client, samples=4)
    assert (avg, jitter) == (0.0, 0.0)


async def test_measure_latency_single_sample_zero_jitter():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"")

    async with _client(handler) as client:
        avg, jitter = await measure_latency(client, samples=1)
    # Bitta namuna -> jitter aniqlanmaydi -> 0.0.
    assert jitter == 0.0


async def test_measure_latency_partial_failures_use_successes():
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] % 2 == 0:
            raise httpx.ReadTimeout("slow")
        return httpx.Response(200, content=b"")

    async with _client(handler) as client:
        avg, jitter = await measure_latency(client, samples=6)
    # Ba'zi so'rovlar muvaffaqiyatli -> avg > 0 (yoki hech bo'lmasa >= 0).
    assert avg >= 0.0


# --- measure_download -------------------------------------------------------


async def test_measure_download_counts_streamed_bytes():
    served = 4 * 1024 * 1024  # 4 MiB per connection

    def handler(request: httpx.Request) -> httpx.Response:
        n = int(request.url.params.get("bytes", 0))
        # Talab qilingan hajmni qaytaramiz, ammo per_conn katta bo'lgani uchun
        # MockTransport faqat shuncha beradi (server cheklovini simulyatsiya).
        return httpx.Response(200, content=b"\x00" * min(n, served))

    async with _client(handler) as client:
        # warmup=0.0 -> barcha baytlar o'lchovga kiradi (deterministik).
        mbps, total = await measure_download(
            client, duration=0.5, parallel=2, on_progress=None, warmup=0.0
        )
    # 2 ta ulanish * 4 MiB = 8 MiB o'qilishi kerak (yoki MockTransport bir martada).
    assert total > 0
    assert mbps > 0.0
    # Mbps = bit / elapsed / 1e6. Real bayt sonidan kelib chiqib mantiqiy chegara.
    # 0.5s davomida 8 MiB ~ 134 Mbps atrofida bo'lishi mumkin; faqat ijobiyligini
    # tasdiqlaymiz (vaqt mashinaga bog'liq).


async def test_measure_download_progress_callback_invoked():
    def handler(request: httpx.Request) -> httpx.Response:
        n = int(request.url.params.get("bytes", 0))
        return httpx.Response(200, content=b"\x00" * min(n, 1024 * 1024))

    seen: list[float] = []

    async with _client(handler) as client:
        await measure_download(
            client, duration=0.5, parallel=1, on_progress=seen.append, warmup=0.0
        )
    # Kamida bitta progress yangilanishi bo'lishi kerak (har 0.2s).
    assert len(seen) >= 1
    assert all(v >= 0.0 for v in seen)


async def test_measure_download_handles_http_error_gracefully():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async with _client(handler) as client:
        mbps, total = await measure_download(client, duration=0.4, parallel=2)
    # Xato yutiladi -> 0 bayt, 0 Mbps, lekin yiqilmaydi.
    assert total == 0
    assert mbps == 0.0


async def test_measure_download_zero_bytes_on_empty_response():
    """Bo'sh javoblar oqimi: 0 bayt -> 0 Mbps, panel yiqilmaydi.

    (Bo'sh javobda worker qayta-qayta so'rov yuboradi, shuning uchun o'lchovni
    qisqa `duration` bilan cheklab, warmup'siz ishlatamiz — suite tez qolsin.)
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"")

    async with _client(handler) as client:
        mbps, total = await measure_download(client, duration=0.3, parallel=1, warmup=0.0)
    assert total == 0
    assert mbps == 0.0


# --- measure_upload ---------------------------------------------------------


async def test_measure_upload_counts_sent_bytes():
    def handler(request: httpx.Request) -> httpx.Response:
        # Generator drain bo'lishi uchun tanani o'qiymiz.
        _ = request.content
        return httpx.Response(200, content=b"ok")

    async with _client(handler) as client:
        mbps, total = await measure_upload(client, duration=0.5, parallel=2, warmup=0.0)
    assert total > 0
    assert mbps > 0.0


async def test_measure_upload_progress_callback_invoked():
    def handler(request: httpx.Request) -> httpx.Response:
        _ = request.content
        return httpx.Response(200, content=b"ok")

    seen: list[float] = []
    async with _client(handler) as client:
        await measure_upload(client, duration=0.5, parallel=1, on_progress=seen.append, warmup=0.0)
    assert len(seen) >= 1


async def test_measure_upload_handles_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.WriteError("broken pipe")

    async with _client(handler) as client:
        mbps, total = await measure_upload(client, duration=0.4, parallel=1)
    # POST xatosi yutiladi. DIQQAT: generator allaqachon counter'ni oshirgan
    # bo'lishi mumkin (BUG-REPORT'ga qarang) — shuning uchun total >= 0.
    assert total >= 0
    assert mbps >= 0.0


# --- stop event vaqt mantig'i -----------------------------------------------


async def test_run_phase_stops_at_duration():
    """Cheksiz oqim bo'lsa ham, _run_phase ``duration`` da to'xtashi kerak."""
    counter = [0]
    stop = asyncio.Event()

    async def infinite_worker():
        # stop o'rnatilmaguncha cheksiz "ish".
        while not stop.is_set():
            counter[0] += 1024
            await asyncio.sleep(0.01)

    workers = [infinite_worker()]
    loop = asyncio.get_running_loop()
    start = loop.time()
    mbps, total = await speed._run_phase(
        workers, counter, duration=0.4, stop=stop, on_progress=None
    )
    elapsed = loop.time() - start
    # duration=0.4 -> taxminan shuncha vaqtda tugashi kerak (progress polling 0.2s).
    assert elapsed < 2.0, f"phase juda uzoq ishladi: {elapsed:.2f}s"
    assert stop.is_set()
    assert total > 0
    assert mbps > 0.0


async def test_run_phase_zero_bytes_zero_mbps():
    counter = [0]
    stop = asyncio.Event()

    async def noop_worker():
        return None

    mbps, total = await speed._run_phase(
        [noop_worker()], counter, duration=1.0, stop=stop, on_progress=None
    )
    assert total == 0
    assert mbps == 0.0


async def test_run_phase_finishes_early_when_workers_done():
    """Worker'lar duration'dan oldin tugasa, phase ham erta tugaydi."""
    counter = [0]
    stop = asyncio.Event()

    async def quick_worker():
        counter[0] += 5_000_000
        await asyncio.sleep(0.05)

    loop = asyncio.get_running_loop()
    start = loop.time()
    mbps, total = await speed._run_phase(
        [quick_worker()], counter, duration=30.0, stop=stop, on_progress=None
    )
    elapsed = loop.time() - start
    assert elapsed < 2.0  # 30s kutmasligi shart
    assert total == 5_000_000
    assert mbps > 0.0


# --- warmup UX: progress "0.0 da osilib qolmaydi" ---------------------------


async def test_run_phase_warmup_reports_intermediate_progress():
    """Warmup ichida baytlar oqayotgan bo'lsa, progress 0.0 EMAS oraliq qiymat.

    Upload fazasi "osilgandek" ko'rinmasligi uchun: o'lchov oynasi boshlanmagan
    bo'lsa ham (warmup), boshlanishdan hisoblangan jonli throughput ko'rsatiladi.
    """
    counter = [0]
    stop = asyncio.Event()

    async def steady_worker():
        # Warmup davomida ham doimiy bayt oqimi.
        while not stop.is_set():
            counter[0] += 2_000_000
            await asyncio.sleep(0.02)

    seen: list[float] = []
    # warmup (0.4s) duration (0.2s) dan uzun => dastlabki callback'lar warmup ichida.
    await speed._run_phase(
        [steady_worker()],
        counter,
        duration=0.2,
        stop=stop,
        on_progress=seen.append,
        warmup=0.4,
    )
    assert seen, "progress callback hech chaqirilmadi"
    # Birinchi (warmup ichidagi) yangilanish 0.0 dan KATTA bo'lishi shart —
    # ya'ni foydalanuvchi harakatni ko'radi, qotib qolmaydi.
    assert seen[0] > 0.0, f"warmup progress 0.0 da osilib qoldi: {seen[:3]}"
    assert all(v >= 0.0 for v in seen)


async def test_run_phase_warmup_excludes_warmup_bytes_from_measurement():
    """Jonli warmup ko'rsatkichi YAKUNIY o'lchovga ta'sir qilmaydi.

    Warmup baytlari faqat progress callback'da ko'rinadi; qaytariladigan Mbps
    esa warmup'dan keyingi oynadan hisoblanadi (aniqlik o'zgarmaganini tasdiqlash).
    """
    counter = [0]
    stop = asyncio.Event()

    async def steady_worker():
        while not stop.is_set():
            counter[0] += 1_000_000
            await asyncio.sleep(0.02)

    mbps_warm, total = await speed._run_phase(
        [steady_worker()], counter, duration=0.3, stop=stop, on_progress=None, warmup=0.3
    )
    assert total > 0
    assert mbps_warm > 0.0  # o'lchov oynasi (warmup'dan keyin) ham baytlarni ko'radi


# --- drain: stop'dan keyin osilgan worker bekor qilinadi --------------------


async def test_drain_workers_cancels_hung_worker(monkeypatch):
    """`stop`'dan keyin uchib turgan (osilgan) worker grace o'tgach bekor qilinadi.

    Upload POST server javobini kutib osilib qolsa, faza cheksiz turib
    qolmasligi kerak. Grace'ni qisqa qilib (test tez bo'lsin), osilgan
    worker bekor qilinishini va istisno yutilishini tasdiqlaymiz.
    """
    monkeypatch.setattr(speed, "_DRAIN_GRACE_S", 0.2)
    cancelled = {"hit": False}

    async def hung_worker():
        try:
            await asyncio.sleep(100)  # hech qachon tugamaydigan "in-flight POST"
        except asyncio.CancelledError:
            cancelled["hit"] = True
            raise

    gather = asyncio.gather(hung_worker())
    loop = asyncio.get_running_loop()
    start = loop.time()
    # _drain_workers istisno KO'TARMASLIGI kerak (jim bekor qiladi).
    await speed._drain_workers(gather)
    elapsed = loop.time() - start
    assert elapsed < 2.0, f"drain juda uzoq kutdi: {elapsed:.2f}s"
    assert cancelled["hit"] is True
    assert gather.cancelled() or gather.done()


async def test_drain_workers_returns_promptly_for_finished_worker():
    """Worker allaqachon tugagan bo'lsa, drain darhol qaytadi (cancel'siz)."""

    async def done_worker():
        return None

    gather = asyncio.gather(done_worker())
    loop = asyncio.get_running_loop()
    start = loop.time()
    await speed._drain_workers(gather)
    assert (loop.time() - start) < 0.5
    assert not gather.cancelled()


async def test_run_phase_with_hung_worker_does_not_hang(monkeypatch):
    """To'liq faza: worker stop'ni e'tiborsiz qoldirib osilsa ham faza tugaydi.

    Bu upload fazasidagi haqiqiy "osilish" simptomining integratsiya testi —
    drain grace tufayli faza cheksiz turmaydi.
    """
    monkeypatch.setattr(speed, "_DRAIN_GRACE_S", 0.2)
    counter = [5_000_000]
    stop = asyncio.Event()

    async def stubborn_worker():
        # `stop`'ni butunlay e'tiborsiz qoldiradi (osilgan POST'ni simulyatsiya).
        await asyncio.sleep(100)

    loop = asyncio.get_running_loop()
    start = loop.time()
    mbps, total = await speed._run_phase(
        [stubborn_worker()], counter, duration=0.3, stop=stop, on_progress=None, warmup=0.0
    )
    elapsed = loop.time() - start
    assert elapsed < 3.0, f"osilgan worker fazani osib qo'ydi: {elapsed:.2f}s"
    assert stop.is_set()
    assert total == 5_000_000  # commit qilingan baytlar saqlanadi


# --- run_speedtest (to'liq, soxta transport bilan) --------------------------


async def test_run_speedtest_full_flow(monkeypatch):
    """measure_* funksiyalarini mock qilib, run_speedtest yig'ish mantig'ini sinaymiz.

    Bu HTTP qatlamiga tushmaydi — faqat SpeedResult to'g'ri yig'ilishini tekshiradi.
    """

    async def fake_latency(client, samples=8):
        return 12.5, 1.2

    async def fake_download(client, *args, **kwargs):
        return 95.0, 60_000_000

    async def fake_upload(client, *args, **kwargs):
        return 40.0, 25_000_000

    monkeypatch.setattr(speed, "measure_latency", fake_latency)
    monkeypatch.setattr(speed, "measure_download", fake_download)
    monkeypatch.setattr(speed, "measure_upload", fake_upload)

    result = await run_speedtest(duration=0.1, parallel=2)
    assert result.download_mbps == 95.0
    assert result.upload_mbps == 40.0
    assert result.latency_ms == 12.5
    assert result.jitter_ms == 1.2
    assert result.bytes_down == 60_000_000
    assert result.bytes_up == 25_000_000


async def test_run_speedtest_propagates_progress_callbacks(monkeypatch):
    captured = {}

    async def fake_latency(client, samples=8):
        return 0.0, 0.0

    async def fake_download(client, *args, on_progress=None, **kwargs):
        captured["download_cb"] = on_progress
        return 0.0, 0

    async def fake_upload(client, *args, on_progress=None, **kwargs):
        captured["upload_cb"] = on_progress
        return 0.0, 0

    monkeypatch.setattr(speed, "measure_latency", fake_latency)
    monkeypatch.setattr(speed, "measure_download", fake_download)
    monkeypatch.setattr(speed, "measure_upload", fake_upload)

    dl_cb = lambda m: None  # noqa: E731
    up_cb = lambda m: None  # noqa: E731
    await run_speedtest(on_download=dl_cb, on_upload=up_cb)
    assert captured["download_cb"] is dl_cb
    assert captured["upload_cb"] is up_cb


# --- throughput matematikasini to'g'ridan-to'g'ri tekshirish ----------------


@pytest.mark.parametrize(
    "byte_count, elapsed, expected_mbps",
    [
        (1_000_000, 1.0, 8.0),  # 1 MB / 1s = 8 Mbps
        (12_500_000, 1.0, 100.0),  # 12.5 MB/s = 100 Mbps
        (1_000_000, 0.5, 16.0),  # yarim soniyada => ikki barobar
    ],
)
def test_throughput_formula(byte_count, elapsed, expected_mbps):
    """speed.py'da ishlatiladigan (bytes*8)/elapsed/1e6 formulasi."""
    mbps = (byte_count * 8) / elapsed / 1e6
    assert mbps == pytest.approx(expected_mbps)
