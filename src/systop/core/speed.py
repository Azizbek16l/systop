"""Internet bandwidth measurement — through the Cloudflare speed test endpoints.

`speedtest-cli` is outdated; instead of it we use Cloudflare's public endpoints:
    download: GET  https://speed.cloudflare.com/__down?bytes=N
    upload:   POST https://speed.cloudflare.com/__up   (body = N bytes)

The measurement is time-bounded (duration in seconds): we open several parallel
connections, count the bytes that passed within that time and derive Mbps. Every
phase is updated live through the `on_progress(mbps)` callback.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field

import httpx

DOWN_URL = "https://speed.cloudflare.com/__down"
UP_URL = "https://speed.cloudflare.com/__up"

# The Cloudflare `__down` endpoint returns 403 for more than ~100 MB in a single
# request. That is why every worker keeps sending requests of this size over and
# over until `stop` is set (this is how the time-bounded measurement is kept).
DOWN_CHUNK_BYTES = 50 * 1024 * 1024  # 50 MB — below the limit, safe
UP_CHUNK_BYTES = 25 * 1024 * 1024  # 25 MB — a single POST body

ProgressCb = Callable[[float], None] | None


@dataclass(slots=True)
class SpeedResult:
    """The result of the speed test."""

    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    bytes_down: int = 0
    bytes_up: int = 0


async def measure_latency(client: httpx.AsyncClient, samples: int = 8) -> tuple[float, float]:
    """Measures latency and jitter (ms) through empty (0 byte) requests."""
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
    # `size` — the size of each request (below the endpoint limit). We keep
    # sending requests until `stop` is set; that is how the measurement stays
    # bounded by time.
    try:
        while not stop.is_set():
            async with client.stream("GET", DOWN_URL, params={"bytes": size}) as resp:
                if resp.status_code != 200:
                    # If we hit the limit or something failed — do not retry.
                    await resp.aread()
                    return
                async for chunk in resp.aiter_bytes():
                    counter[0] += len(chunk)
                    if stop.is_set():
                        break
            # Hand control back to the event loop after every request — this
            # prevents a transport that answers instantly (a test mock, for
            # example) from starving the monitor coroutine so that `stop` is
            # never set.
            await asyncio.sleep(0)
    except httpx.HTTPError:
        pass


async def _upload_gen(
    chunk: bytes, max_bytes: int, sent_box: list[int], stop: asyncio.Event
) -> AsyncIterator[bytes]:
    # This generator only produces the bytes that httpx asked FOR writing to the
    # network. After the yield we increment `sent_box[0]` — the chunk was handed
    # to httpx (that is, written into the transport buffer). But THIS counter is
    # NOT the shared `counter`: so that bytes which were never sent do not enter
    # the overall measurement if the POST breaks half way, the commit happens
    # only once the POST has finished successfully (in `_upload_stream`).
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
    # We keep sending POSTs until `stop` is set — so that on fast links a single
    # POST does not run out and the measurement lasts the full duration.
    #
    # BUG FIXED: previously the bytes were added straight into the shared
    # `counter` inside the generator — if the POST failed (or broke) the bytes
    # that never reached the network were counted too and the Mbps was inflated.
    # Now they are counted per POST in a separate `sent_box` and are committed to
    # the shared `counter` only once the POST has finished SUCCESSFULLY (on an
    # error it rolls back — nothing is added). That way only the bytes really
    # sent are measured.
    try:
        while not stop.is_set():
            sent_box = [0]
            try:
                await client.post(UP_URL, content=_upload_gen(chunk, max_bytes, sent_box, stop))
            except httpx.HTTPError:
                # The POST broke — this request's bytes are unreliable, do not count them.
                break
            # Commit only the bytes of a complete, successful POST.
            counter[0] += sent_box[0]
            await asyncio.sleep(0)  # a breath for the event loop (avoid starvation)
    except httpx.HTTPError:
        pass


# How long to wait for an in-flight request after `stop` has been set.
# In the upload phase, if the server was slow to answer, a POST could stay stuck
# even after `stop` (which looked to the user like a "hang"). Once this grace
# expires the in-flight workers are cancelled — the result (the committed bytes)
# does not change, only the hang stops. Because a mock transport answers
# instantly, this path is never taken in the tests.
_DRAIN_GRACE_S = 3.0


async def _run_phase(
    workers: list,
    counter: list[int],
    duration: float,
    stop: asyncio.Event,
    on_progress: ProgressCb,
    warmup: float = 0.0,
) -> tuple[float, int]:
    """Runs the given workers for `duration` seconds and returns the Mbps.

    `stop` — the event the workers watch; we set it when the time is up.
    `warmup` — the initial ramp-up seconds: the bytes that pass before then do
    not enter the measurement (so that the low speed caused by TCP slow-start
    does not spoil the average). The measurement window starts after the warmup
    and lasts `duration` seconds.

    `on_progress` receives a LIVE value during the warmup as well (the interim
    throughput computed from the start time) — so that the upload phase does not
    look like it is "stuck at 0.0". The Mbps that enters the measurement (the
    returned one) is however computed only from the window after the warmup —
    the accuracy is unchanged.
    """
    start = time.perf_counter()
    base_bytes = 0  # the byte counter at the end of the warmup
    base_time = start  # the time the measurement window started
    warmed = warmup <= 0.0
    gather = asyncio.gather(*workers)
    try:
        while True:
            await asyncio.sleep(0.2)
            now = time.perf_counter()
            elapsed = now - start
            if not warmed and elapsed >= warmup:
                # The warmup is over — we start the measurement window here.
                base_bytes = counter[0]
                base_time = now
                warmed = True
            if warmed:
                window = now - base_time
                measured_bytes = counter[0] - base_bytes
                mbps = (measured_bytes * 8) / window / 1e6 if window > 0 else 0.0
            else:
                # Inside the warmup — we show the interim throughput from the
                # start so that the UI keeps moving (instead of freezing at
                # 0.0). This value does not enter the FINAL measurement, it is
                # only a live indicator.
                warm_window = now - start
                mbps = (counter[0] * 8) / warm_window / 1e6 if warm_window > 0 else 0.0
            if on_progress:
                on_progress(mbps)
            if elapsed >= warmup + duration or gather.done():
                stop.set()
                break
    finally:
        await _drain_workers(gather)
    if not warmed:
        # The workers finished before the warmup was over — we count everything.
        base_bytes = 0
        base_time = start
    window = max(time.perf_counter() - base_time, 1e-6)
    measured = counter[0] - base_bytes
    return (measured * 8) / window / 1e6, counter[0]


async def _drain_workers(gather: asyncio.Future) -> None:
    """Waits for the workers still in flight after `stop`; cancels them if they hang.

    Normally the workers see `stop` and finish immediately (`gather` completes
    at once). But if an upload POST is waiting for the server's answer it can
    hang for longer than `_DRAIN_GRACE_S` — after that deadline `gather` is
    cancelled (the result is not spoiled, because the bytes of an in-flight POST
    have not been committed to `counter` yet). After the cancellation we swallow
    the `CancelledError` — the caller can finish the phase accounting in peace.
    """
    try:
        await asyncio.wait_for(gather, timeout=_DRAIN_GRACE_S)
    except TimeoutError:
        gather.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await gather
    except asyncio.CancelledError:
        # Cancelled from outside (the whole speedtest was cancelled, say) — we
        # cancel `gather` as well and re-raise (to preserve cancel semantics).
        gather.cancel()
        with contextlib.suppress(Exception):
            await gather
        raise


async def measure_download(
    client: httpx.AsyncClient,
    duration: float = 5.0,
    parallel: int = 4,
    on_progress: ProgressCb = None,
    warmup: float = 1.0,
) -> tuple[float, int]:
    """Measures the download speed (Mbps). Returns: (mbps, bytes)."""
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
    """Measures the upload speed (Mbps). Returns: (mbps, bytes)."""
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
    """The full speed test: latency -> download -> upload.

    `warmup` — the initial seconds of each phase, so that the bytes from the TCP
    slow-start period are kept out of the measurement (a more accurate Mbps).
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


# ===========================================================================
# Local (IX) vs international speed
# ===========================================================================
#
# Why this is needed: in many countries the ISP prices and rate-limits traffic
# inside the LOCAL exchange point (IX) completely differently from
# international traffic — TAS-IX in Uzbekistan, KazIX in Kazakhstan, MSK-IX in
# Russia and so on. The result is that the user gets the full local speed while
# the international one is throttled.
#
# When someone complains that "the internet is slow" you cannot draw any
# conclusion without seeing that difference: if local is 100 Mbps and
# international is 8 Mbps — that is NOT a fault, that is the plan. If on the
# other hand both are low — that is a real problem.
#
# The endpoint is NOT HARD-CODED: every country supplies its own in the config
# (`speed_local_urls`). That way the same code works everywhere.


@dataclass(slots=True)
class LocalSpeedResult:
    """The measurement for a single local endpoint."""

    url: str
    ok: bool = False
    mbps: float = 0.0
    latency_ms: float = 0.0
    bytes_read: int = 0
    error: str | None = None


@dataclass(slots=True)
class SpeedComparison:
    """A comparison of the local and the international speed."""

    international_mbps: float = 0.0
    local: list[LocalSpeedResult] = field(default_factory=list)

    @property
    def best_local_mbps(self) -> float:
        vals = [r.mbps for r in self.local if r.ok]
        return max(vals) if vals else 0.0

    @property
    def ratio(self) -> float | None:
        """The local / international ratio. None if international is 0."""
        if self.international_mbps <= 0:
            return None
        return self.best_local_mbps / self.international_mbps

    @property
    def is_throttled_international(self) -> bool:
        """If local is noticeably faster than international — the international link is throttled.

        The threshold is 3x: the natural difference (distance, peering) does not
        usually exceed 2x, and 3x or more is a sign of the plan/shaping.
        """
        r = self.ratio
        return r is not None and r >= 3.0


async def measure_local(
    urls: list[str],
    duration: float = 5.0,
    timeout: float = 10.0,
) -> list[LocalSpeedResult]:
    """Downloads from the given local endpoints and measures the throughput.

    Every URL should be a large file (>= 10 MB recommended). The download is
    stopped after `duration` seconds — there is no need to fetch the whole file,
    only to measure the steady speed.

    Raises no exception: every endpoint is independent, and if one fails the
    rest carry on.
    """
    results: list[LocalSpeedResult] = []
    for url in urls:
        res = LocalSpeedResult(url=url)
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                start = time.perf_counter()
                async with client.stream("GET", url) as resp:
                    res.latency_ms = (time.perf_counter() - start) * 1000.0
                    if resp.status_code >= 400:
                        res.error = f"HTTP {resp.status_code}"
                        results.append(res)
                        continue
                    t0 = time.perf_counter()
                    total = 0
                    async for chunk in resp.aiter_bytes(65536):
                        total += len(chunk)
                        if time.perf_counter() - t0 >= duration:
                            break
                    elapsed = max(time.perf_counter() - t0, 1e-6)
            res.bytes_read = total
            res.mbps = (total * 8) / elapsed / 1e6
            res.ok = total > 0
            if not res.ok:
                res.error = "no data received"
        except httpx.HTTPError as exc:
            res.error = f"request error: {type(exc).__name__}"
        except (OSError, ValueError) as exc:
            res.error = f"connection error: {type(exc).__name__}"
        results.append(res)
    return results
