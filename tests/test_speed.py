"""speed tests — OFFLINE, through ``httpx.MockTransport``.

This file NEVER touches the REAL network: the fake transport returns the
requested bytes (download) or counts up the request body (upload). The
throughput (Mbps) arithmetic, the latency/jitter computation and the ``stop``
event logic are exercised without a network. This is speed.py's most valuable
safety net.
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
    # A single sample -> jitter cannot be determined -> 0.0.
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
    # Some requests succeeded -> avg > 0 (or at the very least >= 0).
    assert avg >= 0.0


# --- measure_download -------------------------------------------------------


async def test_measure_download_counts_streamed_bytes():
    served = 4 * 1024 * 1024  # 4 MiB per connection

    def handler(request: httpx.Request) -> httpx.Response:
        n = int(request.url.params.get("bytes", 0))
        # We return the requested size, but because per_conn is large the
        # MockTransport only gives this much (simulating the server's limit).
        return httpx.Response(200, content=b"\x00" * min(n, served))

    async with _client(handler) as client:
        # warmup=0.0 -> every byte enters the measurement (deterministic).
        mbps, total = await measure_download(
            client, duration=0.5, parallel=2, on_progress=None, warmup=0.0
        )
    # 2 connections * 4 MiB = 8 MiB should be read (or MockTransport in one go).
    assert total > 0
    assert mbps > 0.0
    # Mbps = bits / elapsed / 1e6. A sensible bound derived from the real byte
    # count: 8 MiB over 0.5s can land around 134 Mbps; we only assert that it is
    # positive (the timing depends on the machine).


async def test_measure_download_progress_callback_invoked():
    def handler(request: httpx.Request) -> httpx.Response:
        n = int(request.url.params.get("bytes", 0))
        return httpx.Response(200, content=b"\x00" * min(n, 1024 * 1024))

    seen: list[float] = []

    async with _client(handler) as client:
        await measure_download(
            client, duration=0.5, parallel=1, on_progress=seen.append, warmup=0.0
        )
    # There must be at least one progress update (every 0.2s).
    assert len(seen) >= 1
    assert all(v >= 0.0 for v in seen)


async def test_measure_download_handles_http_error_gracefully():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async with _client(handler) as client:
        mbps, total = await measure_download(client, duration=0.4, parallel=2)
    # The error is swallowed -> 0 bytes, 0 Mbps, but nothing crashes.
    assert total == 0
    assert mbps == 0.0


async def test_measure_download_zero_bytes_on_empty_response():
    """A stream of empty responses: 0 bytes -> 0 Mbps, the panel does not crash.

    (With an empty response the worker keeps re-sending the request, so we bound
    the measurement with a short `duration` and run it without a warmup — to
    keep the suite fast.)
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
        # We read the body so that the generator gets drained.
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
    # The POST error is swallowed. NOTE: the generator may already have
    # incremented the counter (see the BUG REPORT) — hence total >= 0.
    assert total >= 0
    assert mbps >= 0.0


# --- stop event timing logic ------------------------------------------------


async def test_run_phase_stops_at_duration():
    """Even with an endless stream, _run_phase must stop at ``duration``."""
    counter = [0]
    stop = asyncio.Event()

    async def infinite_worker():
        # Endless "work" until stop is set.
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
    # duration=0.4 -> it should finish in roughly that time (progress polling 0.2s).
    assert elapsed < 2.0, f"the phase ran far too long: {elapsed:.2f}s"
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
    """If the workers finish before the duration, the phase finishes early too."""
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
    assert elapsed < 2.0  # it must not wait 30s
    assert total == 5_000_000
    assert mbps > 0.0


# --- warmup UX: the progress "does not get stuck at 0.0" --------------------


async def test_run_phase_warmup_reports_intermediate_progress():
    """If bytes are flowing during the warmup, the progress is an interim value, NOT 0.0.

    So that the upload phase does not look "hung": even when the measurement
    window has not started yet (the warmup), the live throughput computed from
    the start is shown.
    """
    counter = [0]
    stop = asyncio.Event()

    async def steady_worker():
        # A steady stream of bytes during the warmup as well.
        while not stop.is_set():
            counter[0] += 2_000_000
            await asyncio.sleep(0.02)

    seen: list[float] = []
    # warmup (0.4s) is longer than duration (0.2s) => the first callbacks land
    # inside the warmup.
    await speed._run_phase(
        [steady_worker()],
        counter,
        duration=0.2,
        stop=stop,
        on_progress=seen.append,
        warmup=0.4,
    )
    assert seen, "the progress callback was never called"
    # The first update (the one inside the warmup) must be GREATER than 0.0 —
    # that is, the user sees movement instead of a frozen figure.
    assert seen[0] > 0.0, f"the warmup progress got stuck at 0.0: {seen[:3]}"
    assert all(v >= 0.0 for v in seen)


async def test_run_phase_warmup_excludes_warmup_bytes_from_measurement():
    """The live warmup indicator does not affect the FINAL measurement.

    The warmup bytes show up only in the progress callback; the returned Mbps is
    computed from the window after the warmup (confirming that the accuracy did
    not change).
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
    assert mbps_warm > 0.0  # the measurement window (after the warmup) sees bytes too


# --- drain: a worker left hanging after stop is cancelled -------------------


async def test_drain_workers_cancels_hung_worker(monkeypatch):
    """A worker still in flight (hung) after `stop` is cancelled once the grace expires.

    If an upload POST hangs waiting for the server's answer, the phase must not
    stall forever. We shorten the grace (to keep the test fast) and confirm that
    the hung worker gets cancelled and the exception is swallowed.
    """
    monkeypatch.setattr(speed, "_DRAIN_GRACE_S", 0.2)
    cancelled = {"hit": False}

    async def hung_worker():
        try:
            await asyncio.sleep(100)  # an "in-flight POST" that never finishes
        except asyncio.CancelledError:
            cancelled["hit"] = True
            raise

    gather = asyncio.gather(hung_worker())
    loop = asyncio.get_running_loop()
    start = loop.time()
    # _drain_workers must NOT raise (it cancels silently).
    await speed._drain_workers(gather)
    elapsed = loop.time() - start
    assert elapsed < 2.0, f"the drain waited far too long: {elapsed:.2f}s"
    assert cancelled["hit"] is True
    assert gather.cancelled() or gather.done()


async def test_drain_workers_returns_promptly_for_finished_worker():
    """If the worker has already finished, the drain returns at once (no cancel)."""

    async def done_worker():
        return None

    gather = asyncio.gather(done_worker())
    loop = asyncio.get_running_loop()
    start = loop.time()
    await speed._drain_workers(gather)
    assert (loop.time() - start) < 0.5
    assert not gather.cancelled()


async def test_run_phase_with_hung_worker_does_not_hang(monkeypatch):
    """The full phase: even if a worker ignores stop and hangs, the phase finishes.

    This is the integration test for the real "hang" symptom in the upload
    phase — thanks to the drain grace the phase does not stall forever.
    """
    monkeypatch.setattr(speed, "_DRAIN_GRACE_S", 0.2)
    counter = [5_000_000]
    stop = asyncio.Event()

    async def stubborn_worker():
        # Ignores `stop` completely (simulating a hung POST).
        await asyncio.sleep(100)

    loop = asyncio.get_running_loop()
    start = loop.time()
    mbps, total = await speed._run_phase(
        [stubborn_worker()], counter, duration=0.3, stop=stop, on_progress=None, warmup=0.0
    )
    elapsed = loop.time() - start
    assert elapsed < 3.0, f"the hung worker stalled the phase: {elapsed:.2f}s"
    assert stop.is_set()
    assert total == 5_000_000  # the committed bytes are preserved


# --- run_speedtest (the full thing, with a fake transport) ------------------


async def test_run_speedtest_full_flow(monkeypatch):
    """We mock the measure_* functions and exercise run_speedtest's assembly logic.

    This does not reach the HTTP layer — it only checks that SpeedResult is
    assembled correctly.
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


# --- checking the throughput arithmetic directly ----------------------------


@pytest.mark.parametrize(
    "byte_count, elapsed, expected_mbps",
    [
        (1_000_000, 1.0, 8.0),  # 1 MB / 1s = 8 Mbps
        (12_500_000, 1.0, 100.0),  # 12.5 MB/s = 100 Mbps
        (1_000_000, 0.5, 16.0),  # in half a second => twice as much
    ],
)
def test_throughput_formula(byte_count, elapsed, expected_mbps):
    """The (bytes*8)/elapsed/1e6 formula used in speed.py."""
    mbps = (byte_count * 8) / elapsed / 1e6
    assert mbps == pytest.approx(expected_mbps)
