"""bandwidth testlari — OFFLINE.

``_compute_rates`` delta matematikasi (bytes->bps, packets->pps) to'g'ridan-to'g'ri,
``sample_bandwidth`` esa ``psutil.net_io_counters`` ni monkeypatch qilib ikki
snapshot bilan sinaladi. ``asyncio.sleep`` 0 ga aylantiriladi — test tez va
deterministik (haqiqiy vaqt kutilmaydi). Tarmoq yo'q.
"""

from __future__ import annotations

import pytest
from conftest import FakeIOCounters

from systop.core import bandwidth
from systop.core.bandwidth import IfaceRate, _compute_rates, sample_bandwidth

# --- IfaceRate dataclass ----------------------------------------------------


def test_iface_rate_defaults_and_total():
    r = IfaceRate(name="en0")
    assert r.rx_bps == 0.0
    assert r.tx_bps == 0.0
    assert r.rx_pps == 0.0
    assert r.tx_pps == 0.0
    assert r.total_bps == 0.0


def test_iface_rate_total_bps_is_sum():
    r = IfaceRate(name="en0", rx_bps=100.0, tx_bps=40.0)
    assert r.total_bps == 140.0


# --- _compute_rates: delta -> bps/pps ---------------------------------------


def test_compute_rates_basic_math():
    prev = {"en0": FakeIOCounters(bytes_recv=1000, bytes_sent=500, packets_recv=10, packets_sent=5)}
    curr = {
        "en0": FakeIOCounters(bytes_recv=2000, bytes_sent=1500, packets_recv=20, packets_sent=15)
    }
    # 1.0 soniyada: rx 1000 bayt -> 8000 bps; tx 1000 bayt -> 8000 bps;
    # rx 10 paket -> 10 pps; tx 10 paket -> 10 pps.
    rates = _compute_rates(prev, curr, elapsed=1.0)
    assert len(rates) == 1
    r = rates[0]
    assert r.name == "en0"
    assert r.rx_bps == pytest.approx(8000.0)
    assert r.tx_bps == pytest.approx(8000.0)
    assert r.rx_pps == pytest.approx(10.0)
    assert r.tx_pps == pytest.approx(10.0)
    assert r.total_bps == pytest.approx(16000.0)


def test_compute_rates_elapsed_scales_inversely():
    prev = {"en0": FakeIOCounters(bytes_recv=0, bytes_sent=0)}
    curr = {"en0": FakeIOCounters(bytes_recv=1000, bytes_sent=0)}
    # 0.5 soniyada 1000 bayt -> 1000*8/0.5 = 16000 bps.
    rates = _compute_rates(prev, curr, elapsed=0.5)
    assert rates[0].rx_bps == pytest.approx(16000.0)


def test_compute_rates_counter_reset_clamps_to_zero():
    """Hisoblagich qayta yuklansa (curr < prev) -> manfiy delta 0 deb olinadi."""
    prev = {
        "en0": FakeIOCounters(bytes_recv=9_000, bytes_sent=9_000, packets_recv=90, packets_sent=90)
    }
    curr = {"en0": FakeIOCounters(bytes_recv=100, bytes_sent=50, packets_recv=1, packets_sent=2)}
    rates = _compute_rates(prev, curr, elapsed=1.0)
    r = rates[0]
    assert r.rx_bps == 0.0
    assert r.tx_bps == 0.0
    assert r.rx_pps == 0.0
    assert r.tx_pps == 0.0


def test_compute_rates_new_interface_has_zero_rate():
    """``curr`` da bor, ``prev`` da yo'q interfeys -> 0 tezlik (taqqoslash nuqtasi yo'q)."""
    prev: dict = {}
    curr = {"en1": FakeIOCounters(bytes_recv=5000, bytes_sent=5000)}
    rates = _compute_rates(prev, curr, elapsed=1.0)
    assert len(rates) == 1
    assert rates[0].name == "en1"
    assert rates[0].rx_bps == 0.0
    assert rates[0].tx_bps == 0.0


def test_compute_rates_disappeared_interface_dropped():
    """``prev`` da bor, ``curr`` da yo'q interfeys natijaga kirmaydi."""
    prev = {"en0": FakeIOCounters(), "lo0": FakeIOCounters()}
    curr = {"en0": FakeIOCounters(bytes_recv=8)}
    rates = _compute_rates(prev, curr, elapsed=1.0)
    assert [r.name for r in rates] == ["en0"]


def test_compute_rates_sorted_by_name():
    prev = {n: FakeIOCounters() for n in ("wlan0", "en0", "lo0")}
    curr = {n: FakeIOCounters(bytes_recv=80) for n in ("wlan0", "en0", "lo0")}
    rates = _compute_rates(prev, curr, elapsed=1.0)
    assert [r.name for r in rates] == ["en0", "lo0", "wlan0"]


def test_compute_rates_zero_elapsed_no_zero_division():
    """elapsed=0 -> 1e-9 ga almashtiriladi (ZeroDivisionError bo'lmasligi kerak)."""
    prev = {"en0": FakeIOCounters(bytes_recv=0)}
    curr = {"en0": FakeIOCounters(bytes_recv=1)}
    rates = _compute_rates(prev, curr, elapsed=0.0)
    # Juda katta, lekin chekli son (inf emas, xato emas).
    assert rates[0].rx_bps > 0.0
    assert rates[0].rx_bps != float("inf")


# --- sample_bandwidth: monkeypatch _read_counters ---------------------------


async def test_sample_bandwidth_two_snapshots(monkeypatch):
    """``sample_bandwidth`` ketma-ket ikki o'qishni delta'ga aylantirsin."""
    snaps = [
        {"en0": FakeIOCounters(bytes_recv=0, bytes_sent=0, packets_recv=0, packets_sent=0)},
        {"en0": FakeIOCounters(bytes_recv=1000, bytes_sent=2000, packets_recv=4, packets_sent=8)},
    ]
    calls = {"n": 0}

    def fake_read():
        snap = snaps[min(calls["n"], len(snaps) - 1)]
        calls["n"] += 1
        return snap

    monkeypatch.setattr(bandwidth, "_read_counters", fake_read)

    # Haqiqiy kutishni o'chiramiz; monotonic'ni 1.0s farq beradigan qilamiz.
    # (1-chi chaqiruv 100.0, keyingilari 101.0 -> elapsed aniq 1.0s.)
    async def no_sleep(_):
        return None

    mono = {"n": 0}

    def fake_monotonic():
        mono["n"] += 1
        return 100.0 if mono["n"] == 1 else 101.0

    monkeypatch.setattr(bandwidth.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(bandwidth.time, "monotonic", fake_monotonic)

    rates = await sample_bandwidth(interval=1.0)
    assert len(rates) == 1
    r = rates[0]
    assert r.name == "en0"
    assert r.rx_bps == pytest.approx(8000.0)  # 1000 bayt * 8 / 1s
    assert r.tx_bps == pytest.approx(16000.0)  # 2000 bayt * 8 / 1s
    assert r.rx_pps == pytest.approx(4.0)
    assert r.tx_pps == pytest.approx(8.0)
    assert calls["n"] == 2  # aniq ikki marta o'qildi


async def test_sample_bandwidth_calls_read_twice(monkeypatch):
    """interval kutilsa ham, o'lchov uchun aniq 2 ta hisoblagich nuqtasi olinadi."""
    calls = {"n": 0}

    def fake_read():
        calls["n"] += 1
        return {"en0": FakeIOCounters(bytes_recv=calls["n"] * 100)}

    async def no_sleep(_):
        return None

    monkeypatch.setattr(bandwidth, "_read_counters", fake_read)
    monkeypatch.setattr(bandwidth.asyncio, "sleep", no_sleep)
    await sample_bandwidth(interval=0.0)
    assert calls["n"] == 2
