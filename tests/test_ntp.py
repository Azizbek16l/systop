"""Offline tests for `core/ntp.py` — SNTP packet validation.

`parse_response` is a pure function: it takes bytes and returns
`(offset, delay, stratum)` or raises `ValueError`. That makes it fully
testable with synthetic packets.

The main hazard in this module is **false reassurance**: the wrong conclusion
"the clock is correct" is worse than a wrong clock, because the sysadmin stops
looking. Most of the tests are therefore phrased as "REJECT this".
"""

import struct

import pytest

from systop.core.ntp import (
    NTP_UNIX_DELTA,
    NtpReport,
    NtpResult,
    _ntp_to_unix,
    build_request,
    parse_response,
)

# --------------------------------------------------------------------------- #
# Packet-building helper
# --------------------------------------------------------------------------- #


def _ts(unix_time: float) -> bytes:
    """Convert a Unix time into an NTP 32.32 fixed-point timestamp."""
    ntp = unix_time + NTP_UNIX_DELTA
    sec = int(ntp)
    frac = int((ntp - sec) * 2**32)
    return struct.pack("!II", sec, frac)


def make_packet(
    *,
    li: int = 0,
    mode: int = 4,
    stratum: int = 2,
    ref_id: bytes = b"GPS\x00",
    originate: bytes | None = None,
    t2: float = 1000.04,
    t3: float = 1000.05,
    zero_t2: bool = False,
    zero_t3: bool = False,
) -> bytes:
    """Build a complete 48-byte SNTP reply packet."""
    p = bytearray(48)
    p[0] = (li << 6) | (4 << 3) | mode  # LI | VN=4 | Mode
    p[1] = stratum
    p[12:16] = ref_id
    p[24:32] = originate if originate is not None else b"\x00" * 8
    p[32:40] = b"\x00" * 8 if zero_t2 else _ts(t2)
    p[40:48] = b"\x00" * 8 if zero_t3 else _ts(t3)
    return bytes(p)


# The usual measurement window: sent at 1000.0, reply arrived at 1000.1.
T1, T4 = 1000.0, 1000.1


# --------------------------------------------------------------------------- #
# Request: nonce
# --------------------------------------------------------------------------- #


def test_request_is_built_with_a_nonce():
    """The nonce must be written into the Transmit Timestamp field (40:48)."""
    packet, nonce = build_request()
    assert len(packet) == 48
    assert len(nonce) == 8
    assert packet[40:48] == nonce
    assert packet[0] == 0x23  # LI=0, VN=4, Mode=3 (client)


def test_nonce_differs_every_time():
    """A fixed nonce would protect nothing."""
    nonces = {build_request()[1] for _ in range(20)}
    assert len(nonces) == 20


def test_nonce_is_not_zero():
    """REGRESSION: this field used to be all zeroes — nothing could be checked."""
    _, nonce = build_request()
    assert nonce != b"\x00" * 8


# --------------------------------------------------------------------------- #
# Valid packet
# --------------------------------------------------------------------------- #


def test_valid_packet_is_parsed():
    offset, delay, stratum = parse_response(make_packet(), T1, T4)
    assert stratum == 2
    # offset = ((t2-t1) + (t3-t4)) / 2 = (0.04 + -0.05) / 2 = -0.005
    assert offset == pytest.approx(-0.005, abs=1e-6)
    # delay = (t4-t1) - (t3-t2) = 0.1 - 0.01 = 0.09
    assert delay == pytest.approx(0.09, abs=1e-6)


def test_matching_nonce_is_accepted():
    nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    pkt = make_packet(originate=nonce)
    offset, _, _ = parse_response(pkt, T1, T4, nonce=nonce)
    assert offset == pytest.approx(-0.005, abs=1e-6)


# --------------------------------------------------------------------------- #
# Packets that MUST BE REJECTED
# --------------------------------------------------------------------------- #


def test_stray_datagram_is_caught_by_the_nonce():
    """THE KEY SECURITY FIX.

    A stray UDP datagram that landed on the ephemeral port used to be accepted
    as "the server's reply" and produced `offset=-400s`, `severity=critical` —
    that is, it reported a healthy clock as "broken".
    """
    _, nonce = build_request()
    forged = make_packet(originate=b"\xff" * 8)  # a reply to some other request
    with pytest.raises(ValueError, match="does not match"):
        parse_response(forged, T1, T4, nonce=nonce)


def test_non_server_reply_is_rejected():
    """Mode=3 — that is a client request, not a reply (a broadcast/spoof sign)."""
    with pytest.raises(ValueError, match="Mode"):
        parse_response(make_packet(mode=3), T1, T4)


def test_alarm_condition_is_rejected():
    """LI=3 — the server itself is unsynchronised, its time cannot be trusted."""
    with pytest.raises(ValueError, match="not synchronised"):
        parse_response(make_packet(li=3), T1, T4)


def test_kiss_of_death_is_rejected_and_reason_is_read():
    """stratum=0 — KoD. This used to be reported as `severity='ok'`.

    In other words, while the server was saying "your requests are too fast,
    stop", the tool concluded "the clock is correct" — pure false reassurance.
    """
    with pytest.raises(ValueError, match="RATE"):
        parse_response(make_packet(stratum=0, ref_id=b"RATE"), T1, T4)
    with pytest.raises(ValueError, match="DENY"):
        parse_response(make_packet(stratum=0, ref_id=b"DENY"), T1, T4)


def test_invalid_stratum_is_rejected():
    """16 = unsynchronised; anything above that is invalid outright."""
    with pytest.raises(ValueError, match="stratum"):
        parse_response(make_packet(stratum=16), T1, T4)
    with pytest.raises(ValueError, match="stratum"):
        parse_response(make_packet(stratum=99), T1, T4)


def test_stratum_1_and_15_are_accepted():
    """Values inside the bounds must not be rejected (real servers)."""
    for s in (1, 2, 3, 15):
        _, _, got = parse_response(make_packet(stratum=s), T1, T4)
        assert got == s


def test_half_empty_packet_is_rejected():
    """REGRESSION: the condition used to be `and` — rejected only if BOTH zero.

    When a single timestamp is zero it turns into the year 1900 and throws
    `offset` off by ±2e9 seconds.
    """
    with pytest.raises(ValueError, match="timestamp"):
        parse_response(make_packet(zero_t2=True), T1, T4)
    with pytest.raises(ValueError, match="timestamp"):
        parse_response(make_packet(zero_t3=True), T1, T4)


def test_short_packet_is_rejected():
    with pytest.raises(ValueError, match="too short"):
        parse_response(b"\x24" + b"\x00" * 20, T1, T4)


# --------------------------------------------------------------------------- #
# The causality envelope — on the RAW delay
# --------------------------------------------------------------------------- #


def test_impossible_delay_is_rejected():
    """The delay cannot exceed the local round-trip — the packet is from elsewhere.

    `max(delay, 0.0)` hid this SILENTLY: a negative delay became zero and a
    corrupt measurement looked "perfect".
    """
    # t3 - t2 is negative (the server went "backwards") => delay > elapsed
    with pytest.raises(ValueError, match="implausible"):
        parse_response(make_packet(t2=1000.5, t3=1000.0), T1, T4)


def test_small_negative_delay_is_accepted():
    """A few ms of negative delay is normal given clock granularity — clamped to zero."""
    # t3-t2 = 0.11 > elapsed 0.1 => delay = -0.01 (within the 0.05 slack)
    _, delay, _ = parse_response(make_packet(t2=1000.0, t3=1000.11), T1, T4)
    assert delay == 0.0


def test_genuine_large_skew_is_NOT_rejected():
    """IMPORTANT: the envelope constrains `delay`, not `offset`.

    A server with a dead RTC battery reports a time 56 years in the past — that
    is a GENUINE finding and must not be thrown away. The delay meanwhile stays
    perfectly normal.
    """
    now = 1_767_000_000.0  # ~2026
    server_1970 = 0.04  # dead RTC battery => the Unix epoch
    offset, delay, _ = parse_response(
        make_packet(t2=server_1970, t3=server_1970 + 0.01),
        now,
        now + 0.1,
    )
    assert offset < -1.7e9  # a ~56-year skew was recorded, not discarded
    assert delay == pytest.approx(0.09, abs=1e-6)


# --------------------------------------------------------------------------- #
# The RFC 4330 "era" rule
# --------------------------------------------------------------------------- #


def test_era_rule_before_2036():
    """Bit 0 set => counted from 1900."""
    assert _ntp_to_unix(NTP_UNIX_DELTA + 1000, 0) == pytest.approx(1000.0)


def test_era_rule_after_2036():
    """Bit 0 not set => counted from 2036, NOT a negative time.

    An unconditional subtraction turned such a timestamp into -2.2e9 and made
    `offset` completely useless.
    """
    small = 1000  # bit 0 not set
    got = _ntp_to_unix(small, 0)
    assert got > 0
    assert got == pytest.approx(small + 2**32 - NTP_UNIX_DELTA)


def test_era_boundary():
    """Exactly 2**31 — the first "old era" value."""
    assert _ntp_to_unix(2**31, 0) == pytest.approx(2**31 - NTP_UNIX_DELTA)
    assert _ntp_to_unix(2**31 - 1, 0) > 0


# --------------------------------------------------------------------------- #
# Report summary
# --------------------------------------------------------------------------- #


def test_median_withstands_one_lying_server():
    """If one server reports a bogus time the mean is ruined, the median is not."""
    rep = NtpReport(
        results=[
            NtpResult(server="a", ok=True, offset_s=0.01),
            NtpResult(server="b", ok=True, offset_s=0.02),
            NtpResult(server="c", ok=True, offset_s=5000.0),  # the liar
        ]
    )
    assert rep.median_offset_s == pytest.approx(0.02)


def test_non_responders_are_excluded_from_the_median():
    rep = NtpReport(
        results=[
            NtpResult(server="a", ok=True, offset_s=0.5),
            NtpResult(server="b", ok=False),  # offset_s defaults to 0.0
        ]
    )
    assert rep.median_offset_s == pytest.approx(0.5)


def test_empty_report_median_is_none():
    assert NtpReport().median_offset_s is None


def test_severity_thresholds():
    assert NtpResult(server="a", ok=True, offset_s=0.1).severity == "ok"
    assert NtpResult(server="a", ok=True, offset_s=2.0).severity == "warn"
    assert NtpResult(server="a", ok=True, offset_s=60.0).severity == "high"
    assert NtpResult(server="a", ok=True, offset_s=400.0).severity == "critical"
    assert NtpResult(server="a", ok=True, offset_s=-400.0).severity == "critical"


def test_non_responding_server_is_not_counted_as_ok():
    """With ok=False the offset is 0.0 — that must not be read as 'clock correct'."""
    r = NtpResult(server="a", ok=False)
    assert r.severity == "warn"
    assert NtpReport(results=[r]).worst_severity == "warn"
