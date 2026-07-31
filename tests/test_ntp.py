"""`core/ntp.py` uchun offline testlar — SNTP paket validatsiyasi.

`parse_response` sof funksiya: baytlarni oladi, `(offset, delay, stratum)`
beradi yoki `ValueError`. Shuning uchun sun'iy paketlar bilan to'liq sinaladi.

Bu modulning asosiy xavfi — **soxta xotirjamlik**: "soat to'g'ri" degan
noto'g'ri xulosa soat noto'g'riligidan yomonroq, chunki sysadmin tekshirishni
to'xtatadi. Shuning uchun testlarning ko'pchiligi "buni RAD ET" shaklida.
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
# Paket yasovchi yordamchi
# --------------------------------------------------------------------------- #


def _ts(unix_time: float) -> bytes:
    """Unix vaqtni NTP 32.32 fixed-point timestamp'ga o'giradi."""
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
    """To'liq 48-baytli SNTP javob paketini yasaydi."""
    p = bytearray(48)
    p[0] = (li << 6) | (4 << 3) | mode  # LI | VN=4 | Mode
    p[1] = stratum
    p[12:16] = ref_id
    p[24:32] = originate if originate is not None else b"\x00" * 8
    p[32:40] = b"\x00" * 8 if zero_t2 else _ts(t2)
    p[40:48] = b"\x00" * 8 if zero_t3 else _ts(t3)
    return bytes(p)


# Odatiy o'lchov oynasi: jo'natdik 1000.0, javob keldi 1000.1.
T1, T4 = 1000.0, 1000.1


# --------------------------------------------------------------------------- #
# So'rov: nonce
# --------------------------------------------------------------------------- #


def test_sorov_nonce_bilan_yasaladi():
    """Nonce Transmit Timestamp maydoniga (40:48) yozilishi kerak."""
    packet, nonce = build_request()
    assert len(packet) == 48
    assert len(nonce) == 8
    assert packet[40:48] == nonce
    assert packet[0] == 0x23  # LI=0, VN=4, Mode=3 (client)


def test_nonce_har_safar_boshqacha():
    """Qat'iy nonce hech narsani himoya qilmasdi."""
    nonces = {build_request()[1] for _ in range(20)}
    assert len(nonces) == 20


def test_nonce_nol_emas():
    """REGRESSIYA: ilgari bu maydon butunlay nol edi — tekshiruv imkonsiz edi."""
    _, nonce = build_request()
    assert nonce != b"\x00" * 8


# --------------------------------------------------------------------------- #
# To'g'ri paket
# --------------------------------------------------------------------------- #


def test_togri_paket_parse_bolinadi():
    offset, delay, stratum = parse_response(make_packet(), T1, T4)
    assert stratum == 2
    # offset = ((t2-t1) + (t3-t4)) / 2 = (0.04 + -0.05) / 2 = -0.005
    assert offset == pytest.approx(-0.005, abs=1e-6)
    # delay = (t4-t1) - (t3-t2) = 0.1 - 0.01 = 0.09
    assert delay == pytest.approx(0.09, abs=1e-6)


def test_togri_nonce_qabul_qilinadi():
    nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    pkt = make_packet(originate=nonce)
    offset, _, _ = parse_response(pkt, T1, T4, nonce=nonce)
    assert offset == pytest.approx(-0.005, abs=1e-6)


# --------------------------------------------------------------------------- #
# RAD ETILISHI KERAK bo'lgan paketlar
# --------------------------------------------------------------------------- #


def test_begona_datagramma_nonce_bilan_ushlanadi():
    """ASOSIY XAVFSIZLIK TUZATISHI.

    Ephemeral portga tushgan begona UDP datagrammasi ilgari "server javobi"
    deb qabul qilinardi va `offset=-400s`, `severity=critical` berardi —
    ya'ni sog'lom soatni "buzuq" deb ko'rsatardi.
    """
    _, nonce = build_request()
    soxta = make_packet(originate=b"\xff" * 8)  # boshqa so'rovga javob
    with pytest.raises(ValueError, match="mos kelmadi"):
        parse_response(soxta, T1, T4, nonce=nonce)


def test_server_javobi_emas_rad_etiladi():
    """Mode=3 — bu mijoz so'rovi, javob emas (broadcast/spoof belgisi)."""
    with pytest.raises(ValueError, match="Mode"):
        parse_response(make_packet(mode=3), T1, T4)


def test_alarm_holati_rad_etiladi():
    """LI=3 — server o'zi sinxronlanmagan, uning vaqtiga ishonib bo'lmaydi."""
    with pytest.raises(ValueError, match="sinxronlanmagan"):
        parse_response(make_packet(li=3), T1, T4)


def test_kiss_of_death_rad_etiladi_va_sabab_oqiladi():
    """stratum=0 — KoD. Ilgari bu `severity='ok'` deb ko'rsatilardi.

    Ya'ni server "so'rovlaringiz juda tez, to'xtang" deb turgan paytda tool
    "soat to'g'ri" deb xulosa qilardi — sof soxta xotirjamlik.
    """
    with pytest.raises(ValueError, match="RATE"):
        parse_response(make_packet(stratum=0, ref_id=b"RATE"), T1, T4)
    with pytest.raises(ValueError, match="DENY"):
        parse_response(make_packet(stratum=0, ref_id=b"DENY"), T1, T4)


def test_yaroqsiz_stratum_rad_etiladi():
    """16 = sinxronlanmagan; undan yuqorisi umuman yaroqsiz."""
    with pytest.raises(ValueError, match="stratum"):
        parse_response(make_packet(stratum=16), T1, T4)
    with pytest.raises(ValueError, match="stratum"):
        parse_response(make_packet(stratum=99), T1, T4)


def test_stratum_1_va_15_qabul_qilinadi():
    """Chegaralar ichidagilar rad etilmasligi kerak (haqiqiy serverlar)."""
    for s in (1, 2, 3, 15):
        _, _, got = parse_response(make_packet(stratum=s), T1, T4)
        assert got == s


def test_yarim_bosh_paket_rad_etiladi():
    """REGRESSIYA: shart `and` edi — faqat IKKALASI nol bo'lganda rad etilardi.

    Bitta timestamp nol bo'lsa u 1900-yilga aylanib, `offset` ni ±2e9
    soniyaga olib chiqardi.
    """
    with pytest.raises(ValueError, match="timestamp"):
        parse_response(make_packet(zero_t2=True), T1, T4)
    with pytest.raises(ValueError, match="timestamp"):
        parse_response(make_packet(zero_t3=True), T1, T4)


def test_qisqa_paket_rad_etiladi():
    with pytest.raises(ValueError, match="qisqa"):
        parse_response(b"\x24" + b"\x00" * 20, T1, T4)


# --------------------------------------------------------------------------- #
# Sababiyat konverti — XOM delay bo'yicha
# --------------------------------------------------------------------------- #


def test_mumkin_bolmagan_delay_rad_etiladi():
    """delay lokal round-trip'dan katta bo'la olmaydi — paket boshqa vaqtdan.

    `max(delay, 0.0)` buni JIMGINA yashirardi: manfiy delay nolga aylanib,
    buzuq o'lchov "mukammal" bo'lib ko'rinardi.
    """
    # t3 - t2 manfiy (server "orqaga" ketgan) => delay > elapsed
    with pytest.raises(ValueError, match="mantiqsiz"):
        parse_response(make_packet(t2=1000.5, t3=1000.0), T1, T4)


def test_kichik_manfiy_delay_qabul_qilinadi():
    """Soat granularligi tufayli bir necha ms manfiy delay normal — nolga qiriladi."""
    # t3-t2 = 0.11 > elapsed 0.1 => delay = -0.01 (slack 0.05 ichida)
    _, delay, _ = parse_response(make_packet(t2=1000.0, t3=1000.11), T1, T4)
    assert delay == 0.0


def test_haqiqiy_katta_siljish_rad_ETILMAYDI():
    """MUHIM: konvert `offset` ni emas, `delay` ni cheklaydi.

    O'lgan RTC batareyali server 56 yil oldingi vaqtni beradi — bu HAQIQIY
    topilma, uni tashlab yubormaslik kerak. Delay esa normal bo'lib qolaveradi.
    """
    hozir = 1_767_000_000.0          # ~2026
    server_1970 = 0.04               # RTC batareyasi o'lgan => Unix epoch
    offset, delay, _ = parse_response(
        make_packet(t2=server_1970, t3=server_1970 + 0.01),
        hozir,
        hozir + 0.1,
    )
    assert offset < -1.7e9  # ~56 yillik siljish qayd etildi, tashlanmadi
    assert delay == pytest.approx(0.09, abs=1e-6)


# --------------------------------------------------------------------------- #
# RFC 4330 "era" qoidasi
# --------------------------------------------------------------------------- #


def test_era_qoidasi_2036_gacha():
    """0-bit o'rnatilgan => 1900-yildan sanaladi."""
    assert _ntp_to_unix(NTP_UNIX_DELTA + 1000, 0) == pytest.approx(1000.0)


def test_era_qoidasi_2036_dan_keyin():
    """0-bit o'rnatilmagan => 2036-yildan sanaladi, MANFIY vaqt emas.

    Shartsiz ayirish bunday timestamp'ni -2.2e9 ga aylantirib, `offset` ni
    butunlay yaroqsiz qilardi.
    """
    kichik = 1000  # 0-bit o'rnatilmagan
    got = _ntp_to_unix(kichik, 0)
    assert got > 0
    assert got == pytest.approx(kichik + 2**32 - NTP_UNIX_DELTA)


def test_era_chegarasi():
    """Aynan 2**31 — birinchi "eski era" qiymati."""
    assert _ntp_to_unix(2**31, 0) == pytest.approx(2**31 - NTP_UNIX_DELTA)
    assert _ntp_to_unix(2**31 - 1, 0) > 0


# --------------------------------------------------------------------------- #
# Hisobot jamlanmasi
# --------------------------------------------------------------------------- #


def test_mediana_bitta_yolgonchi_serverga_bardosh_beradi():
    """Bitta server yolg'on vaqt bersa o'rtacha buziladi, mediana yo'q."""
    rep = NtpReport(results=[
        NtpResult(server="a", ok=True, offset_s=0.01),
        NtpResult(server="b", ok=True, offset_s=0.02),
        NtpResult(server="c", ok=True, offset_s=5000.0),  # yolg'onchi
    ])
    assert rep.median_offset_s == pytest.approx(0.02)


def test_javob_bermaganlar_medianaga_kirmaydi():
    rep = NtpReport(results=[
        NtpResult(server="a", ok=True, offset_s=0.5),
        NtpResult(server="b", ok=False),  # offset_s standart 0.0
    ])
    assert rep.median_offset_s == pytest.approx(0.5)


def test_bosh_hisobot_medianasi_none():
    assert NtpReport().median_offset_s is None


def test_severity_chegaralari():
    assert NtpResult(server="a", ok=True, offset_s=0.1).severity == "ok"
    assert NtpResult(server="a", ok=True, offset_s=2.0).severity == "warn"
    assert NtpResult(server="a", ok=True, offset_s=60.0).severity == "high"
    assert NtpResult(server="a", ok=True, offset_s=400.0).severity == "critical"
    assert NtpResult(server="a", ok=True, offset_s=-400.0).severity == "critical"


def test_javob_bermagan_server_ok_deb_hisoblanmaydi():
    """ok=False bo'lganda offset 0.0 bo'ladi — buni 'soat to'g'ri' deb o'qimaslik kerak."""
    r = NtpResult(server="a", ok=False)
    assert r.severity == "warn"
    assert NtpReport(results=[r]).worst_severity == "warn"
