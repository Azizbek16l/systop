"""`core/wifi.py` uchun offline testlar — barcha parser sof funksiya."""

from systop.core.wifi import (
    NON_OVERLAPPING_24,
    WifiNetwork,
    WifiStatus,
    _phy_generation,
    channel_to_band,
    freq_to_channel,
    overlapping_24ghz,
    parse_iw_link,
    parse_macos_airport,
    parse_netsh_interfaces,
)

# macOS chiqishi — SSID YASHIRILGAN (`<redacted>`) va ba'zi qo'shni bloklarida
# sarlavha qatori umuman yo'q. Ikkalasi ham haqiqiy macOS xulqi.
_MACOS = """Wi-Fi:

      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4388)
          MAC Address: 52:cd:f8:9d:07:3b
          Country Code: UZ
          Supported PHY Modes: 802.11 a/b/g/n/ac/ax
          Supported Channels: 1 (2GHz), 6 (2GHz), 36 (5GHz), 149 (5GHz)
          Status: Connected
          Current Network Information:
            <redacted>:
              PHY Mode: 802.11n
              Channel: 6 (2GHz, 20MHz)
              Country Code: UZ
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -43 dBm / -84 dBm
              Transmit Rate: 144
              MCS Index: 15
          Other Local Wi-Fi Networks:
              PHY Mode: 802.11a/n/ac
              Channel: 40 (5GHz, 80MHz)
              Network Type: Infrastructure
              Security: WPA2 Personal
              PHY Mode: 802.11b/g/n
              Channel: 8 (2GHz, 40MHz)
              Network Type: Infrastructure
              Security: WPA3 Personal
            MyNeighbour:
              PHY Mode: 802.11b/g/n
              Channel: 11 (2GHz, 20MHz)
              Network Type: Infrastructure
              Security: WPA2 Personal
"""


# --------------------------------------------------------------------------- #
# macOS parser
# --------------------------------------------------------------------------- #


def test_macos_detects_hardware_and_connection():
    w = parse_macos_airport(_MACOS)
    assert w.available is True
    assert w.connected is True
    assert w.interface == "en0"


def test_macos_signal_and_noise():
    w = parse_macos_airport(_MACOS)
    assert w.rssi_dbm == -43
    assert w.noise_dbm == -84
    assert w.snr_db == 41


def test_macos_channel_band_width():
    w = parse_macos_airport(_MACOS)
    assert w.channel == 6
    assert w.band == "2.4GHz"
    assert w.width_mhz == 20
    assert w.is_24ghz is True


def test_macos_phy_and_card_capability():
    w = parse_macos_airport(_MACOS)
    assert w.phy_mode == "802.11n"
    assert w.phy_generation == "n"
    assert w.supported_generation == "ax"
    assert w.supports_5ghz is True


def test_macos_redacted_ssid_is_none_not_literal():
    """macOS SSID'ni `<redacted>` qiladi — uni nom sifatida saqlamaslik kerak."""
    w = parse_macos_airport(_MACOS)
    assert w.ssid is None


def test_macos_transmit_rate_and_security():
    w = parse_macos_airport(_MACOS)
    assert w.tx_rate_mbps == 144.0
    assert w.security == "WPA2 Personal"
    assert w.country_code == "UZ"


def test_macos_parses_headerless_neighbour_blocks():
    """Sarlavhasiz qo'shni bloklari takroriy kalit bo'yicha ajratilishi kerak."""
    w = parse_macos_airport(_MACOS)
    assert len(w.neighbours) == 3
    channels = sorted(n.channel for n in w.neighbours if n.channel)
    assert channels == [8, 11, 40]


def test_macos_neighbour_bands_and_widths():
    w = parse_macos_airport(_MACOS)
    by_ch = {n.channel: n for n in w.neighbours}
    assert by_ch[40].band == "5GHz"
    assert by_ch[40].width_mhz == 80
    assert by_ch[8].band == "2.4GHz"
    assert by_ch[8].width_mhz == 40


def test_macos_five_ghz_available_from_neighbours():
    assert parse_macos_airport(_MACOS).five_ghz_available is True


def test_macos_empty_input_is_safe():
    w = parse_macos_airport("")
    assert w.available is False
    assert w.connected is False
    assert w.neighbours == []


# --------------------------------------------------------------------------- #
# Linux parser
# --------------------------------------------------------------------------- #

_IW_LINK = """Connected to aa:bb:cc:dd:ee:ff (on wlan0)
\tSSID: OfficeWiFi
\tfreq: 5180
\tsignal: -55 dBm
\ttx bitrate: 866.7 MBit/s 80MHz short GI VHT-MCS 9
"""


def test_iw_link_parses_ssid_signal_freq():
    w = parse_iw_link(_IW_LINK, interface="wlan0")
    assert w.connected is True
    assert w.ssid == "OfficeWiFi"
    assert w.rssi_dbm == -55
    assert w.channel == 36
    assert w.band == "5GHz"


def test_iw_link_parses_tx_rate():
    assert parse_iw_link(_IW_LINK).tx_rate_mbps == 866.7


def test_iw_link_not_connected():
    w = parse_iw_link("Not connected.", interface="wlan0")
    assert w.available is True
    assert w.connected is False


# --------------------------------------------------------------------------- #
# Windows parser
# --------------------------------------------------------------------------- #

_NETSH = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : CorpNet
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Channel                : 44
    Receive rate (Mbps)    : 780
    Signal                 : 82%
"""


def test_netsh_parses_ssid_channel_security():
    w = parse_netsh_interfaces(_NETSH)
    assert w.ssid == "CorpNet"
    assert w.channel == 44
    assert w.band == "5GHz"
    assert w.security == "WPA2-Personal"
    assert w.phy_mode == "802.11ac"


def test_netsh_converts_percent_signal_to_dbm():
    """netsh foizda beradi; taxminiy dBm ga chiziqli o'girish."""
    w = parse_netsh_interfaces(_NETSH)
    assert w.rssi_dbm == -59  # 82% -> 82/2 - 100


# --------------------------------------------------------------------------- #
# Sof yordamchilar
# --------------------------------------------------------------------------- #


def test_phy_generation_prefers_ax_over_ac():
    """`a/b/g/n/ac/ax` da `ac` `ax` ni yutib yubormasligi kerak."""
    assert _phy_generation("802.11 a/b/g/n/ac/ax") == "ax"


def test_phy_generation_variants():
    assert _phy_generation("802.11ac") == "ac"
    assert _phy_generation("802.11n") == "n"
    assert _phy_generation("802.11b/g") == "legacy"
    assert _phy_generation(None) is None


def test_channel_to_band():
    assert channel_to_band(1) == "2.4GHz"
    assert channel_to_band(11) == "2.4GHz"
    assert channel_to_band(36) == "5GHz"
    assert channel_to_band(165) == "5GHz"


def test_freq_to_channel():
    assert freq_to_channel(2412) == 1
    assert freq_to_channel(2437) == 6
    assert freq_to_channel(5180) == 36
    assert freq_to_channel(999) is None


def test_overlap_counts_adjacent_24ghz_channels():
    """2.4 GHz da qo'shni kanal fizik ustma-ust tushadi (±4)."""
    nb = [
        WifiNetwork(channel=6, band="2.4GHz", width_mhz=20),
        WifiNetwork(channel=8, band="2.4GHz", width_mhz=20),
        WifiNetwork(channel=11, band="2.4GHz", width_mhz=20),
    ]
    over = overlapping_24ghz(6, nb)
    assert len(over) == 2  # ch6 va ch8; ch11 uzoq


def test_overlap_wider_reach_for_40mhz():
    """40 MHz AP ikki barobar keng joyni egallaydi (±8)."""
    nb = [WifiNetwork(channel=13, band="2.4GHz", width_mhz=40)]
    assert len(overlapping_24ghz(6, nb)) == 1
    nb20 = [WifiNetwork(channel=13, band="2.4GHz", width_mhz=20)]
    assert len(overlapping_24ghz(6, nb20)) == 0


def test_overlap_ignores_5ghz_neighbours():
    nb = [WifiNetwork(channel=36, band="5GHz", width_mhz=80)]
    assert overlapping_24ghz(6, nb) == []


def test_non_overlapping_channels_constant():
    assert NON_OVERLAPPING_24 == (1, 6, 11)


# --------------------------------------------------------------------------- #
# WifiStatus xossalari
# --------------------------------------------------------------------------- #


def test_signal_quality_bands():
    assert WifiStatus(rssi_dbm=-40).signal_quality == "excellent"
    assert WifiStatus(rssi_dbm=-55).signal_quality == "good"
    assert WifiStatus(rssi_dbm=-65).signal_quality == "fair"
    assert WifiStatus(rssi_dbm=-75).signal_quality == "poor"
    assert WifiStatus(rssi_dbm=-90).signal_quality == "unusable"


def test_signal_quality_none_without_rssi():
    assert WifiStatus().signal_quality is None


def test_snr_none_without_noise():
    assert WifiStatus(rssi_dbm=-50).snr_db is None


# --------------------------------------------------------------------------- #
# Kanal kesishuvi — IKKALA diapazon
# --------------------------------------------------------------------------- #

from systop.core.wifi import channel_span, overlapping_channels  # noqa: E402


def test_80mhz_kanal_tortta_uyachani_egallaydi():
    """ "Kanal 64" degan yozuv AP qancha joy egallashini AYTMAYDI.

    80 MHz kenglikdagi AP to'rtta 20 MHz kanalni bosadi. Faqat raqamni
    taqqoslash bu to'qnashuvlarni butunlay o'tkazib yuboradi.
    """
    assert channel_span(64, "5GHz", 80) == {52, 56, 60, 64}
    assert channel_span(36, "5GHz", 80) == {36, 40, 44, 48}
    assert channel_span(157, "5GHz", 80) == {149, 153, 157, 161}


def test_40mhz_va_20mhz_span():
    assert channel_span(60, "5GHz", 40) == {60, 64}
    assert channel_span(64, "5GHz", 20) == {64}
    assert channel_span(64, "5GHz", None) == {64}


def test_unii3_bloki_arifmetika_bilan_chiqmaydi():
    """(149-36)/4 butun son emas — shuning uchun bloklar ro'yxat sifatida.

    Arifmetik formula bu yerda noto'g'ri natija berardi.
    """
    assert channel_span(149, "5GHz", 80) == {149, 153, 157, 161}
    assert 149 not in channel_span(144, "5GHz", 80)


def test_notanish_kanal_ehtiyotkor():
    """Noma'lum (DFS/mintaqaviy) kanalda faqat o'zi hisoblanadi — taxmin qilinmaydi."""
    assert channel_span(177, "5GHz", 80) == {177}


def test_5ghz_bir_kanaldagi_qoshni_aniqlanadi():
    """ASOSIY KAMCHILIK REGRESSIYASI.

    Ilgari faqat 2.4 GHz tekshirilardi. Natijada 5 GHz da AYNAN bir kanalda
    turgan qo'shni — eng jiddiy holat, to'liq co-channel raqobat — umuman
    aytilmasdi.
    """
    ns = [
        WifiNetwork(channel=64, band="5GHz", width_mhz=80),
        WifiNetwork(channel=36, band="5GHz", width_mhz=80),
        WifiNetwork(channel=157, band="5GHz", width_mhz=80),
    ]
    ov = overlapping_channels(64, "5GHz", 80, ns)
    assert [n.channel for n in ov] == [64]


def test_5ghz_kesishuvchi_blok_aniqlanadi():
    """60-kanaldagi 40 MHz AP {60,64} ni egallaydi — 64 bilan kesishadi."""
    ns = [WifiNetwork(channel=60, band="5GHz", width_mhz=40)]
    assert len(overlapping_channels(64, "5GHz", 20, ns)) == 1


def test_boshqa_diapazon_hech_qachon_xalaqit_bermaydi():
    """2.4 va 5 GHz — turli chastotalar, ular kesisha olmaydi."""
    ns = [WifiNetwork(channel=6, band="2.4GHz", width_mhz=20)]
    assert overlapping_channels(64, "5GHz", 80, ns) == []
    ns2 = [WifiNetwork(channel=64, band="5GHz", width_mhz=80)]
    assert overlapping_channels(6, "2.4GHz", 20, ns2) == []


def test_24ghz_qoidasi_saqlanadi():
    """2.4 GHz uzluksiz ustma-ust tushadi: ±4, 40 MHz uchun ±8."""
    ns = [
        WifiNetwork(channel=1, band="2.4GHz", width_mhz=20),  # 6 dan 5 uzoq -> yo'q
        WifiNetwork(channel=8, band="2.4GHz", width_mhz=20),  # 2 uzoq -> ha
        WifiNetwork(channel=13, band="2.4GHz", width_mhz=40),  # 7 uzoq, ±8 -> ha
    ]
    got = {n.channel for n in overlapping_channels(6, "2.4GHz", 20, ns)}
    assert got == {8, 13}


def test_kanalsiz_qoshni_tashlanadi():
    ns = [WifiNetwork(channel=None, band="5GHz", width_mhz=80)]
    assert overlapping_channels(64, "5GHz", 80, ns) == []
