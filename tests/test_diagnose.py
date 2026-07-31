"""`core/diagnose.py` uchun offline testlar — muammo topish mantiqini sinaydi.

Barcha `evaluate_*` funksiyalari sof: tayyor o'lchovni oladi, `Finding` beradi.
Shuning uchun tarmoqsiz to'liq sinaladi (orkestrator `run_diagnostics` sinalmaydi
— u tarmoqqa chiqadi).
"""

from systop.core.diagnose import (
    CAT_CONNECTIVITY,
    CAT_EXPOSURE,
    RISKY_LISTENERS,
    SEV_CRITICAL,
    SEV_HIGH,
    SEV_INFO,
    SEV_LOW,
    SEV_MEDIUM,
    Finding,
    Report,
    Thresholds,
    evaluate_dns,
    evaluate_interface,
    evaluate_ipv6,
    evaluate_lan,
    evaluate_listeners,
    evaluate_ping,
    evaluate_tls,
    evaluate_web,
    is_management_device,
    sort_findings,
)

# --------------------------------------------------------------------------- #
# ping
# --------------------------------------------------------------------------- #


def test_ping_dead_gateway_is_critical():
    f = evaluate_ping("Gateway", "192.168.1.1", False, 100.0, 0, 0, is_lan=True)
    assert len(f) == 1
    assert f[0].severity == SEV_CRITICAL
    assert f[0].category == CAT_CONNECTIVITY


def test_ping_dead_internet_is_high_not_critical():
    """Internet nishoni o'lishi gateway o'limidan kamroq jiddiy."""
    f = evaluate_ping("Cloudflare", "1.1.1.1", False, 100.0, 0, 0, is_lan=False)
    assert f[0].severity == SEV_HIGH


def test_ping_dead_skips_rtt_and_jitter():
    """Javob bermasa RTT/jitter topilmasligi kerak — ular ma'nosiz."""
    f = evaluate_ping("Gateway", "10.0.0.1", False, 100.0, 9999, 9999, is_lan=True)
    assert len(f) == 1


def test_ping_loss_thresholds():
    hi = evaluate_ping("g", "1.1.1.1", True, 25.0, 1, 1)
    med = evaluate_ping("g", "1.1.1.1", True, 10.0, 1, 1)
    low = evaluate_ping("g", "1.1.1.1", True, 1.0, 1, 1)
    assert hi[0].severity == SEV_HIGH
    assert med[0].severity == SEV_MEDIUM
    assert low[0].severity == SEV_LOW


def test_ping_clean_result_has_no_findings():
    assert evaluate_ping("g", "1.1.1.1", True, 0.0, 5.0, 2.0) == []


def test_ping_lan_rtt_limit_is_stricter():
    """LAN'da 60 ms muammo, internetda esa normal."""
    lan = evaluate_ping("Gateway", "192.168.1.1", True, 0, 60.0, 0, is_lan=True)
    wan = evaluate_ping("CF", "1.1.1.1", True, 0, 60.0, 0, is_lan=False)
    assert any("kechikish" in f.title for f in lan)
    assert wan == []


def test_ping_jitter_flagged():
    f = evaluate_ping("g", "1.1.1.1", True, 0, 5.0, 45.0)
    assert any("jitter" in x.title for x in f)


def test_ping_custom_thresholds_respected():
    th = Thresholds(jitter_ms=100.0)
    assert evaluate_ping("g", "1.1.1.1", True, 0, 5.0, 45.0, th=th) == []


# --------------------------------------------------------------------------- #
# interfeys
# --------------------------------------------------------------------------- #


def test_apipa_address_flagged():
    f = evaluate_interface("en0", True, "169.254.10.5")
    assert f[0].severity == SEV_HIGH
    assert "APIPA" in f[0].title


def test_interface_error_rate_flagged():
    f = evaluate_interface("en0", True, "192.168.1.5", errors=100, packets=1000)
    assert any(x.severity == SEV_HIGH for x in f)


def test_interface_drops_flagged_lower_severity():
    f = evaluate_interface("en0", True, "192.168.1.5", drops=100, packets=1000)
    assert any(x.severity == SEV_MEDIUM for x in f)


def test_interface_clean_no_findings():
    assert evaluate_interface("en0", True, "192.168.1.5", 0, 0, 100000) == []


def test_interface_zero_packets_no_division_error():
    """Paket 0 bo'lsa nolga bo'linish bo'lmasligi kerak."""
    assert evaluate_interface("en0", True, "192.168.1.5", 5, 5, 0) == []


# --------------------------------------------------------------------------- #
# ochiq tinglayotgan xizmatlar
# --------------------------------------------------------------------------- #


def test_docker_api_wildcard_is_critical():
    f = evaluate_listeners([("0.0.0.0", 2375, "dockerd")])
    assert f[0].severity == SEV_CRITICAL
    assert f[0].category == CAT_EXPOSURE


def test_localhost_bind_is_safe():
    """127.0.0.1 ga bog'langan xizmat tarmoqqa ochiq emas — ogohlantirmaslik kerak."""
    assert evaluate_listeners([("127.0.0.1", 6379, "redis")]) == []


def test_ipv6_wildcard_also_flagged():
    f = evaluate_listeners([("::", 27017, "mongod")])
    assert len(f) == 1


def test_unknown_port_not_flagged():
    assert evaluate_listeners([("0.0.0.0", 54321, "myapp")]) == []


def test_duplicate_port_reported_once():
    f = evaluate_listeners([("0.0.0.0", 23, "a"), ("0.0.0.0", 23, "b")])
    assert len(f) == 1


def test_risky_listeners_table_has_expected_entries():
    for port in (2375, 23, 6379, 27017, 5900):
        assert port in RISKY_LISTENERS


# --------------------------------------------------------------------------- #
# IPv6
# --------------------------------------------------------------------------- #


def test_ipv6_absent_is_info_only():
    f = evaluate_ipv6(0, 0)
    assert f[0].severity == SEV_INFO
    assert not f[0].is_problem


def test_ipv6_link_local_only_is_medium():
    """Eng ko'p uchraydigan real holat: SLAAC manzil bor, global marshrut yo'q."""
    f = evaluate_ipv6(46, 0)
    assert f[0].severity == SEV_MEDIUM
    assert "link-local" in f[0].title


def test_ipv6_global_present_no_finding():
    assert evaluate_ipv6(5, 3) == []


def test_ipv6_blackhole_is_high():
    f = evaluate_ipv6(5, 3, has_ipv6_internet=False)
    assert any(x.severity == SEV_HIGH for x in f)


# --------------------------------------------------------------------------- #
# LAN anomaliyalari
# --------------------------------------------------------------------------- #


def test_duplicate_mac_on_gateway_is_high():
    hosts = [("192.168.1.1", "aa:bb:cc:dd:ee:ff", True),
             ("192.168.1.50", "aa:bb:cc:dd:ee:ff", False)]
    f = evaluate_lan(hosts, "192.168.1.1")
    assert f[0].severity == SEV_HIGH
    assert "spoofing" in f[0].detail


def test_duplicate_mac_non_gateway_is_medium():
    hosts = [("192.168.1.20", "aa:bb:cc:dd:ee:ff", False),
             ("192.168.1.50", "aa:bb:cc:dd:ee:ff", False)]
    f = evaluate_lan(hosts, "192.168.1.1")
    assert f[0].severity == SEV_MEDIUM


def test_unique_macs_no_finding():
    hosts = [("192.168.1.1", "aa:bb:cc:dd:ee:01", True),
             ("192.168.1.2", "aa:bb:cc:dd:ee:02", False)]
    assert evaluate_lan(hosts, "192.168.1.1") == []


def test_hosts_without_mac_ignored():
    assert evaluate_lan([("192.168.1.1", None, True), ("192.168.1.2", None, False)]) == []


# --------------------------------------------------------------------------- #
# web / admin panel
# --------------------------------------------------------------------------- #


def test_http_basic_auth_admin_is_high():
    f = evaluate_web([("192.168.1.1", 80, "http", True, "high", "MikroTik")])
    assert f[0].severity == SEV_HIGH
    assert "ochiq matnda" in f[0].title


def test_http_form_admin_is_medium():
    f = evaluate_web([("192.168.1.1", 80, "http", True, "medium", "Grafana")])
    assert f[0].severity == SEV_MEDIUM


def test_https_admin_no_finding():
    assert evaluate_web([("192.168.1.1", 443, "https", True, "low", "Kerio Control")]) == []


def test_non_admin_service_ignored():
    assert evaluate_web([("192.168.1.9", 80, "http", False, "none", "Nginx")]) == []


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def test_system_dns_broken_is_critical():
    f = evaluate_dns(False, "resolve xatosi", [])
    assert f[0].severity == SEV_CRITICAL


def test_all_resolvers_dead_is_high():
    f = evaluate_dns(True, None, [("1.1.1.1", False, 0), ("8.8.8.8", False, 0)])
    assert any(x.severity == SEV_HIGH for x in f)


def test_some_resolvers_dead_is_low():
    f = evaluate_dns(True, None, [("1.1.1.1", True, 20), ("8.8.8.8", False, 0)])
    assert any(x.severity == SEV_LOW for x in f)


def test_slow_resolver_flagged():
    f = evaluate_dns(True, None, [("1.1.1.1", True, 900)])
    assert any("sekin" in x.title for x in f)


def test_healthy_dns_no_findings():
    assert evaluate_dns(True, None, [("1.1.1.1", True, 20)]) == []


# --- tizim resolveri vs ommaviy: jiddiylik shunga bog'liq ------------------


def test_tizim_resolveri_olik_high():
    """Mashina sozlangan resolver javob bermasa — har doim haqiqiy nosozlik."""
    f = evaluate_dns(True, None, [
        ("192.168.1.1", False, 0, True),
        ("8.8.8.8", True, 30, False),
    ])
    hi = [x for x in f if x.severity == SEV_HIGH]
    assert len(hi) == 1
    assert "Tizim DNS" in hi[0].title
    assert hi[0].evidence["scope"] == "system"


def test_tashqi_dns_yopiq_muammo_emas():
    """SOXTA POZITIV REGRESSIYASI.

    Korporativ tarmoqda tashqi 53-port ataylab yopiladi. Ilgari bu holat
    "Barcha DNS serverlar javob bermayapti" degan HIGH va exit 2 berardi —
    butunlay sog'lom tarmoqda. Endi INFO: is_problem False, exit kodga
    ta'sir qilmaydi.
    """
    f = evaluate_dns(True, None, [
        ("192.168.1.1", True, 12, True),
        ("8.8.8.8", False, 0, False),
        ("1.1.1.1", False, 0, False),
    ])
    assert not any(x.is_problem for x in f)
    info = [x for x in f if x.severity == SEV_INFO]
    assert len(info) == 1
    assert "Tashqi DNS" in info[0].title
    assert info[0].fix is None  # "firewall'ni tekshiring" NOTO'G'RI tavsiya edi


def test_tizim_aniqlanmagan_bolsa_eski_xulosa_saqlanadi():
    """Tizim resolveri topilmasa ehtiyotkor bo'lamiz — eski HIGH qoladi."""
    f = evaluate_dns(True, None, [("1.1.1.1", False, 0, False), ("8.8.8.8", False, 0, False)])
    hi = [x for x in f if x.severity == SEV_HIGH]
    assert len(hi) == 1
    assert "Barcha DNS" in hi[0].title


def test_uchlik_ham_qabul_qilinadi():
    """Eski 3-lik chaqiruv yiqilmasligi kerak (is_system=False deb olinadi)."""
    assert evaluate_dns(True, None, [("1.1.1.1", True, 20)]) == []
    f = evaluate_dns(True, None, [("1.1.1.1", False, 0)])
    assert any(x.severity == SEV_HIGH for x in f)


def test_sekinlik_tizim_resolveri_boyicha_olchanadi():
    """Ommaviy server 900 ms — normal masofa. Tizim resolveri 900 ms — muammo.

    Aralashtirsak, uzoqdagi OpenDNS har doim "DNS sekin" deb belgilanardi.
    """
    faqat_ommaviy_sekin = evaluate_dns(True, None, [
        ("192.168.1.1", True, 12, True),
        ("208.67.222.222", True, 900, False),
    ])
    assert not any("sekin" in x.title for x in faqat_ommaviy_sekin)

    tizim_sekin = evaluate_dns(True, None, [
        ("192.168.1.1", True, 900, True),
        ("8.8.8.8", True, 30, False),
    ])
    assert any("sekin" in x.title for x in tizim_sekin)


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def test_expired_cert_is_critical():
    f = evaluate_tls("example.com", -3)
    assert f[0].severity == SEV_CRITICAL


def test_expiring_soon_is_medium():
    f = evaluate_tls("example.com", 7)
    assert f[0].severity == SEV_MEDIUM


def test_valid_cert_no_finding():
    assert evaluate_tls("example.com", 90) == []


def test_tls_error_is_high():
    f = evaluate_tls("example.com", None, error="ulanib bo'lmadi")
    assert f[0].severity == SEV_HIGH


# --------------------------------------------------------------------------- #
# boshqaruvchi qurilma + saralash + Report
# --------------------------------------------------------------------------- #


def test_management_device_kinds():
    assert is_management_device("firewall")
    assert is_management_device("router")
    assert is_management_device("kamera/NVR")
    assert not is_management_device("printer")
    assert not is_management_device(None)


def test_gateway_is_always_management():
    assert is_management_device(None, is_gateway=True)
    assert is_management_device("printer", is_gateway=True)


def test_sort_findings_critical_first():
    fs = [
        Finding(SEV_LOW, "a", "low", ""),
        Finding(SEV_CRITICAL, "a", "crit", ""),
        Finding(SEV_MEDIUM, "a", "med", ""),
    ]
    assert [f.title for f in sort_findings(fs)] == ["crit", "med", "low"]


def test_report_worst_severity_ignores_info():
    r = Report(findings=[Finding(SEV_INFO, "a", "i", ""), Finding(SEV_MEDIUM, "a", "m", "")])
    assert r.worst_severity == SEV_MEDIUM
    assert len(r.problems) == 1


def test_report_no_problems_worst_is_none():
    assert Report(findings=[Finding(SEV_INFO, "a", "i", "")]).worst_severity is None


def test_report_counts():
    r = Report(findings=[Finding(SEV_HIGH, "a", "1", ""), Finding(SEV_HIGH, "a", "2", "")])
    assert r.counts[SEV_HIGH] == 2


# --------------------------------------------------------------------------- #
# Wi-Fi / link tezligi / MAC filtri (0.7.0)
# --------------------------------------------------------------------------- #

from systop.core.diagnose import (  # noqa: E402
    evaluate_link_speed,
    evaluate_wifi,
    is_real_device_mac,
)


def _wifi(**kw):
    base = dict(
        available=True, connected=True, rssi=-45, snr=40, band="5GHz", channel=36,
        width_mhz=80, phy_gen="ax", card_gen="ax", tx_rate=800.0,
        security="WPA2 Personal", five_ghz_available=True, overlap_count=0,
    )
    base.update(kw)
    return evaluate_wifi(**base)


def test_wifi_no_hardware_returns_nothing():
    """Wi-Fi apparati yo'q serverda ogohlantirish BO'LMASLIGI shart."""
    assert _wifi(available=False) == []


def test_wifi_not_connected_returns_nothing():
    assert _wifi(connected=False) == []


def test_wifi_healthy_returns_nothing():
    assert _wifi() == []


def test_wifi_very_weak_signal_is_critical():
    f = _wifi(rssi=-85)
    assert any(x.severity == SEV_CRITICAL for x in f)


def test_wifi_weak_signal_is_medium():
    f = _wifi(rssi=-75)
    assert any(x.severity == SEV_MEDIUM and "zaif" in x.title for x in f)


def test_wifi_low_snr_is_high():
    f = _wifi(snr=10)
    assert any(x.severity == SEV_HIGH and "shovqin" in x.title for x in f)


def test_wifi_24ghz_with_5ghz_available_flagged():
    f = _wifi(band="2.4GHz", channel=6)
    assert any("2.4 GHz da ulangan" in x.title for x in f)


def test_wifi_24ghz_without_5ghz_not_flagged():
    """5 GHz mavjud bo'lmasa 2.4 GHz da bo'lish muammo emas."""
    f = _wifi(band="2.4GHz", channel=6, five_ghz_available=False)
    assert not any("2.4 GHz da ulangan" in x.title for x in f)


def test_wifi_channel_congestion_scales_with_count():
    med = _wifi(band="2.4GHz", channel=6, overlap_count=4)
    high = _wifi(band="2.4GHz", channel=6, overlap_count=7)
    assert any(x.severity == SEV_MEDIUM and "tiqilinch" in x.title for x in med)
    assert any(x.severity == SEV_HIGH and "tiqilinch" in x.title for x in high)


def test_wifi_low_congestion_not_flagged():
    assert not any("tiqilinch" in x.title for x in _wifi(band="2.4GHz", channel=6, overlap_count=2))


def test_wifi_nonstandard_24ghz_channel():
    f = _wifi(band="2.4GHz", channel=3, five_ghz_available=False)
    assert any("nostandart kanal" in x.title for x in f)


def test_wifi_standard_channels_not_flagged():
    for ch in (1, 6, 11):
        f = _wifi(band="2.4GHz", channel=ch, five_ghz_available=False)
        assert not any("nostandart" in x.title for x in f), ch


def test_wifi_phy_below_card_capability():
    f = _wifi(phy_gen="n", card_gen="ax")
    assert any("karta ax" in x.title for x in f)


def test_wifi_phy_matching_card_not_flagged():
    assert not any("karta" in x.title for x in _wifi(phy_gen="ax", card_gen="ax"))


def test_wifi_wep_is_critical():
    f = _wifi(security="WEP")
    assert any(x.severity == SEV_CRITICAL and "WEP" in x.title for x in f)


def test_wifi_open_network_is_high():
    f = _wifi(security="None")
    assert any(x.severity == SEV_HIGH and "ochiq" in x.title for x in f)


def test_wifi_narrow_5ghz_channel_flagged():
    f = _wifi(band="5GHz", width_mhz=20)
    assert any("tor kanal" in x.title for x in f)


# --- link tezligi ---------------------------------------------------------- #


def test_link_speed_gigabit_not_flagged():
    assert evaluate_link_speed("en0", 1000, True) == []


def test_link_speed_100mbps_is_medium():
    f = evaluate_link_speed("en0", 100, True)
    assert f[0].severity == SEV_MEDIUM
    assert "100 Mbps" in f[0].title


def test_link_speed_10mbps_is_high():
    assert evaluate_link_speed("en0", 10, True)[0].severity == SEV_HIGH


def test_link_speed_virtual_interface_skipped():
    """utun/awdl kabi virtual interfeyslarda 'tezlik' ma'nosiz."""
    assert evaluate_link_speed("utun0", 100, True, is_virtual=True) == []


def test_link_speed_down_interface_skipped():
    assert evaluate_link_speed("en1", 100, False) == []


def test_link_speed_unknown_speed_skipped():
    assert evaluate_link_speed("en0", 0, True) == []


# --- MAC filtri ------------------------------------------------------------ #


def test_broadcast_mac_is_not_a_device():
    assert is_real_device_mac("ff:ff:ff:ff:ff:ff") is False


def test_ipv4_multicast_mac_is_not_a_device():
    assert is_real_device_mac("01:00:5e:00:00:fb") is False


def test_ipv6_multicast_mac_is_not_a_device():
    assert is_real_device_mac("33:33:00:00:00:01") is False


def test_unicast_mac_is_a_device():
    assert is_real_device_mac("00:15:5d:27:40:03") is True


def test_malformed_mac_is_not_a_device():
    assert is_real_device_mac("nonsense") is False
    assert is_real_device_mac(None) is False


def test_duplicate_detection_ignores_broadcast():
    """Broadcast MAC ko'p IP'da bo'lishi normal — dublikat deb belgilanmasin."""
    hosts = [("192.168.1.1", "ff:ff:ff:ff:ff:ff", False),
             ("192.168.1.2", "ff:ff:ff:ff:ff:ff", False)]
    assert evaluate_lan(hosts, "192.168.1.254") == []


# --------------------------------------------------------------------------- #
# Adaptiv chegaralar (0.8.0) — bitta raqam har tarmoqda to'g'ri bo'lolmaydi
# --------------------------------------------------------------------------- #

from systop.core.diagnose import (  # noqa: E402
    LINK_CELLULAR,
    LINK_UNKNOWN,
    LINK_VPN,
    LINK_WIFI,
    LINK_WIRED,
    classify_link,
    thresholds_for_link,
)


def test_classify_wifi_by_state_not_name():
    """macOS'da Wi-Fi ham `en0` — nomdan emas, holatdan aniqlanishi kerak."""
    assert classify_link("en0", wifi_connected=True, wifi_interface="en0") == LINK_WIFI


def test_classify_same_name_wired_when_not_wifi():
    assert classify_link("en0", wifi_connected=False) == LINK_WIRED


def test_classify_by_prefix():
    assert classify_link("wlan0") == LINK_WIFI
    assert classify_link("eth0") == LINK_WIRED
    assert classify_link("utun3") == LINK_VPN
    assert classify_link("wg0") == LINK_VPN
    assert classify_link("rmnet0") == LINK_CELLULAR


def test_classify_unknown_interface():
    assert classify_link("weird9") == LINK_UNKNOWN
    assert classify_link(None) == LINK_UNKNOWN


def test_wired_thresholds_are_strictest():
    """Kabelda 50 ms falokat, Wi-Fi'da normal — chegaralar shuni aks ettirsin."""
    wired = thresholds_for_link(LINK_WIRED)
    wifi = thresholds_for_link(LINK_WIFI)
    cell = thresholds_for_link(LINK_CELLULAR)
    assert wired.gateway_rtt_ms < wifi.gateway_rtt_ms < cell.gateway_rtt_ms
    assert wired.jitter_ms < wifi.jitter_ms < cell.jitter_ms
    assert wired.loss_high_pct < wifi.loss_high_pct


def test_same_rtt_judged_differently_per_link():
    """Xuddi shu 30 ms kabelda muammo, Wi-Fi'da emas."""
    wired = evaluate_ping("GW", "10.0.0.1", True, 0, 30.0, 0, is_lan=True,
                          th=thresholds_for_link(LINK_WIRED))
    wifi = evaluate_ping("GW", "10.0.0.1", True, 0, 30.0, 0, is_lan=True,
                         th=thresholds_for_link(LINK_WIFI))
    assert any("kechikish" in f.title for f in wired)
    assert wifi == []


def test_user_config_overrides_link_profile():
    """Qo'lda qo'yilgan qiymat avtomatik moslashuvdan USTUN turishi kerak."""
    user = Thresholds(gateway_rtt_ms=999.0)
    assert thresholds_for_link(LINK_WIRED, user).gateway_rtt_ms == 999.0


def test_unset_config_fields_take_profile_value():
    user = Thresholds()  # hammasi default
    assert thresholds_for_link(LINK_WIRED, user).gateway_rtt_ms == 5.0


def test_unknown_profile_is_lenient_not_strict():
    """Noma'lum tarmoqda qattiq chegara soxta ogohlantirish beradi."""
    unk = thresholds_for_link(LINK_UNKNOWN)
    assert unk.gateway_rtt_ms > thresholds_for_link(LINK_WIRED).gateway_rtt_ms


# --------------------------------------------------------------------------- #
# Masofaviy vs lokal ekspozitsiya (0.9.0) — noto'g'ri ayblashning oldini olish
# --------------------------------------------------------------------------- #

from systop.core.diagnose import evaluate_remote_exposure  # noqa: E402


def test_remote_exposure_says_other_devices_not_yours():
    """Qo'shni qurilmaning ochiq porti 'sizning xizmatingiz' deb aytilmasin."""
    f = evaluate_remote_exposure([("192.168.1.50", 2375)])
    assert len(f) == 1
    assert "BOSHQA" in f[0].detail
    assert "localhost" not in (f[0].fix or "")


def test_remote_exposure_severity_is_lowered():
    """Masofaviy topilma lokalidan bir daraja past: bu sizning hostingiz emas."""
    local = evaluate_listeners([("0.0.0.0", 2375, "dockerd")])
    remote = evaluate_remote_exposure([("192.168.1.50", 2375)])
    assert local[0].severity == SEV_CRITICAL
    assert remote[0].severity == SEV_HIGH


def test_remote_exposure_groups_hosts_by_port():
    f = evaluate_remote_exposure([
        ("10.0.0.1", 23), ("10.0.0.2", 23), ("10.0.0.3", 6379),
    ])
    assert len(f) == 2
    telnet = next(x for x in f if "23" in x.title)
    assert "2 ta host" in telnet.title


def test_remote_exposure_ignores_unknown_ports():
    assert evaluate_remote_exposure([("10.0.0.1", 54321)]) == []


def test_remote_exposure_empty():
    assert evaluate_remote_exposure([]) == []
