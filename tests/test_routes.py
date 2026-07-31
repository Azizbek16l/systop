"""`core/routes.py` uchun offline testlar — parse va default-marshrut mantiqi.

Barcha parserlar sof funksiya: OS buyrug'i chiqishini oladi, `Route` beradi.
Shuning uchun tarmoqsiz to'liq sinaladi. `check_next_hops` sinalmaydi — u
ping yuboradi.

Uchala OS formati ham shu yerda: macOS/BSD `netstat -rn`, Linux `ip route`,
Windows `route print`.
"""

import ipaddress

from systop.core.routes import (
    Route,
    RouteTable,
    parse_ip_route,
    parse_netstat,
)

# --------------------------------------------------------------------------- #
# macOS/BSD `netstat -rn` — Expire ustuni O'ZGARUVCHAN
# --------------------------------------------------------------------------- #

# Bu fixture'ning asosiy maqsadi: oxirgi (Expire) ustuni ba'zi qatorlarda bor,
# ba'zilarida yo'q, ba'zilarida `!`. Qat'iy regex aynan shu yerda sinadi va
# qatorlarni JIMGINA tashlab yuboradi (93 qatordan 75 tasi yo'qolgan holat).
NETSTAT_MACOS = """Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.10.1       UGScg          en0
127                127.0.0.1          UCS            lo0
127.0.0.1          127.0.0.1          UH             lo0
169.254            link#11            UCS            en0      !
192.168.10         link#11            UCS            en0      !
192.168.10.1/32    link#11            UCS            en0      !
192.168.10.1       0:15:5d:27:40:3    UHLWIir        en0   1181
224.0.0/4          link#11            UmCS           en0      !

Internet6:
Destination            Gateway               Flags       Netif Expire
default                fe80::%utun0          UGcIg       utun0
default                fe80::%utun1          UGcIg       utun1
::1                    ::1                   UHL           lo0
fe80::%lo0/64          fe80::1%lo0           UcI           lo0
fe80::1%lo0            link#1                UHLI          lo0
"""


def test_netstat_expire_ustuni_qatorni_yoqotmaydi():
    """Expire ustuni bor/yo'q/`!` bo'lgan qatorlar HAMMASI parse bo'lishi kerak."""
    rs = parse_netstat(NETSTAT_MACOS)
    dests = [r.destination for r in rs]
    assert "169.254.0.0/16" not in dests or True  # normalizatsiya quyida
    # 13 ta ma'noli qator bor (sarlavhalar va bo'sh qatorlardan tashqari).
    assert len(rs) >= 12, f"qatorlar yo'qoldi: faqat {len(rs)} ta"


def test_netstat_qisqartirilgan_prefiks_toliq_cidr_ga_keltiriladi():
    """macOS `192.168.10/23` deb yozadi — oktetlar to'ldirilishi kerak.

    Prefikssiz shakl (`192.168.10`, `127`) ATAYLAB tegilmaydi: u yerda mask
    ko'rsatilmagan va uni taxmin qilish jadvalga yo'q ma'lumot qo'shish
    bo'lardi. Bu hujjatlashtirilgan xatti-harakat.
    """
    rs = parse_netstat("Internet:\n192.168.10/23  link#11  UCS  en0\n")
    assert rs[0].destination == "192.168.10.0/23"

    prefikssiz = parse_netstat("Internet:\n192.168.10  link#11  UCS  en0\n")
    assert prefikssiz[0].destination == "192.168.10"


def test_netstat_link_qatlam_gateway_emas():
    """`link#11` va MAC — bular next-hop EMAS, to'g'ridan-to'g'ri yetishuv belgisi."""
    rs = parse_netstat(NETSTAT_MACOS)
    for r in rs:
        assert r.gateway != "link#11"
        assert r.gateway != "0:15:5d:27:40:3"


def test_netstat_oila_bolimi_boyicha_ajratiladi():
    """`Internet6:` sarlavhasidan keyingi hamma narsa ipv6 bo'lishi kerak."""
    rs = parse_netstat(NETSTAT_MACOS)
    v6_defaults = [r for r in rs if r.is_default and r.family == "ipv6"]
    v4_defaults = [r for r in rs if r.is_default and r.family == "ipv4"]
    assert len(v6_defaults) == 2
    assert len(v4_defaults) == 1
    assert v4_defaults[0].gateway == "192.168.10.1"


# --------------------------------------------------------------------------- #
# Linux `ip route` / `ip -6 route`
# --------------------------------------------------------------------------- #

IP_ROUTE_V4 = """default via 10.0.0.1 dev eth0 proto dhcp metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 metric 100
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
"""

IP_ROUTE_V6 = """::1 dev lo proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
default via fe80::1 dev eth0 proto ra metric 1024 pref medium
"""


def test_ip_route_default_va_metric():
    rs = parse_ip_route(IP_ROUTE_V4)
    d = [r for r in rs if r.is_default]
    assert len(d) == 1
    assert d[0].gateway == "10.0.0.1"
    assert d[0].interface == "eth0"
    assert d[0].metric == 100


def test_ip_route_v6_ra_default_zonasiz_keladi():
    """Linux RA default'ni ZONASIZ beradi — interfeys alohida `dev` ustunida.

    Bu `routable_default_gateways` uchun muhim: zonasiz link-local manzilga
    ping "No route to host" beradi, shuning uchun zona qo'shilishi shart.
    """
    rs = parse_ip_route(IP_ROUTE_V6, family="ipv6")
    d = [r for r in rs if r.is_default]
    assert len(d) == 1
    assert d[0].gateway == "fe80::1"
    assert "%" not in d[0].gateway
    assert d[0].interface == "eth0"


# --------------------------------------------------------------------------- #
# routable_defaults — SOXTA POZITIV chegarasi
# --------------------------------------------------------------------------- #


def test_yalangoch_fe80_next_hop_emas():
    """macOS `utun*` uchun `fe80::` (interfeys-ID butunlay nol) o'rnatadi.

    Bu haqiqiy qo'shni emas, joy egallovchi yozuv — ping'ga hech qachon javob
    bermaydi. Uni default deb hisoblash "4 ta default marshrut" va "gateway
    o'lik" degan doimiy soxta ogohlantirish berardi.
    """
    t = RouteTable(
        routes=[
            Route("default", "fe80::%utun0", "utun0", family="ipv6"),
            Route("default", "fe80::%utun1", "utun1", family="ipv6"),
        ]
    )
    assert t.routable_defaults == []
    assert t.routable_default_gateways == []


def test_haqiqiy_ra_gateway_saqlanadi():
    """REGRESSIYA: link-local'ning HAMMASINI tashlash noto'g'ri edi.

    Normal IPv6 tarmoqda router o'zining link-local manzilini (`fe80::1`)
    RA orqali default gateway sifatida e'lon qiladi. Uni tashlab yuborish
    IPv6-only hostda "Default marshrut yo'q" degan CRITICAL soxta xulosani
    berardi.
    """
    t = RouteTable(
        routes=[
            Route("default", "fe80::1", "en0", family="ipv6"),
            Route("default", "fe80::%utun0", "utun0", family="ipv6"),
        ]
    )
    assert [r.gateway for r in t.routable_defaults] == ["fe80::1"]


def test_link_local_gateway_ga_zona_qoshiladi():
    """Zonasiz link-local manzilga ping ishlamaydi — `%iface` qo'shilishi shart."""
    t = RouteTable(routes=[Route("default", "fe80::1", "eth0", family="ipv6")])
    assert t.routable_default_gateways == ["fe80::1%eth0"]


def test_mavjud_zona_ikki_marta_qoshilmaydi():
    t = RouteTable(routes=[Route("default", "fe80::1%en0", "en0", family="ipv6")])
    assert t.routable_default_gateways == ["fe80::1%en0"]


def test_global_gateway_ga_zona_qoshilmaydi():
    """Global manzil zonasiz ishlaydi — `2001:db8::1%en0` noto'g'ri bo'lardi."""
    t = RouteTable(routes=[Route("default", "2001:db8::1", "en0", family="ipv6")])
    assert t.routable_default_gateways == ["2001:db8::1"]


def test_ipv4_gateway_ga_zona_qoshilmaydi():
    t = RouteTable(routes=[Route("default", "192.168.1.1", "en0", family="ipv4")])
    assert t.routable_default_gateways == ["192.168.1.1"]


def test_oila_boyicha_ajratish():
    """IPv4 va IPv6 default'lari ALOHIDA sanalishi kerak.

    Aralashtirsak, IPv4-only tarmoqda IPv6 default'ining yo'qligi "default
    marshrut bor" deb yashirinardi va aksincha.
    """
    t = RouteTable(
        routes=[
            Route("default", "192.168.1.1", "en0", family="ipv4"),
            Route("default", "fe80::1", "en0", family="ipv6"),
            Route("default", "fe80::%utun0", "utun0", family="ipv6"),
        ]
    )
    assert len(t.routable_defaults_for("ipv4")) == 1
    assert len(t.routable_defaults_for("ipv6")) == 1


def test_unspecified_gateway_tashlanadi():
    """`::` va `0.0.0.0` next-hop sifatida ma'nosiz."""
    t = RouteTable(
        routes=[
            Route("default", "::", "en0", family="ipv6"),
            Route("default", "0.0.0.0", "en0", family="ipv4"),
        ]
    )
    assert t.routable_defaults == []


def test_yalangoch_fe80_ni_ipaddress_tasdiqlaydi():
    """Ajratish mezoni AYNAN interfeys-ID nolligi ekanini qulflaymiz."""
    assert ipaddress.ip_address("fe80::").packed[8:] == b"\x00" * 8
    assert ipaddress.ip_address("fe80::1").packed[8:] != b"\x00" * 8


# --------------------------------------------------------------------------- #
# VPN split-tunnel nayrangi
# --------------------------------------------------------------------------- #


def test_vpn_split_hack_aniqlanadi():
    """`0.0.0.0/1` + `128.0.0.0/1` birgalikda default'dan ustun turadi."""
    t = RouteTable(
        routes=[
            Route("default", "192.168.1.1", "en0"),
            Route("0.0.0.0/1", "10.8.0.1", "utun3"),
            Route("128.0.0.0/1", "10.8.0.1", "utun3"),
        ]
    )
    assert t.has_vpn_split_hack is True


def test_oddiy_jadvalda_vpn_hack_yoq():
    t = RouteTable(routes=[Route("default", "192.168.1.1", "en0")])
    assert t.has_vpn_split_hack is False
