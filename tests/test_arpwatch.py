"""`core/arpwatch.py` uchun offline testlar — ARP/NDP o'zgarish kuzatuvi.

`diff_snapshots` sof funksiya: ikki `{ip: mac}` lug'atini oladi, o'zgarishlar
ro'yxatini beradi. Baseline o'qish/yozish vaqtinchalik katalogda sinaladi.

Bu modulning tarixi soxta pozitivlardan iborat, shuning uchun testlarning
ko'pchiligi "bu o'zgarish EMAS" shaklida. Bitta doimiy soxta "ARP spoofing"
ogohlantirishi butun toolga ishonchni yo'q qiladi — sysadmin hisobotni
o'qishni umuman to'xtatadi.
"""

import json

from systop.core.arpwatch import (
    ArpChange,
    ArpDiff,
    _address_scope,
    diff_snapshots,
    load_baseline,
    save_baseline,
)

# To'liq 6-oktetli MAC'lar SHART: `is_real_device_mac` qisqartmani
# ("aa:bb") rad etadi, shuning uchun qisqa MAC bilan yozilgan dublikat
# testi JIMGINA bo'sh o'tib ketardi.
MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"


# --------------------------------------------------------------------------- #
# Haqiqiy o'zgarishlar — BU ISHLASHI kerak
# --------------------------------------------------------------------------- #


def test_mac_almashishi_yuqori_jiddiylik():
    """Gateway IP'sining MAC'i almashdi — klassik ARP spoofing/MITM alomati."""
    ch = diff_snapshots({"192.168.1.1": MAC_A}, {"192.168.1.1": MAC_B})
    assert len(ch) == 1
    assert ch[0].kind == "mac_changed"
    assert ch[0].severity == "high"
    assert ch[0].old_mac == MAC_A
    assert ch[0].new_mac == MAC_B


def test_yangi_host_past_jiddiylik():
    ch = diff_snapshots({}, {"192.168.1.5": MAC_A})
    assert ch[0].kind == "new_host"
    assert ch[0].severity == "low"


def test_yoqolgan_host_ogohlantirish_emas():
    """Qurilma o'chirilgan bo'lishi mumkin — bu normal, `info`."""
    ch = diff_snapshots({"192.168.1.5": MAC_A}, {})
    assert ch[0].kind == "disappeared"
    assert ch[0].severity == "info"


def test_haqiqiy_dublikat_mac_aniqlanadi():
    """Bir MAC ikki xil IPv4 manzilda — IP dublikati yoki spoofing."""
    ch = diff_snapshots({}, {"192.168.1.5": MAC_A, "192.168.1.9": MAC_A})
    dup = [c for c in ch if c.kind == "duplicate_mac"]
    assert len(dup) == 1
    assert dup[0].new_mac == MAC_A
    assert set([dup[0].ip, *dup[0].extra_ips]) == {"192.168.1.5", "192.168.1.9"}


def test_ozgarishsiz_holat_bosh():
    snap = {"192.168.1.1": MAC_A, "192.168.1.5": MAC_B}
    assert diff_snapshots(snap, dict(snap)) == []


# --------------------------------------------------------------------------- #
# SOXTA POZITIVLAR — bular o'zgarish deb belgilanmasligi kerak
# --------------------------------------------------------------------------- #


def test_broadcast_mac_dublikat_emas():
    """`ff:ff:ff:ff:ff:ff` tabiiy ravishda ko'p IP bilan bog'lanadi."""
    ch = diff_snapshots(
        {},
        {
            "192.168.1.255": "ff:ff:ff:ff:ff:ff",
            "10.0.0.255": "ff:ff:ff:ff:ff:ff",
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_multicast_mac_dublikat_emas():
    """I/G biti o'rnatilgan MAC (`01:00:5e:...`) — multicast, qurilma emas."""
    ch = diff_snapshots(
        {},
        {
            "224.0.0.251": "01:00:5e:00:00:fb",
            "224.0.0.252": "01:00:5e:00:00:fc",
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_ipv4_va_ipv6_bir_qurilmada_dublikat_emas():
    """SOXTA POZITIV REGRESSIYASI — dastlab 34 ta ogohlantirish bergan holat.

    Bitta qurilmada IPv4 va IPv6 manzil bir vaqtda bo'lishi va ikkalasining
    MAC'i bir xil bo'lishi BUTUNLAY NORMAL. Taqqoslash faqat bir oila ichida
    bo'lishi kerak.
    """
    ch = diff_snapshots(
        {},
        {
            "192.168.1.5": MAC_A,
            "2001:db8::5": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_link_local_va_global_v6_dublikat_emas():
    """Bir NIC'da `fe80::` va global IPv6 birga bo'ladi — doira bo'yicha ajratiladi."""
    ch = diff_snapshots(
        {},
        {
            "fe80::5": MAC_A,
            "2001:db8::5": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_apipa_va_dhcp_manzili_dublikat_emas():
    """169.254.x (APIPA) va DHCP manzili bir NIC'da bir vaqtda bo'lishi mumkin."""
    ch = diff_snapshots(
        {},
        {
            "169.254.10.5": MAC_A,
            "192.168.1.5": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_bir_manzil_turli_zonada_dublikat_emas():
    """macOS'da `awdl0` va `llw0` bir MAC va bir `fe80::` manzilni bo'lishadi.

    Faqat zona farq qiladi. Zonani hisobga olmasak, har ishga tushirishda
    DOIMIY "bir MAC ikki IP'da" ogohlantirishi chiqardi — spoofing detektori
    o'zini ayblab turardi.
    """
    ch = diff_snapshots(
        {},
        {
            "fe80::1c9d:5eff:fe00:1%awdl0": MAC_A,
            "fe80::1c9d:5eff:fe00:1%llw0": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_turli_link_local_manzil_dublikat_boladi():
    """Zona farqi emas, MANZIL farqi bo'lsa — bu haqiqiy dublikat."""
    ch = diff_snapshots(
        {},
        {
            "fe80::1%en0": MAC_A,
            "fe80::2%en0": MAC_A,
        },
    )
    assert len([c for c in ch if c.kind == "duplicate_mac"]) == 1


# --------------------------------------------------------------------------- #
# Manzil doirasi
# --------------------------------------------------------------------------- #


def test_manzil_doirasi_ajratiladi():
    assert _address_scope("192.168.1.1") == "ipv4"
    assert _address_scope("169.254.1.1") == "apipa"
    assert _address_scope("2001:db8::1") == "ipv6"
    assert _address_scope("fe80::1") == "link-local"
    assert _address_scope("fe80::1%en0") == "link-local"


# --------------------------------------------------------------------------- #
# Tartib va vendor
# --------------------------------------------------------------------------- #


def test_jiddiyroq_ozgarish_yuqorida():
    ch = diff_snapshots(
        {"192.168.1.1": MAC_A, "192.168.1.9": MAC_A},
        {"192.168.1.1": MAC_B, "192.168.1.20": MAC_B},
    )
    assert ch[0].kind == "mac_changed"


def test_vendor_qidiruvi_ulanadi():
    """Vendor almashishi ("Hikvision -> Apple") xom MAC'dan ancha ma'noli."""
    ch = diff_snapshots(
        {"192.168.1.1": MAC_A},
        {"192.168.1.1": MAC_B},
        vendor_lookup=lambda m: "Hikvision" if m == MAC_A else "Apple",
    )
    assert ch[0].old_vendor == "Hikvision"
    assert ch[0].new_vendor == "Apple"


def test_has_suspicious_faqat_jiddiylarda():
    assert ArpDiff(changes=[ArpChange(kind="new_host", ip="1.1.1.1")]).has_suspicious is False
    assert ArpDiff(changes=[ArpChange(kind="mac_changed", ip="1.1.1.1")]).has_suspicious is True
    assert ArpDiff(changes=[ArpChange(kind="duplicate_mac", ip="1.1.1.1")]).has_suspicious is True


# --------------------------------------------------------------------------- #
# Baseline saqlash/o'qish
# --------------------------------------------------------------------------- #


def test_baseline_yozib_oqiladi(tmp_path):
    p = tmp_path / "baseline.json"
    snap = {"192.168.1.1": MAC_A}
    assert save_baseline(snap, p) is True
    got, saved_at = load_baseline(p)
    assert got == snap
    assert saved_at is not None


def test_baseline_yoq_fayl_bosh():
    got, saved_at = load_baseline(__import__("pathlib").Path("/yo/q/fayl.json"))
    assert got == {} and saved_at is None


def test_buzuq_baseline_soxta_spoofing_yasamaydi(tmp_path):
    """MUHIM: `errors="replace"` ATAYLAB ishlatilmaydi.

    U buzuq faylni `{"10.0.0.1": "\\ufffd\\ufffd"}` ga aylantiradi — natijada
    keyingi ishga tushirishda MAC "o'zgargan" bo'lib ko'rinib, disk
    buzilishidan SEV_HIGH "ARP spoofing (MITM)" ogohlantirishi yasalardi.
    """
    p = tmp_path / "baseline.json"
    p.write_bytes(b'{"hosts": {"10.0.0.1": "\xff\xfe"}}')
    got, saved_at = load_baseline(p)
    assert got == {}
    assert saved_at is None


def test_notogri_json_bosh_qaytaradi(tmp_path):
    p = tmp_path / "baseline.json"
    p.write_text("bu json emas", encoding="utf-8")
    assert load_baseline(p) == ({}, None)


def test_notogri_shakldagi_json_bosh(tmp_path):
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(["royxat", "lugat emas"]), encoding="utf-8")
    assert load_baseline(p) == ({}, None)
    p.write_text(json.dumps({"hosts": "lugat emas"}), encoding="utf-8")
    assert load_baseline(p) == ({}, None)


def test_baseline_atomik_yoziladi(tmp_path):
    """Yarim yozilgan fayl eski baseline'ni yo'qotmasligi kerak."""
    p = tmp_path / "baseline.json"
    save_baseline({"192.168.1.1": MAC_A}, p)
    save_baseline({"192.168.1.2": MAC_B}, p)
    got, _ = load_baseline(p)
    assert got == {"192.168.1.2": MAC_B}
    assert not (tmp_path / "baseline.tmp").exists()


def test_birinchi_ishlash_shovqin_bermaydi():
    """Baseline bo'sh bo'lsa hamma host "yangi" bo'lardi — foydasiz shovqin."""
    d = ArpDiff(first_run=True, current_hosts=42)
    assert d.changes == []
    assert d.has_suspicious is False
