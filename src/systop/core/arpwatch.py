"""ARP/NDP kuzatuv — vaqt bo'yicha MAC o'zgarishini aniqlash. Root kerak emas.

Nima uchun sysadmin uchun muhim: bir marta olingan ARP jadvali "hozir kim bor"
degan savolga javob beradi. Lekin eng xavfli holatlar **o'zgarishda** ko'rinadi —

  * **ARP spoofing / MITM** — gateway IP'sining MAC'i almashadi. Bir snapshot
    bunda hech qanday g'ayrioddiylik ko'rsatmaydi: jadval "to'g'ri" ko'rinadi,
    faqat MAC boshqa. Faqat oldingi holat bilan solishtirish fosh qiladi;
  * **IP dublikati** — ikki qurilma bir IP'ni talashadi, MAC almashib turadi
    (alomat: "internet uzilib-uzilib ketadi");
  * **ruxsatsiz qurilma** — tarmoqqa yangi host qo'shildi;
  * **qurilma almashtirilgan** — bir xil IP, boshqa vendor (masalan kamera
    o'rniga noutbuk).

Bazaviy holat (baseline) config katalogida JSON sifatida saqlanadi, har
ishlashda diff olinadi. `diff_snapshots` — sof funksiya, offline sinaladi.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from systop.core.diagnose import is_real_device_mac

# Baseline fayl joyi — `core/config.py` bilan bir xil katalog qoidasi
# (`SYSTOP_CONFIG` env yo'lni ko'chirishga imkon beradi).
_DEFAULT_DIR = Path.home() / ".config" / "systop"
BASELINE_NAME = "arp-baseline.json"


def baseline_path() -> Path:
    """Baseline fayl yo'li. `SYSTOP_STATE_DIR` env bilan ko'chirilishi mumkin."""
    env = os.environ.get("SYSTOP_STATE_DIR")
    base = Path(env) if env else _DEFAULT_DIR
    return base / BASELINE_NAME


@dataclass(slots=True)
class ArpChange:
    """Bitta o'zgarish."""

    kind: str  # mac_changed | new_host | disappeared | duplicate_mac
    ip: str
    old_mac: str | None = None
    new_mac: str | None = None
    old_vendor: str | None = None
    new_vendor: str | None = None
    extra_ips: list[str] = field(default_factory=list)  # duplicate_mac uchun

    @property
    def severity(self) -> str:
        """`high` — MAC almashishi (spoofing/dublikat), qolgani `low`/`info`."""
        if self.kind == "mac_changed":
            return "high"
        if self.kind == "duplicate_mac":
            return "medium"
        if self.kind == "new_host":
            return "low"
        return "info"


@dataclass(slots=True)
class ArpDiff:
    """Baseline bilan joriy holat orasidagi farq."""

    changes: list[ArpChange] = field(default_factory=list)
    baseline_age_s: float | None = None
    baseline_hosts: int = 0
    current_hosts: int = 0
    first_run: bool = False

    @property
    def mac_changes(self) -> list[ArpChange]:
        return [c for c in self.changes if c.kind == "mac_changed"]

    @property
    def has_suspicious(self) -> bool:
        """MAC almashishi yoki MAC dublikati bormi (e'tibor talab qiladigan)."""
        return any(c.kind in ("mac_changed", "duplicate_mac") for c in self.changes)


def _address_scope(ip: str) -> str:
    """Manzil doirasi: `ipv4` | `ipv6` | `link-local` | `apipa` — SOF funksiya.

    Doira bo'yicha ajratish shart: bitta NIC'da bir vaqtda APIPA (169.254.x)
    va DHCP manzili bo'lishi, yoki IPv6 link-local va global bo'lishi mumkin.
    Ularni bir doirada taqqoslash "bir MAC ko'p IP'da" soxta natijasini berardi.
    """
    bare = ip.split("%")[0]
    if ":" in bare:
        return "link-local" if bare.lower().startswith(("fe80", "fe9", "fea", "feb")) else "ipv6"
    return "apipa" if bare.startswith("169.254.") else "ipv4"


def diff_snapshots(
    baseline: dict[str, str],
    current: dict[str, str],
    vendor_lookup=None,
) -> list[ArpChange]:
    """Ikki `{ip: mac}` snapshot orasidagi farqni topadi — SOF funksiya.

    `vendor_lookup` — ixtiyoriy `mac -> vendor` funksiyasi (odatda
    `oui.lookup_vendor`); berilsa o'zgarishga vendor nomi qo'shiladi, chunki
    "Hikvision -> Apple" almashishi "MAC o'zgardi" dan ko'ra ancha ma'noli.

    Yo'qolgan hostlar ham qaytariladi, lekin ular normal holat bo'lishi mumkin
    (qurilma o'chirilgan) — shuning uchun `severity` da `info`.
    """
    ven = vendor_lookup or (lambda _mac: None)
    changes: list[ArpChange] = []

    for ip, new_mac in current.items():
        old_mac = baseline.get(ip)
        if old_mac is None:
            changes.append(
                ArpChange(kind="new_host", ip=ip, new_mac=new_mac, new_vendor=ven(new_mac))
            )
        elif old_mac != new_mac:
            changes.append(
                ArpChange(
                    kind="mac_changed",
                    ip=ip,
                    old_mac=old_mac,
                    new_mac=new_mac,
                    old_vendor=ven(old_mac),
                    new_vendor=ven(new_mac),
                )
            )

    for ip, old_mac in baseline.items():
        if ip not in current:
            changes.append(
                ArpChange(kind="disappeared", ip=ip, old_mac=old_mac, old_vendor=ven(old_mac))
            )

    # Bir MAC bir nechta IP'da — joriy holat ichida.
    #
    # MUHIM: faqat BIR OILA ichida taqqoslanadi. Bitta qurilmada IPv4 va IPv6
    # (link-local) manzil bir vaqtda bo'lishi butunlay normal va MAC ikkalasida
    # bir xil — ularni "MAC dublikati" deb belgilash soxta pozitiv beradi
    # (dastlabki versiyada aynan shu bo'lib, 34 ta soxta ogohlantirish chiqdi).
    by_mac: dict[tuple[str, str], list[str]] = {}
    for ip, mac in current.items():
        # Broadcast/multicast MAC tabiiy ravishda ko'p IP bilan bog'lanadi —
        # ularni dublikat deb belgilash soxta pozitiv beradi.
        if not is_real_device_mac(mac):
            continue
        by_mac.setdefault((mac, _address_scope(ip)), []).append(ip)
    for (mac, _scope), ips in by_mac.items():
        # AYNI manzil turli zonada ko'rinishi (fe80::x%awdl0 va %llw0) bitta
        # manzil — dublikat emas. Zonani olib tashlab takrorlarni yig'amiz.
        unique = {i.split("%")[0] for i in ips}
        if len(unique) > 1:
            ordered = sorted(ips)
            changes.append(
                ArpChange(
                    kind="duplicate_mac",
                    ip=ordered[0],
                    new_mac=mac,
                    new_vendor=ven(mac),
                    extra_ips=ordered[1:],
                )
            )

    # Barqaror tartib: jiddiylik, keyin IP.
    order = {"mac_changed": 0, "duplicate_mac": 1, "new_host": 2, "disappeared": 3}
    changes.sort(key=lambda c: (order.get(c.kind, 9), c.ip))
    return changes


def load_baseline(path: Path | None = None) -> tuple[dict[str, str], float | None]:
    """Saqlangan baseline'ni o'qiydi. Qaytaradi: `(snapshot, yozilgan_vaqt)`.

    Fayl yo'q/buzuq bo'lsa `({}, None)` — istisno ko'tarilmaydi (config.py
    bilan bir xil "jim default" qoidasi).
    """
    p = path or baseline_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # ValueError JSONDecodeError va UnicodeDecodeError ni ham qamraydi.
        # `errors="replace"` ATAYLAB ishlatilmaydi: u buzuq faylni
        # `{"10.0.0.1": "\ufffd\ufffd"}` ga aylantirib, disk buzilishidan
        # SOXTA "ARP spoofing" ogohlantirishi yasardi.
        return {}, None
    if not isinstance(data, dict):
        return {}, None
    hosts = data.get("hosts")
    if not isinstance(hosts, dict):
        return {}, None
    saved = data.get("saved_at")
    return (
        {str(k): str(v) for k, v in hosts.items()},
        float(saved) if isinstance(saved, (int, float)) else None,
    )


def save_baseline(snapshot: dict[str, str], path: Path | None = None) -> bool:
    """Baseline'ni yozadi. Muvaffaqiyatda True (xato yutiladi)."""
    p = path or baseline_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {"saved_at": time.time(), "hosts": snapshot}
        # Atomik yozish: yarim yozilgan fayl keyingi o'qishda baseline'ni
        # yo'qotmasligi kerak.
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(p)
        return True
    except OSError:
        return False


def own_mac_addresses() -> set[str]:
    """Shu mashinaning o'z interfeys MAC'lari — SOF-ga yaqin yordamchi.

    Qo'shni jadvalida o'zimizning interfeyslar ham turadi (macOS'da `awdl0` va
    `llw0` bir MAC va bir `fe80::` manzilni bo'lishadi, faqat zona farq qiladi).
    Ularni qo'shni deb hisoblash "bir MAC ikki IP'da" degan DOIMIY soxta
    ogohlantirish berardi — spoofing detektori o'zini ayblab turardi.
    """
    import psutil

    out: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == psutil.AF_LINK and a.address:
                out.add(a.address.lower())
    return out


async def current_snapshot(include_ipv6: bool = True) -> dict[str, str]:
    """Joriy ARP (+ ixtiyoriy NDP) jadvalini `{ip: mac}` sifatida oladi.

    O'z interfeyslarimiz chiqarib tashlanadi — ular qo'shni emas.
    """
    from systop.core import topology

    try:
        own = own_mac_addresses()
    except Exception:  # noqa: BLE001 — psutil yiqilsa filtrsiz davom etamiz
        own = set()

    snap = {ip: mac for ip, mac in topology._parse_arp_table().items() if mac.lower() not in own}
    if include_ipv6:
        for ip, mac in topology._read_ndp_table().items():
            if mac.lower() not in own:
                snap.setdefault(ip, mac)
    return snap


async def check(
    update: bool = True,
    include_ipv6: bool = True,
    path: Path | None = None,
) -> ArpDiff:
    """Joriy holatni baseline bilan solishtiradi va (ixtiyoriy) baseline'ni yangilaydi.

    Birinchi ishlashda taqqoslash uchun narsa yo'q — `first_run=True` qaytadi va
    baseline yoziladi (ogohlantirish berilmaydi, aks holda har yangi mashinada
    "hamma host yangi" degan foydasiz shovqin chiqardi).

    `update=False` — baseline o'zgarmaydi (faqat ko'rish; `doctor` shu rejimda
    ishlaydi, chunki diagnostika holatni o'zgartirmasligi kerak).
    """
    from systop.core.oui import lookup_vendor

    snapshot = await current_snapshot(include_ipv6=include_ipv6)
    baseline, saved_at = load_baseline(path)

    diff = ArpDiff(
        baseline_hosts=len(baseline),
        current_hosts=len(snapshot),
        baseline_age_s=(time.time() - saved_at) if saved_at else None,
        first_run=not baseline,
    )
    if baseline:
        diff.changes = diff_snapshots(baseline, snapshot, vendor_lookup=lookup_vendor)
    if update and snapshot:
        save_baseline(snapshot, path)
    return diff
