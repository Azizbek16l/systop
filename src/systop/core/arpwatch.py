"""ARP/NDP watch — detecting MAC changes over time. No root required.

Why this matters for a sysadmin: a single ARP table snapshot answers the
question "who is here right now". But the most dangerous situations only show
up **in the change** —

  * **ARP spoofing / MITM** — the MAC behind the gateway IP changes. A single
    snapshot shows nothing unusual at all: the table looks "correct", only the
    MAC is different. Only a comparison against the previous state exposes it;
  * **a duplicate IP** — two devices fight over one IP and the MAC keeps
    flipping (symptom: "the internet keeps cutting out");
  * **an unauthorised device** — a new host joined the network;
  * **a replaced device** — same IP, different vendor (a laptop where a camera
    used to be, for instance).

The baseline is stored as JSON in the config directory and diffed on every run.
`diff_snapshots` is a pure function and is tested offline.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from systop.core.diagnose import is_real_device_mac

# Where the baseline file lives — the same directory rule as `core/config.py`
# (`SYSTOP_CONFIG` allows the path to be relocated).
_DEFAULT_DIR = Path.home() / ".config" / "systop"
BASELINE_NAME = "arp-baseline.json"


def baseline_path() -> Path:
    """Path to the baseline file. Can be relocated with `SYSTOP_STATE_DIR`."""
    env = os.environ.get("SYSTOP_STATE_DIR")
    base = Path(env) if env else _DEFAULT_DIR
    return base / BASELINE_NAME


@dataclass(slots=True)
class ArpChange:
    """A single change."""

    kind: str  # mac_changed | new_host | disappeared | duplicate_mac
    ip: str
    old_mac: str | None = None
    new_mac: str | None = None
    old_vendor: str | None = None
    new_vendor: str | None = None
    extra_ips: list[str] = field(default_factory=list)  # for duplicate_mac

    @property
    def severity(self) -> str:
        """`high` — a MAC change (spoofing/duplicate); the rest is `low`/`info`."""
        if self.kind == "mac_changed":
            return "high"
        if self.kind == "duplicate_mac":
            return "medium"
        if self.kind == "new_host":
            return "low"
        return "info"


@dataclass(slots=True)
class ArpDiff:
    """The difference between the baseline and the current state."""

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
        """Is there a MAC change or a duplicate MAC (anything needing attention)."""
        return any(c.kind in ("mac_changed", "duplicate_mac") for c in self.changes)


def _address_scope(ip: str) -> str:
    """Address scope: `ipv4` | `ipv6` | `link-local` | `apipa` — pure function.

    Separating by scope is essential: one NIC can hold an APIPA address
    (169.254.x) and a DHCP address at the same time, or an IPv6 link-local and
    a global one. Comparing those within a single scope produced the false
    result "one MAC on many IPs".
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
    """Find the difference between two `{ip: mac}` snapshots — pure function.

    `vendor_lookup` is an optional `mac -> vendor` function (usually
    `oui.lookup_vendor`); when supplied, the vendor name is attached to the
    change, because "Hikvision -> Apple" is far more meaningful than "the MAC
    changed".

    Disappeared hosts are returned too, but they may well be a normal
    situation (the device was switched off) — hence `info` in `severity`.
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

    # One MAC on several IPs — within the current state.
    #
    # IMPORTANT: the comparison happens only WITHIN ONE SCOPE. It is entirely
    # normal for a single device to hold an IPv4 and an IPv6 (link-local)
    # address at the same time with the same MAC on both — flagging that as a
    # "duplicate MAC" gives a false positive (that is exactly what the first
    # version did, and it produced 34 false warnings).
    by_mac: dict[tuple[str, str], list[str]] = {}
    for ip, mac in current.items():
        # A broadcast/multicast MAC is naturally associated with many IPs —
        # flagging those as duplicates gives a false positive.
        if not is_real_device_mac(mac):
            continue
        by_mac.setdefault((mac, _address_scope(ip)), []).append(ip)
    for (mac, _scope), ips in by_mac.items():
        # The SAME address seen in different zones (fe80::x%awdl0 and %llw0) is
        # one address, not a duplicate. Strip the zone and collapse repeats.
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

    # A stable order: severity first, then IP.
    order = {"mac_changed": 0, "duplicate_mac": 1, "new_host": 2, "disappeared": 3}
    changes.sort(key=lambda c: (order.get(c.kind, 9), c.ip))
    return changes


def load_baseline(path: Path | None = None) -> tuple[dict[str, str], float | None]:
    """Read the stored baseline. Returns `(snapshot, written_at)`.

    If the file is missing or corrupt, `({}, None)` — no exception is raised
    (the same "quiet default" rule as config.py).
    """
    p = path or baseline_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # ValueError also covers JSONDecodeError and UnicodeDecodeError.
        # `errors="replace"` is DELIBERATELY not used: it would turn a corrupt
        # file into `{"10.0.0.1": "��"}` and manufacture a FALSE
        # "ARP spoofing" warning out of a disk problem.
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
    """Write the baseline. True on success (errors are swallowed)."""
    p = path or baseline_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {"saved_at": time.time(), "hosts": snapshot}
        # An atomic write: a half-written file must not lose the baseline on
        # the next read.
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(p)
        return True
    except OSError:
        return False


def own_mac_addresses() -> set[str]:
    """This machine's own interface MACs — a near-pure helper.

    Our own interfaces also appear in the neighbour table (on macOS `awdl0` and
    `llw0` share one MAC and one `fe80::` address, only the zone differs).
    Treating them as neighbours produced a PERMANENT false warning of "one MAC
    on two IPs" — the spoofing detector kept accusing itself.
    """
    import psutil

    out: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == psutil.AF_LINK and a.address:
                out.add(a.address.lower())
    return out


async def current_snapshot(include_ipv6: bool = True) -> dict[str, str]:
    """Take the current ARP (plus optional NDP) table as `{ip: mac}`.

    Our own interfaces are excluded — they are not neighbours.
    """
    from systop.core import topology

    try:
        own = own_mac_addresses()
    except Exception:  # noqa: BLE001 — if psutil fails we carry on unfiltered
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
    """Compare the current state with the baseline and (optionally) update it.

    On the first run there is nothing to compare against — `first_run=True` is
    returned and the baseline is written (no warning is emitted, otherwise
    every new machine would produce the useless noise "every host is new").

    `update=False` leaves the baseline untouched (view only; `doctor` runs in
    this mode, because diagnostics must not change state).
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
