"""Offline tests for `core/arpwatch.py` — watching ARP/NDP changes.

`diff_snapshots` is a pure function: it takes two `{ip: mac}` dictionaries and
returns a list of changes. Reading and writing the baseline is tested in a
temporary directory.

The history of this module is a history of false positives, so most of the
tests are phrased as "this is NOT a change". A single permanent false
"ARP spoofing" warning destroys all trust in the tool — the sysadmin stops
reading the report altogether.
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

# Full 6-octet MACs are REQUIRED: `is_real_device_mac` rejects an abbreviation
# ("aa:bb"), so a duplicate test written with a short MAC used to pass
# SILENTLY without testing anything.
MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"


# --------------------------------------------------------------------------- #
# Real changes — THESE MUST WORK
# --------------------------------------------------------------------------- #


def test_mac_change_is_high_severity():
    """The MAC behind the gateway IP changed — the classic ARP spoofing/MITM sign."""
    ch = diff_snapshots({"192.168.1.1": MAC_A}, {"192.168.1.1": MAC_B})
    assert len(ch) == 1
    assert ch[0].kind == "mac_changed"
    assert ch[0].severity == "high"
    assert ch[0].old_mac == MAC_A
    assert ch[0].new_mac == MAC_B


def test_new_host_is_low_severity():
    ch = diff_snapshots({}, {"192.168.1.5": MAC_A})
    assert ch[0].kind == "new_host"
    assert ch[0].severity == "low"


def test_disappeared_host_is_not_a_warning():
    """The device may simply have been switched off — that is normal, `info`."""
    ch = diff_snapshots({"192.168.1.5": MAC_A}, {})
    assert ch[0].kind == "disappeared"
    assert ch[0].severity == "info"


def test_a_real_duplicate_mac_is_detected():
    """One MAC on two different IPv4 addresses — a duplicate IP or spoofing."""
    ch = diff_snapshots({}, {"192.168.1.5": MAC_A, "192.168.1.9": MAC_A})
    dup = [c for c in ch if c.kind == "duplicate_mac"]
    assert len(dup) == 1
    assert dup[0].new_mac == MAC_A
    assert set([dup[0].ip, *dup[0].extra_ips]) == {"192.168.1.5", "192.168.1.9"}


def test_unchanged_state_reports_nothing():
    snap = {"192.168.1.1": MAC_A, "192.168.1.5": MAC_B}
    assert diff_snapshots(snap, dict(snap)) == []


# --------------------------------------------------------------------------- #
# FALSE POSITIVES — these must not be flagged as changes
# --------------------------------------------------------------------------- #


def test_broadcast_mac_is_not_a_duplicate():
    """`ff:ff:ff:ff:ff:ff` is naturally associated with many IPs."""
    ch = diff_snapshots(
        {},
        {
            "192.168.1.255": "ff:ff:ff:ff:ff:ff",
            "10.0.0.255": "ff:ff:ff:ff:ff:ff",
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_multicast_mac_is_not_a_duplicate():
    """A MAC with the I/G bit set (`01:00:5e:...`) is multicast, not a device."""
    ch = diff_snapshots(
        {},
        {
            "224.0.0.251": "01:00:5e:00:00:fb",
            "224.0.0.252": "01:00:5e:00:00:fc",
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_ipv4_and_ipv6_on_one_device_is_not_a_duplicate():
    """FALSE-POSITIVE REGRESSION — the case that produced 34 warnings at first.

    It is COMPLETELY NORMAL for one device to hold an IPv4 and an IPv6 address
    at the same time with the same MAC on both. The comparison must happen
    within a single scope only.
    """
    ch = diff_snapshots(
        {},
        {
            "192.168.1.5": MAC_A,
            "2001:db8::5": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_link_local_and_global_v6_is_not_a_duplicate():
    """One NIC carries `fe80::` and a global IPv6 together — separated by scope."""
    ch = diff_snapshots(
        {},
        {
            "fe80::5": MAC_A,
            "2001:db8::5": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_apipa_and_dhcp_address_is_not_a_duplicate():
    """169.254.x (APIPA) and a DHCP address can sit on one NIC at the same time."""
    ch = diff_snapshots(
        {},
        {
            "169.254.10.5": MAC_A,
            "192.168.1.5": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_one_address_in_different_zones_is_not_a_duplicate():
    """On macOS `awdl0` and `llw0` share one MAC and one `fe80::` address.

    Only the zone differs. Ignoring the zone produced a PERMANENT "one MAC on
    two IPs" warning on every run — the spoofing detector kept accusing
    itself.
    """
    ch = diff_snapshots(
        {},
        {
            "fe80::1c9d:5eff:fe00:1%awdl0": MAC_A,
            "fe80::1c9d:5eff:fe00:1%llw0": MAC_A,
        },
    )
    assert [c for c in ch if c.kind == "duplicate_mac"] == []


def test_different_link_local_addresses_are_a_duplicate():
    """When the ADDRESS differs rather than the zone — that is a real duplicate."""
    ch = diff_snapshots(
        {},
        {
            "fe80::1%en0": MAC_A,
            "fe80::2%en0": MAC_A,
        },
    )
    assert len([c for c in ch if c.kind == "duplicate_mac"]) == 1


# --------------------------------------------------------------------------- #
# Address scope
# --------------------------------------------------------------------------- #


def test_address_scopes_are_separated():
    assert _address_scope("192.168.1.1") == "ipv4"
    assert _address_scope("169.254.1.1") == "apipa"
    assert _address_scope("2001:db8::1") == "ipv6"
    assert _address_scope("fe80::1") == "link-local"
    assert _address_scope("fe80::1%en0") == "link-local"


# --------------------------------------------------------------------------- #
# Ordering and vendors
# --------------------------------------------------------------------------- #


def test_the_more_severe_change_comes_first():
    ch = diff_snapshots(
        {"192.168.1.1": MAC_A, "192.168.1.9": MAC_A},
        {"192.168.1.1": MAC_B, "192.168.1.20": MAC_B},
    )
    assert ch[0].kind == "mac_changed"


def test_vendor_lookup_is_wired_in():
    """A vendor change ("Hikvision -> Apple") says far more than a raw MAC."""
    ch = diff_snapshots(
        {"192.168.1.1": MAC_A},
        {"192.168.1.1": MAC_B},
        vendor_lookup=lambda m: "Hikvision" if m == MAC_A else "Apple",
    )
    assert ch[0].old_vendor == "Hikvision"
    assert ch[0].new_vendor == "Apple"


def test_has_suspicious_only_for_the_serious_kinds():
    assert ArpDiff(changes=[ArpChange(kind="new_host", ip="1.1.1.1")]).has_suspicious is False
    assert ArpDiff(changes=[ArpChange(kind="mac_changed", ip="1.1.1.1")]).has_suspicious is True
    assert ArpDiff(changes=[ArpChange(kind="duplicate_mac", ip="1.1.1.1")]).has_suspicious is True


# --------------------------------------------------------------------------- #
# Saving and reading the baseline
# --------------------------------------------------------------------------- #


def test_baseline_round_trips(tmp_path):
    p = tmp_path / "baseline.json"
    snap = {"192.168.1.1": MAC_A}
    assert save_baseline(snap, p) is True
    got, saved_at = load_baseline(p)
    assert got == snap
    assert saved_at is not None


def test_missing_baseline_file_is_empty():
    got, saved_at = load_baseline(__import__("pathlib").Path("/no/such/file.json"))
    assert got == {} and saved_at is None


def test_corrupt_baseline_does_not_manufacture_spoofing(tmp_path):
    """IMPORTANT: `errors="replace"` is DELIBERATELY not used.

    It turns a corrupt file into `{"10.0.0.1": "\\ufffd\\ufffd"}` — so on the
    next run the MAC looks "changed" and a SEV_HIGH "ARP spoofing (MITM)"
    warning gets manufactured out of a disk problem.
    """
    p = tmp_path / "baseline.json"
    p.write_bytes(b'{"hosts": {"10.0.0.1": "\xff\xfe"}}')
    got, saved_at = load_baseline(p)
    assert got == {}
    assert saved_at is None


def test_invalid_json_returns_empty(tmp_path):
    p = tmp_path / "baseline.json"
    p.write_text("this is not json", encoding="utf-8")
    assert load_baseline(p) == ({}, None)


def test_wrongly_shaped_json_is_empty(tmp_path):
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(["a list", "not a dict"]), encoding="utf-8")
    assert load_baseline(p) == ({}, None)
    p.write_text(json.dumps({"hosts": "not a dict"}), encoding="utf-8")
    assert load_baseline(p) == ({}, None)


def test_baseline_is_written_atomically(tmp_path):
    """A half-written file must not lose the previous baseline."""
    p = tmp_path / "baseline.json"
    save_baseline({"192.168.1.1": MAC_A}, p)
    save_baseline({"192.168.1.2": MAC_B}, p)
    got, _ = load_baseline(p)
    assert got == {"192.168.1.2": MAC_B}
    assert not (tmp_path / "baseline.tmp").exists()


def test_first_run_produces_no_noise():
    """With an empty baseline every host would be "new" — useless noise."""
    d = ArpDiff(first_run=True, current_hosts=42)
    assert d.changes == []
    assert d.has_suspicious is False
