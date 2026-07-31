"""Tarmoqsiz (offline) ishlaydigan birlik testlari."""

from systop.core.netinfo import Interface
from systop.core.ping import DEFAULT_GLOBAL_TARGETS, PingResult, build_targets
from systop.core.topology import _ARP_RE, _NEIGH_RE


def test_interface_cidr():
    iface = Interface(name="en0", ipv4="192.168.1.42", netmask="255.255.255.0")
    assert iface.cidr == "192.168.1.0/24"


def test_interface_cidr_none_without_ip():
    assert Interface(name="en0").cidr is None


def test_build_targets_with_gateway():
    targets = build_targets("192.168.1.1")
    assert targets["Gateway (lokal)"] == "192.168.1.1"
    assert "Cloudflare" in targets
    assert len(targets) == len(DEFAULT_GLOBAL_TARGETS) + 1


def test_build_targets_no_gateway_no_global():
    assert build_targets(None, include_global=False) == {}


def test_ping_result_loss_pct():
    assert PingResult(label="x", address="1.1.1.1", packet_loss=0.25).loss_pct == 25.0


def test_arp_regex_macos():
    line = "? (192.168.1.1) at a4:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]"
    m = _ARP_RE.search(line)
    assert m and m.group(1) == "192.168.1.1"
    assert m.group(2) == "a4:b1:c2:d3:e4:f5"


def test_neigh_regex_linux():
    line = "192.168.1.1 dev eth0 lladdr a4:b1:c2:d3:e4:f5 REACHABLE"
    m = _NEIGH_RE.search(line)
    assert m and m.group(1) == "192.168.1.1"
    assert m.group(2) == "a4:b1:c2:d3:e4:f5"


# --------------------------------------------------------------------------- #
# Rich emoji shortcode himoyasi (0.5.1) — MAC/IPv6 buzilishi regressiyasi
# --------------------------------------------------------------------------- #

import io  # noqa: E402

from rich.console import Console  # noqa: E402

from systop.widgets._glyphs import data_cell  # noqa: E402


def _render(renderable) -> str:
    """Emoji almashtirish YOQILGAN konsolda render qiladi (TUI holati)."""
    c = Console(file=io.StringIO(), emoji=True, force_terminal=False, width=80)
    c.print(renderable)
    return c.file.getvalue()


def test_raw_string_mac_is_corrupted_by_rich():
    """Muammoni hujjatlashtiradi: xom satr Rich'da emojiga aylanadi."""
    assert "🆎" in _render("62:46:3c:ab:d1:1a")


def test_data_cell_protects_mac_with_ab_octet():
    """`:ab:` -> 🆎 bo'lmasligi kerak (ekranda ko'rilgan haqiqiy bug)."""
    out = _render(data_cell("62:46:3c:ab:d1:1a"))
    assert "62:46:3c:ab:d1:1a" in out
    assert "🆎" not in out


def test_data_cell_protects_mac_with_cd_octet():
    out = _render(data_cell("aa:bb:cd:11:22:33"))
    assert "aa:bb:cd:11:22:33" in out
    assert "💿" not in out


def test_data_cell_protects_ipv6_hex_groups():
    """IPv6'da xavf kattaroq: :a: :b: :abc: :abcd: :bed: :bee: :100: :1234:."""
    for addr, emoji in [
        ("2001:a:1::1", "🅰"),
        ("2001:b:1::1", "🅱"),
        ("2001:abc:1::1", "🔤"),
        ("2001:abcd:1::1", "🔡"),
        ("2001:bed:1::1", "🛏"),
        ("2001:bee:1::1", "🐝"),
        ("2001:100:1::1", "💯"),
        ("2001:1234:1::1", "🔢"),
    ]:
        out = _render(data_cell(addr))
        assert addr in out, addr
        assert emoji not in out, addr


def test_data_cell_does_not_interpret_markup():
    """Ma'lumotda `[dim]` bo'lsa ham uslub sifatida talqin qilinmasligi kerak."""
    out = _render(data_cell("[red]not-a-style[/]"))
    assert "[red]not-a-style[/]" in out


def test_data_cell_empty_uses_placeholder():
    assert "—" in _render(data_cell(None, "—"))
    assert "—" in _render(data_cell("", "—"))


def test_data_cell_stringifies_non_str():
    assert "8080" in _render(data_cell(8080))


def test_all_hex_emoji_shortcodes_are_covered():
    """Rich'da 16-lik belgilardan iborat shortcode'lar soni o'zgarsa xabar bersin.

    Rich yangilanib yangi shortcode qo'shilsa (masalan `:dead:`) bu test
    yiqiladi va himoyani qayta ko'rib chiqishga majbur qiladi.
    """
    from rich._emoji_codes import EMOJI

    hexchars = set("0123456789abcdef")
    risky = {n for n in EMOJI if 1 <= len(n) <= 4 and set(n.lower()) <= hexchars}
    assert risky == {"a", "b", "ab", "cd", "abc", "abcd", "bed", "bee", "100", "1234"}
