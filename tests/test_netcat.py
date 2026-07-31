"""Offline tests for `core/netcat.py`.

`unescape`, `to_hexdump` and the `NcResult` properties are pure — they are
tested without a network. `connect()` does go to the network, so it is not
tested (a project rule).
"""

from systop.core.netcat import NcResult, to_hexdump, unescape

# --------------------------------------------------------------------------- #
# unescape — turning the `\r\n` that came from the shell into real bytes
# --------------------------------------------------------------------------- #


def test_unescape_crlf():
    assert unescape(r"GET / HTTP/1.0\r\n\r\n") == b"GET / HTTP/1.0\r\n\r\n"


def test_unescape_tab_and_nul():
    assert unescape(r"a\tb\0c") == b"a\tb\x00c"


def test_unescape_hex():
    assert unescape(r"\x41\x42\x43") == b"ABC"


def test_unescape_hex_uppercase_and_lowercase():
    assert unescape(r"\x4a\x4B") == b"JK"


def test_unescape_double_backslash():
    assert unescape(r"a\\b") == b"a\\b"


def test_unescape_unknown_sequence_left_alone():
    """`\\q` is unrecognised — it has to stay as it is (nothing is dropped silently)."""
    assert unescape(r"no\qescape") == b"no\\qescape"


def test_unescape_plain_text_unchanged():
    assert unescape("PING") == b"PING"


def test_unescape_empty():
    assert unescape("") == b""


def test_unescape_non_ascii_encoded_utf8():
    assert unescape("hello") == b"hello"


# --------------------------------------------------------------------------- #
# to_hexdump
# --------------------------------------------------------------------------- #


def test_hexdump_offset_hex_and_ascii_columns():
    out = to_hexdump(b"ABC")
    assert out.startswith("00000000")
    assert "41 42 43" in out
    assert "|ABC|" in out


def test_hexdump_non_printable_becomes_dot():
    assert "|..|" in to_hexdump(b"\x00\xff")


def test_hexdump_wraps_at_width():
    out = to_hexdump(bytes(range(32)), width=16)
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[1].startswith("00000010")


def test_hexdump_empty_is_empty_string():
    assert to_hexdump(b"") == ""


# --------------------------------------------------------------------------- #
# NcResult properties
# --------------------------------------------------------------------------- #


def test_received_text_decodes_utf8():
    assert NcResult(host="h", port=1, received=b"hello").received_text == "hello"


def test_received_text_replaces_invalid_bytes():
    """A binary answer must turn into text as well, without falling over."""
    assert "�" in NcResult(host="h", port=1, received=b"\xff\xfe").received_text


def test_received_bytes_count():
    assert NcResult(host="h", port=1, received=b"1234").received_bytes_count == 4


def test_is_binary_false_for_text():
    r = NcResult(host="h", port=1, received=b"SSH-2.0-OpenSSH_9.6\r\n")
    assert r.is_binary is False


def test_is_binary_true_for_binary():
    r = NcResult(host="h", port=1, received=bytes(range(0, 32)))
    assert r.is_binary is True


def test_is_binary_false_for_empty():
    assert NcResult(host="h", port=1).is_binary is False


def test_defaults():
    r = NcResult(host="h", port=22)
    assert r.connected is False
    assert r.tls is False
    assert r.sent_bytes == 0
    assert r.received == b""
    assert r.error is None
    assert r.peer_cert_sha256 is None
