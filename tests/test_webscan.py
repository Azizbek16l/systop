"""Offline tests for `core/webscan.py` — they never touch the network.

`classify` was deliberately made a pure function (the network call lives in
`probe_service`), so the admin-panel detection logic can be exercised in full
without a network.
"""

from systop.core.webscan import (
    QUICK_WEB_PORTS,
    WEB_PORTS,
    WebService,
    classify,
    extract_title,
    summarize,
)

# --------------------------------------------------------------------------- #
# extract_title
# --------------------------------------------------------------------------- #


def test_extract_title_basic():
    assert extract_title("<html><title>Kerio Control</title></html>") == "Kerio Control"


def test_extract_title_collapses_whitespace():
    body = "<title>\n  Router\t\tAdmin  \n</title>"
    assert extract_title(body) == "Router Admin"


def test_extract_title_missing():
    assert extract_title("<html><body>hello</body></html>") is None


def test_extract_title_empty_is_none():
    assert extract_title("<title>   </title>") is None


def test_extract_title_truncated_to_120():
    assert len(extract_title(f"<title>{'a' * 500}</title>")) == 120


# --------------------------------------------------------------------------- #
# classify — finding the admin panel
# --------------------------------------------------------------------------- #


def test_classify_basic_auth_is_admin():
    v = classify("", {"WWW-Authenticate": 'Basic realm="RouterOS"'}, 401)
    assert v.is_admin
    assert v.auth_type == "basic"
    assert v.score >= 3


def test_classify_digest_auth_detected():
    v = classify("", {"WWW-Authenticate": 'Digest realm="cam"'}, 401)
    assert v.auth_type == "digest"


def test_classify_password_form_is_admin():
    v = classify('<title>Sign in</title><input type="password" name="p">', {}, 200)
    assert v.is_admin
    assert v.auth_type == "form"


def test_classify_known_admin_product():
    v = classify("<title>Web Client</title>/doc/page/login.asp", {}, 200)
    assert v.is_admin
    assert v.product == "Hikvision"
    assert v.device_kind == "camera/NVR"


def test_classify_proxmox_from_body():
    v = classify("<script src='/pve2/js/pvemanagerlib.js'></script>", {}, 200)
    assert v.product == "Proxmox VE"
    assert v.is_admin


# --- false positives: a web server is NOT an admin panel ------------------- #


def test_classify_nginx_default_is_not_admin():
    """The nginx welcome page — not an admin panel (this was the original bug)."""
    v = classify(
        "<title>Welcome to nginx!</title><h1>Welcome to nginx!</h1>",
        {"Server": "nginx"},
        200,
    )
    assert not v.is_admin
    assert v.product == "Nginx"  # identification happens, but no score
    assert v.score == 0


def test_classify_apache_default_is_not_admin():
    v = classify("<title>Apache2 Ubuntu Default Page</title>", {"Server": "Apache/2.4"}, 200)
    assert not v.is_admin


def test_classify_plain_site_behind_caddy_is_not_admin():
    v = classify("<title>Static site — services</title><p>hello</p>", {"Server": "caddy"}, 200)
    assert not v.is_admin
    assert v.product == "Caddy"


def test_classify_short_token_does_not_false_match():
    """The 'hass' inside 'chassis' must not be detected as Home Assistant."""
    v = classify("<title>Server chassis status</title>", {}, 200)
    assert v.product is None
    assert not v.is_admin


# --- false positives: the pattern fell inside an ordinary ENGLISH WORD ------ #
#
# All of these were seen in reality. The `\b` word boundary does NOT fix them:
# both "asterisk" and "prometheus" stand as separate words in the text — the fix
# is to add context to the pattern ("asterisk management portal").


def test_classify_asterisk_word_is_not_telephony():
    """'marked with an asterisk (*)' — an ordinary login page, not FreePBX."""
    body = (
        "<title>Login</title><form>"
        '<input type="password" name="p">'
        "<p>Required fields are marked with an asterisk (*)</p></form>"
    )
    v = classify(body, {}, 200)
    assert v.product is None
    assert v.device_kind != "telephony"


def test_classify_unified_communications_is_not_unifi():
    """'Unified' contains 'unifi' — it must not be flagged as a UniFi device."""
    v = classify(
        "<title>Unified Communications for Business</title>"
        "<p>Our unified communications platform</p>",
        {"Server": "Apache/2.4.57"},
        200,
    )
    assert v.product != "UniFi"
    assert v.device_kind != "network"
    assert not v.is_admin


def test_classify_dominion_is_not_minio():
    """The 'minio' inside 'dominion' — not a storage panel."""
    v = classify("<title>Dominion Insurance</title><p>Dominion Group</p>", {}, 200)
    assert v.product is None
    assert not v.is_admin


def test_classify_k8s_manifest_is_not_docker_api():
    """'apiVersion' appears in any Kubernetes manifest — it is not an exposed Docker API."""
    v = classify(
        '{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}}',
        {"Content-Type": "application/json"},
        200,
    )
    assert v.product is None
    assert not v.is_admin


def test_classify_jenkins_surname_is_not_jenkins():
    """'Jenkins' is also a surname; it must not be flagged as a CI server."""
    v = classify("<title>Our team</title><p>Contact: Sarah Jenkins</p>", {}, 200)
    assert v.product is None
    assert not v.is_admin


def test_classify_prometheus_prose_is_not_monitoring():
    """'Prometheus' in mythology/blog prose — not a monitoring panel."""
    v = classify("<title>Prometheus and the fire</title><p>A Greek myth</p>", {}, 200)
    assert v.product is None
    assert not v.is_admin


# --- header and body patterns DO NOT MIX ------------------------------------ #


def test_classify_header_token_in_body_does_not_match():
    """`x-jenkins` is a header token; if it appears in the page TEXT it is ignored."""
    v = classify("<p>Header name: x-jenkins</p>", {}, 200)
    assert v.product is None


def test_classify_server_pattern_in_body_does_not_match():
    """The `server:nginx` pattern is searched only in the header text, not the body."""
    v = classify("<pre>server:nginx</pre>", {}, 200)
    assert v.product is None


def test_classify_body_pattern_in_header_does_not_match():
    """A body pattern ('welcome to nginx') must not be found in a header value."""
    v = classify("", {"X-Note": "welcome to nginx"}, 200)
    assert v.product is None


# --- shadowing: the first match must not override the correct product ------- #


def test_classify_bogus_hit_does_not_shadow_real_product():
    """A bogus early match must not SHADOW the real product.

    Previously there was a `break` on the first match: UniFi (from inside
    "Unified"), sitting higher in the list, would override Proxmox.
    """
    v = classify(
        "<title>Unified Communications</title><script src='/pve2/js/pvemanagerlib.js'></script>",
        {},
        200,
    )
    assert v.product == "Proxmox VE"
    assert v.device_kind == "hypervisor"


def test_classify_admin_product_wins_over_infra():
    """Kerio behind nginx — the product must be Kerio, not nginx."""
    v = classify("<title>Kerio Control</title>", {"Server": "nginx"}, 200)
    assert v.product == "Kerio Control"


# --- corroboration: a weak fingerprint ALONE is not an admin panel ---------- #


def test_classify_weak_product_alone_is_not_admin():
    """A bare-word fingerprint ('grafana') is not an admin panel without other evidence."""
    v = classify("<p>We use grafana here</p>", {}, 200)
    assert v.product == "Grafana"  # the identification stays
    assert v.score == 2
    assert not v.is_admin  # ...but it is not a security finding


def test_classify_weak_product_with_login_form_is_admin():
    """The same fingerprint + a password field = a real panel."""
    v = classify('<title>Grafana</title><input type="password">', {}, 200)
    assert v.product == "Grafana"
    assert v.is_admin


# --- the real products are still found (detection was not lost) ------------- #


def test_classify_real_freepbx_still_detected():
    v = classify('<title>FreePBX Administration</title><input type="password">', {}, 200)
    assert v.product == "Asterisk/FreePBX"
    assert v.is_admin


def test_classify_real_unifi_still_detected():
    v = classify("<title>UniFi Network</title>", {}, 200)
    assert v.product == "UniFi"


def test_classify_real_minio_console_still_detected():
    v = classify("<title>MinIO Console</title>", {}, 200)
    assert v.product == "MinIO"


def test_classify_real_prometheus_still_detected():
    v = classify("<title>Prometheus Time Series Collection</title>", {}, 200)
    assert v.product == "Prometheus"


def test_classify_open_docker_api_from_header():
    """An exposed Docker API — detected by the `Server: Docker/...` header."""
    v = classify('{"ApiVersion":"1.41"}', {"Server": "Docker/20.10.7 (linux)"}, 200)
    assert v.product == "Docker API (exposed!)"
    assert v.is_admin  # the header fingerprint is strong — enough on its own


def test_classify_jenkins_header_still_detected():
    v = classify("", {"X-Jenkins": "2.401.1"}, 403)
    assert v.product == "Jenkins"


def test_classify_empty_body_no_headers():
    v = classify("", {}, 200)
    assert not v.is_admin
    assert v.score == 0


def test_classify_401_alone_is_not_enough():
    """A 401 on its own (with no product/auth header) does not count as an admin panel."""
    v = classify("", {}, 401)
    assert v.score == 1
    assert not v.is_admin


def test_classify_admin_title_plus_401_is_admin():
    v = classify("<title>Login</title>", {}, 401)
    assert v.score == 2
    assert v.is_admin


def test_classify_headers_case_insensitive():
    lower = classify("", {"www-authenticate": "Basic realm=x"}, 401)
    upper = classify("", {"WWW-Authenticate": "Basic realm=x"}, 401)
    assert lower.is_admin == upper.is_admin == True  # noqa: E712


def test_classify_localized_login_words():
    """Device firmware often ships a localised login page — those titles count too."""
    for title in ("Tizimga kirish", "Вход в систему"):
        v = classify(f"<title>{title}</title>", {}, 401)
        assert v.is_admin, title


# --------------------------------------------------------------------------- #
# WebService properties (url / risk)
# --------------------------------------------------------------------------- #


def test_url_ipv4():
    assert WebService(ip="192.168.1.1", port=8080).url == "http://192.168.1.1:8080/"


def test_url_ipv6_is_bracketed():
    """An IPv6 address MUST be bracketed in the URL, otherwise the port is not separated."""
    svc = WebService(ip="2001:db8::1", port=443, scheme="https")
    assert svc.url == "https://[2001:db8::1]:443/"


def test_risk_none_when_not_admin():
    assert WebService(ip="10.0.0.1", port=80).risk == "none"


def test_risk_high_basic_auth_over_http():
    svc = WebService(
        ip="10.0.0.1", port=80, scheme="http", is_admin=True, auth_type="basic", insecure_admin=True
    )
    assert svc.risk == "high"


def test_risk_medium_admin_over_http_form_auth():
    svc = WebService(
        ip="10.0.0.1", port=80, scheme="http", is_admin=True, auth_type="form", insecure_admin=True
    )
    assert svc.risk == "medium"


def test_risk_low_admin_over_https():
    svc = WebService(
        ip="10.0.0.1",
        port=443,
        scheme="https",
        is_admin=True,
        auth_type="form",
        insecure_admin=False,
    )
    assert svc.risk == "low"


# --------------------------------------------------------------------------- #
# summarize + the port tables
# --------------------------------------------------------------------------- #


def test_summarize_counts():
    services = [
        WebService(
            ip="1.1.1.1",
            port=80,
            is_admin=True,
            insecure_admin=True,
            auth_type="basic",
            scheme="http",
        ),
        WebService(ip="1.1.1.2", port=443, is_admin=True, scheme="https"),
        WebService(ip="1.1.1.3", port=80, scheme="http"),
    ]
    st = summarize(services)
    assert st["total"] == 3
    assert st["admin"] == 2
    assert st["insecure_admin"] == 1
    assert st["high_risk"] == 1
    assert st["http_80"] == 2


def test_summarize_empty():
    assert summarize([])["total"] == 0


def test_web_ports_include_80_and_443():
    assert WEB_PORTS[80] == "http"
    assert WEB_PORTS[443] == "https"


def test_quick_ports_are_subset_of_web_ports():
    assert set(QUICK_WEB_PORTS) <= set(WEB_PORTS)


def test_kerio_admin_port_present():
    """4081 — the Kerio Control admin port; common on small-business firewalls."""
    assert 4081 in WEB_PORTS
