"""`core/webscan.py` uchun offline testlar — tarmoqqa chiqmaydi.

`classify` ataylab sof funksiya qilingan (tarmoq chaqiruvi `probe_service`da),
shuning uchun admin-panel aniqlash mantiqini tarmoqsiz to'liq sinash mumkin.
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
    assert extract_title("<html><body>salom</body></html>") is None


def test_extract_title_empty_is_none():
    assert extract_title("<title>   </title>") is None


def test_extract_title_truncated_to_120():
    assert len(extract_title(f"<title>{'a' * 500}</title>")) == 120


# --------------------------------------------------------------------------- #
# classify — admin panelni topish
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
    v = classify('<title>Kirish</title><input type="password" name="p">', {}, 200)
    assert v.is_admin
    assert v.auth_type == "form"


def test_classify_known_admin_product():
    v = classify("<title>Web Client</title>/doc/page/login.asp", {}, 200)
    assert v.is_admin
    assert v.product == "Hikvision"
    assert v.device_kind == "kamera/NVR"


def test_classify_proxmox_from_body():
    v = classify("<script src='/pve2/js/pvemanagerlib.js'></script>", {}, 200)
    assert v.product == "Proxmox VE"
    assert v.is_admin


# --- soxta pozitivlar: web server admin panel EMAS ------------------------- #


def test_classify_nginx_default_is_not_admin():
    """nginx welcome sahifasi — admin panel emas (dastlab shu xato bo'lgan)."""
    v = classify(
        "<title>Welcome to nginx!</title><h1>Welcome to nginx!</h1>",
        {"Server": "nginx"},
        200,
    )
    assert not v.is_admin
    assert v.product == "Nginx"  # identifikatsiya bo'ladi, ball emas
    assert v.score == 0


def test_classify_apache_default_is_not_admin():
    v = classify("<title>Apache2 Ubuntu Default Page</title>", {"Server": "Apache/2.4"}, 200)
    assert not v.is_admin


def test_classify_plain_site_behind_caddy_is_not_admin():
    v = classify("<title>Static site — services</title><p>salom</p>", {"Server": "caddy"}, 200)
    assert not v.is_admin
    assert v.product == "Caddy"


def test_classify_short_token_does_not_false_match():
    """'chassis' ichidagi 'hass' Home Assistant deb topilmasligi kerak."""
    v = classify("<title>Server chassis status</title>", {}, 200)
    assert v.product is None
    assert not v.is_admin


# --- soxta pozitivlar: naqsh oddiy INGLIZCHA SO'Z ichiga tushib ketgan ------ #
#
# Hammasi haqiqatda ko'rilgan holatlar. `\b` so'z chegarasi bularni YECHMAYDI:
# "asterisk" ham, "prometheus" ham matnda alohida so'z bo'lib turadi — yechim
# naqshga kontekst qo'shish ("asterisk management portal").


def test_classify_asterisk_word_is_not_telephony():
    """'marked with an asterisk (*)' — oddiy login sahifasi, FreePBX emas."""
    body = (
        "<title>Login</title><form>"
        '<input type="password" name="p">'
        "<p>Required fields are marked with an asterisk (*)</p></form>"
    )
    v = classify(body, {}, 200)
    assert v.product is None
    assert v.device_kind != "telefoniya"


def test_classify_unified_communications_is_not_unifi():
    """'Unified' ichida 'unifi' bor — UniFi qurilmasi deb belgilanmasin."""
    v = classify(
        "<title>Unified Communications for Business</title>"
        "<p>Our unified communications platform</p>",
        {"Server": "Apache/2.4.57"},
        200,
    )
    assert v.product != "UniFi"
    assert v.device_kind != "tarmoq"
    assert not v.is_admin


def test_classify_dominion_is_not_minio():
    """'dominion' ichidagi 'minio' — storage paneli emas."""
    v = classify("<title>Dominion Insurance</title><p>Dominion Group</p>", {}, 200)
    assert v.product is None
    assert not v.is_admin


def test_classify_k8s_manifest_is_not_docker_api():
    """'apiVersion' har qanday Kubernetes manifestida bor — ochiq Docker API emas."""
    v = classify(
        '{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}}',
        {"Content-Type": "application/json"},
        200,
    )
    assert v.product is None
    assert not v.is_admin


def test_classify_jenkins_surname_is_not_jenkins():
    """'Jenkins' — familiya ham bo'ladi; CI serveri deb belgilanmasin."""
    v = classify("<title>Jamoa</title><p>Bog'lanish: Sarah Jenkins</p>", {}, 200)
    assert v.product is None
    assert not v.is_admin


def test_classify_prometheus_prose_is_not_monitoring():
    """Mifologiya/blog matnidagi 'Prometheus' — monitoring paneli emas."""
    v = classify("<title>Prometheus va olov</title><p>Yunon afsonasi</p>", {}, 200)
    assert v.product is None
    assert not v.is_admin


# --- header va body naqshlari ARALASHMAYDI ---------------------------------- #


def test_classify_header_token_in_body_does_not_match():
    """`x-jenkins` — header tokeni; sahifa MATNIDA uchrasa hisobga olinmaydi."""
    v = classify("<p>Header nomi: x-jenkins</p>", {}, 200)
    assert v.product is None


def test_classify_server_pattern_in_body_does_not_match():
    """`server:nginx` naqshi faqat header matnida izlanadi, tanada emas."""
    v = classify("<pre>server:nginx</pre>", {}, 200)
    assert v.product is None


def test_classify_body_pattern_in_header_does_not_match():
    """Body naqshi ('welcome to nginx') header qiymatida topilmasin."""
    v = classify("", {"X-Note": "welcome to nginx"}, 200)
    assert v.product is None


# --- soya (shadowing): birinchi moslik to'g'ri mahsulotni bosib ketmasin ---- #


def test_classify_bogus_hit_does_not_shadow_real_product():
    """Soxta erta moslik haqiqiy mahsulotni SOYALAB qo'ymasligi kerak.

    Ilgari birinchi moslikda `break` bor edi: ro'yxatda yuqoriroq turgan UniFi
    ("Unified" ichidan) Proxmox'ni bosib ketardi.
    """
    v = classify(
        "<title>Unified Communications</title>"
        "<script src='/pve2/js/pvemanagerlib.js'></script>",
        {},
        200,
    )
    assert v.product == "Proxmox VE"
    assert v.device_kind == "hypervisor"


def test_classify_admin_product_wins_over_infra():
    """nginx ortidagi Kerio — mahsulot Kerio bo'lishi kerak, nginx emas."""
    v = classify("<title>Kerio Control</title>", {"Server": "nginx"}, 200)
    assert v.product == "Kerio Control"


# --- tasdiq (corroboration): zaif iz YOLG'IZ o'zi admin panel emas --------- #


def test_classify_weak_product_alone_is_not_admin():
    """Yalang'och so'zli iz ('grafana') boshqa dalilsiz admin panel emas."""
    v = classify("<p>Biz grafana ishlatamiz</p>", {}, 200)
    assert v.product == "Grafana"  # identifikatsiya qoladi
    assert v.score == 2
    assert not v.is_admin  # ...lekin xavfsizlik topilmasi emas


def test_classify_weak_product_with_login_form_is_admin():
    """O'sha iz + parol maydoni = haqiqiy panel."""
    v = classify('<title>Grafana</title><input type="password">', {}, 200)
    assert v.product == "Grafana"
    assert v.is_admin


# --- haqiqiy mahsulotlar hamon topiladi (aniqlash yo'qolmadi) -------------- #


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
    """Ochiq Docker API — `Server: Docker/...` header'i bilan aniqlanadi."""
    v = classify('{"ApiVersion":"1.41"}', {"Server": "Docker/20.10.7 (linux)"}, 200)
    assert v.product == "Docker API (ochiq!)"
    assert v.is_admin  # header izi kuchli — o'zicha yetarli


def test_classify_jenkins_header_still_detected():
    v = classify("", {"X-Jenkins": "2.401.1"}, 403)
    assert v.product == "Jenkins"


def test_classify_empty_body_no_headers():
    v = classify("", {}, 200)
    assert not v.is_admin
    assert v.score == 0


def test_classify_401_alone_is_not_enough():
    """Faqat 401 (mahsulot/auth headersiz) admin panel deb hisoblanmaydi."""
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


def test_classify_uzbek_and_russian_login_words():
    for title in ("Tizimga kirish", "Вход в систему"):
        v = classify(f"<title>{title}</title>", {}, 401)
        assert v.is_admin, title


# --------------------------------------------------------------------------- #
# WebService property'lari (url / risk)
# --------------------------------------------------------------------------- #


def test_url_ipv4():
    assert WebService(ip="192.168.1.1", port=8080).url == "http://192.168.1.1:8080/"


def test_url_ipv6_is_bracketed():
    """IPv6 manzil URL'da qavsga olinishi SHART, aks holda port ajratilmaydi."""
    svc = WebService(ip="2001:db8::1", port=443, scheme="https")
    assert svc.url == "https://[2001:db8::1]:443/"


def test_risk_none_when_not_admin():
    assert WebService(ip="10.0.0.1", port=80).risk == "none"


def test_risk_high_basic_auth_over_http():
    svc = WebService(ip="10.0.0.1", port=80, scheme="http", is_admin=True,
                     auth_type="basic", insecure_admin=True)
    assert svc.risk == "high"


def test_risk_medium_admin_over_http_form_auth():
    svc = WebService(ip="10.0.0.1", port=80, scheme="http", is_admin=True,
                     auth_type="form", insecure_admin=True)
    assert svc.risk == "medium"


def test_risk_low_admin_over_https():
    svc = WebService(ip="10.0.0.1", port=443, scheme="https", is_admin=True,
                     auth_type="form", insecure_admin=False)
    assert svc.risk == "low"


# --------------------------------------------------------------------------- #
# summarize + port jadvallari
# --------------------------------------------------------------------------- #


def test_summarize_counts():
    services = [
        WebService(ip="1.1.1.1", port=80, is_admin=True, insecure_admin=True,
                   auth_type="basic", scheme="http"),
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
    """4081 — Kerio Control admin porti; the organisation parkida muhim."""
    assert 4081 in WEB_PORTS
