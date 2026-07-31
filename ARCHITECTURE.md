# Arxitektura va ishlab chiqish qo'llanmasi

Bu hujjat `systop` kod bazasida ishlaydigan dasturchi uchun: qatlamlar,
modullar xaritasi va koddan KO'RINMAYDIGAN qarorlar (nima uchun aynan
shunday qilingan). Yangi funksiya qo'shishdan oldin "Muhim qarorlar"
bo'limini o'qing — u yerdagi har bir band haqiqiy bug natijasida yozilgan.

## Loyiha

`systop` — sysadminlar uchun root talab qilmaydigan terminal tarmoq tooli
(TUI + CLI), **Linux, Windows va macOS** da ishlaydi. Sysadminning kundalik
tarmoq vazifalari bitta toolda: internet tezligi (xalqaro + lokal/IX), lokal va
global ping, traceroute/mtr, LAN discovery (IPv4+IPv6), port skan va banner,
xom TCP/TLS mijoz, DNS taqqoslash, per-interfeys bandwidth, TLS/HTTP
tekshiruvi, faol ulanishlar, web/boshqaruv paneli inventari, avto-diagnostika,
soat siljishi (SNTP), marshrut jadvali, path MTU, DHCP aniqlash, ARP/NDP
kuzatuv va Wi-Fi tahlili. Har bir buyruq scriptlarga mos (`--json`/`--format`,
mazmunli exit kodlar). Stack: **Python 3.11+**, **Textual** (TUI), **httpx**,
**icmplib**, **psutil**. Paket menejeri: **uv**.

> **Buyruqlar ro'yxati — yagona manba `cli.py`dagi `_build_parser()`.** Bu
> yerdagi ro'yxatni qo'lda sanamang; u eskirsa `tests/test_docs.py` yiqiladi.
> Yangi subbuyruq qo'shsangiz `cli.py` modul docstring'ini VA ikkala
> README'ni ham yangilash SHART — parity testi aynan shuni tekshiradi.

## Buyruqlar

```bash
uv sync                          # muhit + bog'liqliklar (dev uchun: uv sync --extra dev)
uv run systop                    # dashboard (TUI) — default
uv run systop {speed|ping|lan|info|conn}   # bir martalik buyruqlar
uv run systop ping --watch       # doimiy ping monitor (rich.Live)
uv run systop ping --ipv6        # IPv6 global nishonlarni ham qo'shadi
uv run systop ping --targets 1.1.1.1,8.8.8.8   # aniq nishonlar (config'ni override)
uv run systop trace <host> [--continuous]   # traceroute (--continuous == mtr)
uv run systop mtr <host> [--interval 1.0 --cycles N]   # jonli mtr (per-hop loss/avg/best/worst)
uv run systop scan <host> [--ports 22,80,443|1-1024]   # TCP port skaner
uv run systop dns <name> [--resolvers ...]   # DNS resolve + serverlar latency taqqoslash
uv run systop bw [--watch --interval 1.0]   # per-interfeys bandwidth (RX/TX/pps)
uv run systop tls <host[:port]> [--warn-days 14]   # TLS sertifikat (muddat, issuer, SAN)
uv run systop http <url>         # HTTP holat (status, redirect, vaqt)
uv run systop conn [--listen]    # faol ulanishlar (faqat LISTEN ham)
uv run systop web [HOST...]      # web xizmat + boshqaruv panellari (LAN avtomatik)
uv run systop web --http80       # faqat 80-port: lokal HTTP ochiqligini topish
uv run systop web --mgmt         # faqat tarmoqni boshqaruvchi qurilmalar
uv run systop web --polite       # sekin rejim (IPS/anti-scan bor tarmoq uchun)
uv run systop doctor             # tarmoq muammolarini avtomatik topish
uv run systop doctor --quick     # tez rejim (web/IPv6 tashlanadi)
uv run systop scan -6 HOST       # IPv6 port skan (-4 majburan IPv4)
uv run systop lan -6             # LAN: IPv4 + IPv6 (ff02::1 + NDP jadval)
uv run systop lan --global-only  # IPv6'da link-local'ni chiqarib tashlash
uv run systop scan 10.0.0.0/24 --top 20   # LAN bo'ylab port sweep (nmap -sT)
uv run systop scan HOST --banner          # xizmat versiyasi (nmap -sV yengil)
uv run systop nc HOST PORT [--send 'PING\r\n'] [--tls] [--hex]   # ncat uslubi
uv run systop speed --local      # lokal (IX) endpointlar vs xalqaro (speed_local_urls)
uv run systop speed --local-url URL   # bir martalik lokal endpoint (config'ni bekor qiladi)
uv run systop ntp [--servers a,b]     # soat siljishi (SNTP, clock skew)
uv run systop route              # marshrut jadvali + next-hop yetishuvi
uv run systop mtu [HOST] [--low 1200 --high 1500]   # path MTU (DF-ping ikkilik qidiruv)
uv run systop dhcp [--listen 4.0]     # DHCP server(lar) — rogue DHCP aniqlash
uv run systop arpwatch [--no-update|--reset]   # ARP/NDP diff (MAC almashishi, dublikat)
uv run systop wifi [--neighbours]     # Wi-Fi signal/SNR/kanal (+ qo'shni AP'lar)
uv run systop config [--path|--show]   # konfiguratsiya fayli / samarali sozlamalar

# Global (skriptga mos) bayroqlar — har bir buyruqda:
#   --json / --format {table,json,csv}   mashinaga mos chiqish (sof stdout)
#   -q/--quiet, -v/--verbose, --no-color (NO_COLOR env ham)
# Exit kodlari: 0 OK, 1 umumiy xato, 2 yetib bo'lmadi/o'lik/muddat tugagan/resolve yo'q

uv run pytest                    # barcha testlar (offline)
uv run pytest tests/test_core.py::test_interface_cidr   # bitta test
uv run ruff check .              # lint
uv run ruff format .             # format
uv run textual run --dev systop.app:SystopApp   # TUI'ni dev/debug rejimida (console: `textual console`)
```

## Arxitektura

Ikki qatlamga qat'iy ajratilgan — **core mantiq TUI'dan mustaqil**:

Quyidagi daraxt — **to'liq** ro'yxat (`src/` dagi har bir modul shu yerda).
Yangi modul qo'shsangiz shu daraxtga ham qo'shing.

```
src/systop/
  __main__.py       # `python -m systop` kirish nuqtasi -> cli.main()
  cli.py            # argparse kirish nuqtasi; default -> dashboard, aks holda bir martalik buyruq
                    #   + scriptability qatlami: _resolve_format, emit_json/emit_csv, _to_dict,
                    #     status()/note()/error() (machine rejimda stdout toza), exit kodlar
                    #   subbuyruqlar YAGONA manbasi: `_build_parser()` (docs parity testi shunga qaraydi)
  app.py            # SystopApp (Textual App): status-bar + chap ustun (speed+ping) + topology
  _render.py        # CLI (Rich) chiqishi uchun dizayn qatlami: styled_table + rtt_cell/loss_cell/
                    #   alive_cell gradatsiyasi (30/100 ms, 50% loss chegaralari TUI bilan bir xil).
                    #   FAQAT "table" rejimi; JSON/CSV bunga bog'liq emas.
                    #   DIQQAT: `glyph`/`data_cell` bu yerda EMAS — `widgets/_glyphs.py` da
                    #   (aylanma import'ni oldini olish uchun ataylab shunday joylashtirilgan)
  styles.tcss       # dashboard CSS (grid, panel ramkalari, sparkline ranglari)
  core/             # tarmoq mantiqi — async, Textual'ga bog'liq EMAS, alohida ham ishlatsa bo'ladi
    _platform.py    #   ★ OS strategiya qatlami — HAR QANDAY platforma shoxi SHU YERDA:
                    #     IS_WINDOWS/IS_MACOS/IS_LINUX, `run_command(cmd, timeout, include_stderr)`
                    #     (yagona async subprocess yordamchisi), decode_console (Windows OEM cp),
                    #     init_console/unicode_ok, Win32 IcmpSendEcho ping/traceroute (ctypes),
                    #     parse_windows_ping / _tracert / _route_print.
                    #     Yangi OS buyrug'i chaqirmoqchi bo'lsangiz `subprocess`ni O'ZINGIZ
                    #     yozmang — `run_command` ni ishlating. `include_stderr=True` esdan
                    #     chiqsa haqiqiy bug tug'iladi: macOS `ping` "Message too long" ni
                    #     stderr'ga yozadi va path-MTU aniqlash butunlay ishlamay qolgan edi.
    netinfo.py      #   interfeyslar (psutil), default_gateway (OS route jadvali), public_ip; gather_summary
    ping.py         #   ping_once/ping_many (icmplib async_*), build_targets(gateway), ping_stream (--watch)
    speed.py        #   run_speedtest -> Cloudflare __down/__up, vaqt-cheklangan parallel oqim + warmup
    topology.py     #   trace_path/traceroute (asyncio.to_thread), trace_stream (mtr), discover_lan (ping+ARP+vendor)
    ports.py        #   scan_host -> asyncio TCP connect port skaner (stdlib, parallel, semaphore), parse_ports
                    #     + family (auto|ipv4|ipv6), family_of() sof funksiya
    netcat.py       #   `nc` — xom TCP/TLS MIJOZ (listen rejimi yo'q, root kerak emas):
                    #     ulanish + ixtiyoriy --send + javob (matn yoki hexdump), IPv6 to'liq
    webscan.py      #   discover_web/probe_service -> HTTP barmoq izi + admin panel;
                    #     classify() SOF funksiya (tarmoqsiz, offline sinaladi)
    diagnose.py     #   run_diagnostics -> Report(Finding[]); evaluate_* SOF baholovchilar,
                    #     Thresholds, RISKY_LISTENERS, is_management_device
    dns.py          #   diagnose_dns -> tizim resolve + dig/nslookup bilan serverlar latency taqqoslash
    bandwidth.py    #   sample_bandwidth/bandwidth_stream -> per-interfeys RX/TX/pps (psutil delta)
    tls.py          #   check_tls (sertifikat: days_left/issuer/SAN/version), check_http (status/redirect/vaqt)
    connections.py  #   list_connections -> psutil.net_connections + jarayon nomi (sinxron, to_thread orqali)
                    #     + scan_connections -> ConnScan(permitted, source): macOS'da psutil root'siz
                    #       HAR DOIM AccessDenied => `netstat -an -p tcp` zaxira yo'li
    ntp.py          #   check_ntp -> SNTP (stdlib UDP/123), soat siljishi/offset/delay; root kerak emas
    routes.py       #   marshrut jadvali (`ip route`/`netstat -rn`/`route print`) + next-hop yetishuvi;
                    #     parse_* SOF funksiyalar (ikki default marshrut, VPN 0.0.0.0/1 nayrangi)
    mtu.py          #   discover_path_mtu -> DF-ping ikkilik qidiruv; classify_ping_output SOF
                    #     (ok | too_big | no_reply — aralashtirilsa ICMP bloklangan hostda MTU 0 chiqadi)
    dhcp.py         #   DHCP DISCOVER (ephemeral portdan, root'siz) + lease manbasi; rogue DHCP.
                    #     Javob kelmasligi "server yo'q" DEGANI EMAS => `partial=True`
    arpwatch.py     #   ARP/NDP snapshot + baseline diff (MAC almashishi, IP dublikati, yangi host);
                    #     diff_snapshots SOF funksiya, baseline config katalogida JSON
    wifi.py         #   Wi-Fi signal/SNR/kanal/diapazon/PHY + qo'shni AP'lar; har OS'da root'siz
                    #     manba (system_profiler / iw / netsh), parse'lar SOF funksiya
    config.py       #   load_config -> ~/.config/systop/config.toml (tomllib), SystopConfig dataclass, SYSTOP_CONFIG
                    #     speed_local_urls default'i ATAYLAB bo'sh (IX har mamlakatda boshqacha);
                    #     http:// ham, https:// ham oq ro'yxatda
    oui.py          #   lookup_vendor(mac) -> OUI vendor (offline), normalize_oui, is_locally_administered
  data/
    oui_min.py      #   o'rnatilgan kichik OUI->vendor jadvali (~60 vendor; to'liq IEEE bazasi emas)
  widgets/          # core'ni chaqiruvchi Textual panellari (har biri @work bilan async ish bajaradi)
    _glyphs.py      #   ★ glyph()/data_cell()/dash()/ellipsis() + unicode_ok() — Unicode yoki ASCII
                    #     fallback (eski cmd.exe). `cli.py` VA barcha widget'lar belgini shu yerdan
                    #     oladi. Nega `_render.py` da emas: `_render` <- `_glyphs` bog'lanishi bir
                    #     tomonlama qolishi uchun (aylanma import'ni oldini olish)
    status_bar.py   #   tepa holat-paneli (gateway/public IP/interfeys)
    speed_panel.py  #   tezlik paneli (sparkline)
    ping_panel.py   #   ping paneli (jonli jadval)
    help_screen.py  #   `?` bilan ochiladigan yordam modali
    topology_panel.py #   6 tab: LAN, traceroute, port skan, DNS, bandwidth, ulanishlar
                      #   (har biri alohida @work group'i: lan/trace/scan/dns/bw/conn)
```

**Ma'lumot oqimi:** `widgets/*` va `cli.py` — bu yagona ikki chaqiruvchi.
Ikkalasi ham `core/*` ning bir xil async funksiyalarini chaqiradi. Yangi
o'lchov qo'shganda: avval `core/`da sof async funksiya yoz (UI'siz, dataclass
qaytar), keyin uni `cli.py`da Rich jadval + JSON/CSV bilan, `widgets/`da panel
bilan ulang. CLI'da JSON/CSV avtomatik ishlaydi: `_to_dict` dataclass'larni
(va `loss_pct`/`cidr`/`total_bps`/`is_open` kabi property'larni) seriyalashtirib
beradi — yangi dataclass faqat shu property'larni mos nomlasa kifoya.

### Muhim qarorlar (kontekstdan ko'rinmaydigan)

- **`getaddrinfo` AAAA'ni YASHIRADI.** Hostda global IPv6 marshruti bo'lmasa OS
  AAAA'ni butunlay filtrlab, `::ffff:1.2.3.4` (IPv4-mapped) beradi — RFC 6724
  manzil tanlash. Diagnostika tooli DNS **nima deyotganini** ko'rsatishi kerak,
  shuning uchun haqiqiy AAAA `dig +short AAAA` orqali alohida olinadi va
  `::ffff:` shakllari A ro'yxatidan tashlanadi.
- **Banner: TLS portlarini avval handshake qiling.** 443/4081/8006/8443... ga
  ochiq matnli HTTP yuborish faqat "400 Bad Request" beradi. `_TLS_PORTS`
  ro'yxatidagi portlar `ssl=` bilan ulanadi, shundan keyin so'rov ketadi.
- **`idna` kodeki `errors=` argumentini QO'LLAB-QUVVATLAMAYDI.**
  `host.encode("idna", "ignore")` -> `UnicodeError`, keng `except` esa uni yutib,
  banner'ni jimgina yo'q qilardi. Host header uchun ASCII kifoya.
- **IPv6 CIDR sweep qilinmaydi.** `parse_targets` IPv6 `/64` ni ataylab rad
  etadi (2^64 manzil); bitta IPv6 manzil esa qabul qilinadi. IPv6 hostlarni
  topish uchun `discover_lan6`.
- **`trace` IPv6'da root talab qiladi (macOS).** ICMPv6 datagram socket'i
  privileged — ICMPv4'dan farqli. Bu OS cheklovi, kodda tuzatilmaydi.

- **Admin panel aniqlash — mahsulot izi YOLG'IZ yetarli emas.** `webscan`da
  barmoq izlari ikki sinfga bo'lingan: `admin` (Kerio/Hikvision/Proxmox — +2
  ball) va `infra` (nginx/Apache/Caddy/Traefik — **0 ball**, faqat
  identifikatsiya). Bu bo'linishsiz oddiy nginx welcome sahifasi "admin panel"
  deb belgilanardi. Naqshlar ham ataylab uzun: qisqa bo'lak (`hass`, `syno`,
  yalang'och `docker`) boshqa so'z ichiga tushib soxta natija beradi
  (`chassis` -> `hass`).
- **IPv6 LAN discovery sweep EMAS.** /64 da 2^64 manzil bor — ping sweep
  imkonsiz. `discover_lan6` `ff02::1` (all-nodes multicast) ga ping yuborib,
  keyin OS qo'shni jadvalini o'qiydi (`ip -6 neigh` / `ndp -an` / `netsh`).
  Zona qo'shimchasi (`fe80::1%en0`) **saqlanadi** — link-local manzil zonasiz
  ishlatilmaydi. macOS qisqa MAC oktet beradi (`0:1c:42:3:4:5`) — `parse_ndp_output`
  ikki raqamga to'ldiradi.
- **Skan tezligi ataylab past.** `web`/`doctor` default `concurrency=16`,
  `--polite` esa 4 + 300 ms. Sabab: tez keng skan IPS/anti-scan himoyasini
  qo'zg'atadi va skanerlovchi IP vaqtincha bloklanadi. Alomat chalg'ituvchi —
  ICMP ishlaydi, mavjud ulanishlar ishlaydi, faqat YANGI TCP "Connection
  refused" beradi (2026-07-28 da aynan shu bilan soatlab yo'ldan chiqilgan).
- **`_to_dict` property ro'yxati — jim yo'qotish manbasi.** Yangi dataclass
  property qo'shsangiz `cli.py`dagi ro'yxatga ham qo'shing, aks holda u
  `--json`/`--format csv` chiqishida **jimgina yo'q** bo'ladi. Hozirgi ro'yxat:
  `loss_pct, cidr, total_bps, is_open, url, risk, is_link_local, is_problem,
  worst_severity, counts`.
- **`diagnose` bosqichlari mustaqil.** `run_diagnostics`da har tekshiruv alohida
  `try` ichida va xatoni `report.skipped`ga yozadi. Diagnostika tooli o'zi
  yiqilsa foydasi yo'q — bitta tekshiruv (masalan DNS) buzilsa qolganlari
  natija berishi kerak.
- **`evaluate_*` sof, orkestrator emas.** Baholash mantiqi tarmoq chaqiruvidan
  ajratilgan, shuning uchun butun test to'plami offline ishlaydi (aniq son
  uchun `uv run pytest -q` ga qarang — bu yerga raqam yozmang, eskiradi).
  Yangi tekshiruv qo'shganda ham shu shaklni saqlang: o'lchovni argument qilib
  oling, `Finding` qaytaring.

- **Tezlik `speedtest-cli`siz.** Eskirgan kutubxona o'rniga Cloudflare'ning
  ochiq endpointlari ishlatiladi (`speed.cloudflare.com/__down`, `/__up`).
  O'lchov **vaqt bilan chegaralangan**: bir nechta parallel ulanish ochiladi,
  `duration` soniya o'tgach umumiy `stop` event o'rnatilib, baytlar/elapsed dan
  Mbps hisoblanadi. `_run_phase` va worker'lar **bitta `stop` event**ni baham
  ko'rishi shart — alohida event berilsa to'xtatish ishlamaydi.
- **ICMP root'siz.** `icmplib`ga hamma joyda `privileged=False` beriladi
  (macOS/Linux SOCK_DGRAM ICMP). Standartni o'zgartirma — aks holda `sudo`
  talab qilinadi. traceroute ham shu rejimda. Windows `icmplib`dan umuman
  o'tmaydi: `_platform.win_icmp_ping`/`win_icmp_traceroute` (Win32
  `IcmpSendEcho`) ishlatiladi va u ham Administrator talab qilmaydi. Yagona
  istisno — macOS'da IPv6 `trace` (pastdagi qarorga qarang).
- **LAN discovery scapy'siz.** Root kerak bo'lmasligi uchun: `/24` ni ping
  sweep (`async_multiping`) + OS ARP jadvalini (`arp -a` / `ip neigh`) regex
  bilan o'qish. `max_hosts` katta tarmoqlarni cheklaydi.
- **traceroute sinxron.** `icmplib.traceroute` async emas, shuning uchun
  `asyncio.to_thread` orqali chaqiriladi — event loop bloklanmasligi uchun.
- **Textual worker'lari.** Panellardagi tarmoq ishi `@work(exclusive=True)`
  metodlarda. Async worker'lar event loop'da ishlaydi, shuning uchun progress
  callback'lardan widget'larni **to'g'ridan-to'g'ri** yangilash xavfsiz
  (`call_from_thread` shart emas). `TopologyPanel`dagi 4 amal (LAN/trace/scan/dns)
  **har biri alohida `group=`** bilan — aks holda bitta default group'da bo'lib,
  biri ishga tushganda ikkinchisini bekor qilardi (masalan LAN skan + DNS birga
  ishlay olmasdi).
- **speed.py'da event loop starvation.** `_download_stream`/`_upload_stream`
  `stop` o'rnatilguncha qayta-qayta so'rov yuboradi (Cloudflare `__down` 100 MB'ga
  403 qaytargani uchun ~50 MB bo'laklab). Har so'rovdan keyin **`await
  asyncio.sleep(0)`** SHART: darhol javob beruvchi transport (test mock'i)
  bilan monitor coroutine och qolib, `stop` hech qachon o'rnatilmasligining
  oldini oladi. `warmup` (default 1s) — TCP slow-start baytlarini o'lchovdan
  chiqaradi (aniqroq Mbps).
- **ICMP/port skan testsiz.** Tarmoqli funksiyalar (ping/traceroute/scan/dns)
  offline sinab bo'lmaydi; speed.py esa `httpx.MockTransport` bilan tarmoqsiz
  sinaladi (`tests/test_speed.py`). Mock darhol javob bergani uchun yuqoridagi
  `sleep(0)` bo'lmasa test osilib qoladi.
- **Scriptability — yagona JSON/CSV qatlami.** Chiqish formati `cli.py`dagi
  global `_FORMAT` (table|json|csv) bilan boshqariladi (`_resolve_format`:
  `--format` > `--json` > table). Mashina rejimida (`_is_machine()`) status
  spinner, izoh va Rich jadval **bostiriladi** — faqat sof natija stdout'ga,
  xato esa stderr'ga (`error()`). Buyruq handler'lari `core/` dataclass'ini
  oladi va `emit_json`/`emit_csv`/Rich jadvalga uzatadi. **Yangi maydon =
  yangi qator JSON'da avtomatik** — `_to_dict` `dataclasses.fields` bo'ylab
  yuradi, `_`-prefiksli ichki maydonlarni tashlaydi va tanlangan property'larni
  (`loss_pct`/`cidr`/`total_bps`/`is_open`) qo'lda qo'shadi.
- **Exit-kod sxemasi.** `0` OK, `1` umumiy xato (noto'g'ri argument / istisno —
  `main()`da tutiladi), `2` "yetib bo'lmadi" (host o'lik, hech bir port ochiq
  emas, sertifikat muddati tugagan/yaqin, DNS resolve yo'q, traceroute hopsiz).
  Har handler `int` qaytaradi; `tls`/`http` uchun alohida `_tls_exit_code`/
  `_http_exit_code` (status>=400 yoki days_left<=warn_days => 2). `--watch`/`mtr`
  jonli rejimi mashina formatida ishlamaydi (xato beradi); `mtr --json` bir
  necha cycle olib oxirgi snapshot'ni chiqaradi.
- **Upload bayt-fix.** `speed.py` upload fazasida **haqiqatda yuborilgan**
  baytlar sanaladi (generator/streamda har chunk hisoblanadi), aks holda Mbps
  noto'g'ri (juda yuqori) chiqardi. Download bilan bir xil `stop` event-time
  mantiqi.
- **`trace_stream` — mtr asosida.** `mtr` va `trace --continuous` `core`'dagi
  `trace_stream(host, interval, cycles)` async generatoridan oziqlanadi: har
  cycle'da hop'larni qayta probe qilib, per-hop `HopStat` (loss%/last/avg/best/
  worst) ni yangilab beradi. CLI buni `rich.Live` bilan jonli ko'rsatadi;
  `cycles=None` => cheksiz (Ctrl+C to'xtatadi).
- **OUI vendor — offline.** LAN discovery'da MAC'dan vendor `core/oui.py` orqali
  o'rnatilgan kichik jadvaldan (`data/oui_min.py`, ~60 vendor) aniqlanadi —
  tarmoqqa chiqmaydi, qo'shimcha bog'liqlik yo'q. Lokal-tayinlangan
  (locally-administered) MAC global vendorni bildirmaydi => `None`. To'liq IEEE
  bazasi (~30k) maqsadli ravishda QO'SHILMAGAN (fayl hajmi).
- **Konfiguratsiya — ixtiyoriy, jim default.** `core/config.py` faqat stdlib
  (`tomllib`); fayl yo'q/buzuq/ruxsatsiz bo'lsa to'liq default `SystopConfig`
  qaytadi (istisno YO'Q). Faqat tanilgan kalitlar, noto'g'ri turdagi qiymat jim
  e'tiborsiz. Yo'l tartibi: argument > `SYSTOP_CONFIG` env > `~/.config/systop/
  config.toml`. `core/config.py` boshqa core modullarni import qilmaydi.

## Konvensiyalar

- Foydalanuvchiga ko'rinadigan matn (panel sarlavhalari, jadval ustunlari,
  xato xabarlari, docstring'lar) — **o'zbek tilida**. Kod identifikatorlari
  ingliz tilida.
- Har bir `core/` funksiyasi dataclass yoki oddiy qiymat qaytaradi (UI obyekti
  emas), shunda CLI ham, TUI ham, testlar ham bir xil ishlatadi.
- Testlar **offline** bo'lishi kerak (tarmoqqa kirmasin) — regex, dataclass,
  `build_targets` kabi sof mantiqni sina. Tarmoqli funksiyalarni sinab bo'lmaydi.
- **Hujjatlar kod bilan bir qadamda.** `tests/test_docs.py` `_build_parser()`
  dagi har bir subbuyruq `README.md` va `README.uz.md` da uchrashini, hamda
  `cli.py` modul docstring'idagi buyruqlar to'plami parser bilan AYNAN teng
  ekanini tekshiradi. Yangi subbuyruq = uchala joyni ham yangilash.
- **Platforma shoxi faqat `core/_platform.py` da.** Boshqa modulda
  `platform.system()`/`subprocess` yozmang; `_platform.run_command(...)` ni
  chaqiring va OS xabari stderr'ga chiqadigan bo'lsa `include_stderr=True` ni
  unutmang.
