# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Loyiha

`systop` — sysadminlar uchun root talab qilmaydigan terminal tarmoq tooli
(TUI + CLI). 12 ta tarmoq vazifasi bitta toolda: internet tezligi, lokal+global
ping, traceroute/mtr, LAN discovery, port skan, DNS taqqoslash, per-interfeys
bandwidth, TLS/HTTP tekshiruvi, faol ulanishlar. Har bir buyruq scriptlarga mos
(`--json`/`--format`, mazmunli exit kodlar). Stack: **Python 3.11+**, **Textual**
(TUI), **httpx**, **icmplib**, **psutil**. Paket menejeri: **uv**.

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

```
src/systop/
  cli.py            # argparse kirish nuqtasi; default -> dashboard, aks holda bir martalik buyruq
                    #   + scriptability qatlami: _resolve_format, emit_json/emit_csv, _to_dict,
                    #     status()/note()/error() (machine rejimda stdout toza), exit kodlar
  app.py            # SystopApp (Textual App): status-bar + chap ustun (speed+ping) + topology
  styles.tcss       # dashboard CSS (grid, panel ramkalari, sparkline ranglari)
  core/             # tarmoq mantiqi — async, Textual'ga bog'liq EMAS, alohida ham ishlatsa bo'ladi
    netinfo.py      #   interfeyslar (psutil), default_gateway (OS route jadvali), public_ip; gather_summary
    ping.py         #   ping_once/ping_many (icmplib async_*), build_targets(gateway), ping_stream (--watch)
    speed.py        #   run_speedtest -> Cloudflare __down/__up, vaqt-cheklangan parallel oqim + warmup
    topology.py     #   trace_path/traceroute (asyncio.to_thread), trace_stream (mtr), discover_lan (ping+ARP+vendor)
    ports.py        #   scan_host -> asyncio TCP connect port skaner (stdlib, parallel, semaphore), parse_ports
    dns.py          #   diagnose_dns -> tizim resolve + dig/nslookup bilan serverlar latency taqqoslash
    bandwidth.py    #   sample_bandwidth/bandwidth_stream -> per-interfeys RX/TX/pps (psutil delta)
    tls.py          #   check_tls (sertifikat: days_left/issuer/SAN/version), check_http (status/redirect/vaqt)
    connections.py  #   list_connections -> psutil.net_connections + jarayon nomi (sinxron, to_thread orqali)
    config.py       #   load_config -> ~/.config/systop/config.toml (tomllib), SystopConfig dataclass, SYSTOP_CONFIG
    oui.py          #   lookup_vendor(mac) -> OUI vendor (offline), normalize_oui, is_locally_administered
  data/
    oui_min.py      #   o'rnatilgan kichik OUI->vendor jadvali (~60 vendor; to'liq IEEE bazasi emas)
  widgets/          # core'ni chaqiruvchi Textual panellari (har biri @work bilan async ish bajaradi)
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

- **Tezlik `speedtest-cli`siz.** Eskirgan kutubxona o'rniga Cloudflare'ning
  ochiq endpointlari ishlatiladi (`speed.cloudflare.com/__down`, `/__up`).
  O'lchov **vaqt bilan chegaralangan**: bir nechta parallel ulanish ochiladi,
  `duration` soniya o'tgach umumiy `stop` event o'rnatilib, baytlar/elapsed dan
  Mbps hisoblanadi. `_run_phase` va worker'lar **bitta `stop` event**ni baham
  ko'rishi shart — alohida event berilsa to'xtatish ishlamaydi.
- **ICMP root'siz.** `icmplib`ga hamma joyda `privileged=False` beriladi
  (macOS/Linux SOCK_DGRAM ICMP). Standartni o'zgartirma — aks holda `sudo`
  talab qilinadi. traceroute ham shu rejimda.
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
