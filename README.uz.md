# systop

> Sysadminlar uchun root talab qilmaydigan terminal tarmoq tooli (TUI + CLI) —
> tezlik, ping, traceroute/mtr, LAN discovery, port skan, DNS, bandwidth,
> TLS/HTTP va ulanishlar — barchasi bitta toolda.

[English](README.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

[![CI](https://img.shields.io/badge/CI-pending-lightgrey)](#)
[![PyPI](https://img.shields.io/badge/PyPI-soon-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

![demo](assets/demo.gif)

<!-- Yuqoridagi GIF `demo.tape` dan charmbracelet/vhs bilan yasaladi (`vhs demo.tape`). -->

---

## Nega systop?

Tarmoqni diagnostika qilish odatda bir nechta tor-maxsus toolni qatorlashni
anglatadi: `ping`, `mtr`, `traceroute`, `dig`, `nmap`, `openssl s_client`,
`iftop`, `ss`/`netstat`, ustiga brauzerda ochilgan speed-test sahifasi. Har
birining o'z bayroqlari, o'z chiqish formati bor; ba'zilari root talab qiladi.

`systop` 12 ta keng tarqalgan tarmoq vazifasini **bitta toolga** jamlaydi:

- **Root kerak emas.** ICMP unprivileged datagram soketlar (`SOCK_DGRAM`)
  orqali ishlaydi (macOS va Linux) — `ping`, `traceroute` va `mtr` `sudo`siz.
- **Ikki xil rejim.** Interaktiv monitoring uchun to'liq-ekran **Textual TUI
  dashboard**, qolgan hamma narsa uchun **bir martalik CLI buyruqlari**.
- **Scriptlarga mos.** Har bir buyruq `--json` / `--format csv` ni qo'llaydi,
  stdout toza qoladi va **mazmunli exit kodlar** qaytaradi — monitoring
  skriptlari, CI tekshiruvlari va cron ishlariga bevosita ulanadi.
- **Offline sinaladigan va yengil.** Sof Python core, `nmap`/`scapy`/
  `speedtest-cli` ishlatmaydi. OUI (MAC vendor) jadvali ichida keladi.

Tarmoq mantiqi UI'dan mustaqil `core/` qatlamida — bir xil async funksiyalar
TUI, CLI va testlarni ta'minlaydi. 200+ offline test.

---

## Imkoniyatlar jadvali

systop'ni keng tarqalgan maxsus toollar bilan taqqoslash. systop maqsadi —
bitta toolda kenglik, har bir mutaxassisni o'z sohasida chuqurlikda yengish
emas.

| Imkoniyat                  | systop | gping | trippy | dog | naabu | bandwhich |
|----------------------------|:------:|:-----:|:------:|:---:|:-----:|:---------:|
| Tezlik testi (down/up)     |   ✅   |  —    |   —    |  —  |   —   |    —      |
| Ping (ko'p nishon)         |   ✅   |  ✅   |   —    |  —  |   —   |    —      |
| Jonli ping monitor         |   ✅   |  ✅   |   —    |  —  |   —   |    —      |
| Traceroute                 |   ✅   |  —    |   ✅   |  —  |   —   |    —      |
| Jonli mtr (per-hop loss)   |   ✅   |  —    |   ✅   |  —  |   —   |    —      |
| LAN discovery + vendor     |   ✅   |  —    |   —    |  —  |   —   |    —      |
| TCP port skan              |   ✅   |  —    |   —    |  —  |   ✅  |    —      |
| DNS resolver taqqoslash    |   ✅   |  —    |   —    |  ✅ |   —   |    —      |
| Per-interfeys bandwidth    |   ✅   |  —    |   —    |  —  |   —   |    ✅     |
| Per-jarayon bandwidth      |   —    |  —    |   —    |  —  |   —   |    ✅     |
| TLS sertifikat tekshiruvi  |   ✅   |  —    |   —    |  —  |   —   |    —      |
| HTTP holat tekshiruvi      |   ✅   |  —    |   —    |  —  |   —   |    —      |
| Faol ulanishlar            |   ✅   |  —    |   —    |  —  |   —   |    —      |
| Interaktiv TUI             |   ✅   |  ✅   |   ✅   |  —  |   —   |    ✅     |
| JSON chiqish               |   ✅   |  —    |   ✅   |  ✅ |   ✅  |    —      |
| Root kerak emas            |   ✅   |  ✅   |  ⚠️*  |  ✅ |   ✅  |   ⚠️*    |
| Bitta toolda yuqoridagilar |   ✅   |  —    |   —    |  —  |   —   |    —      |

<sub>✅ qo'llab-quvvatlanadi · — bu toolning vazifasi emas · ⚠️ platforma/rejimga
bog'liq. Bu jadval har bir toolning asosiy maqsadini aks ettiradi;
mutaxassislar odatda o'z sohasida chuqurroq ishlaydi.</sub>

---

## O'rnatish

systop **Python 3.11+** talab qiladi.

### O'rnatmasdan ishlatish (tez sinash uchun)

```bash
uvx systop            # eng so'nggi versiyani vaqtinchalik muhitda ishga tushiradi
```

### Tool sifatida o'rnatish

```bash
uv tool install systop      # uv bilan
pipx install systop         # pipx bilan
```

### Manbadan

```bash
git clone https://github.com/azizbek/systop
cd systop
uv sync                                   # venv + bog'liqliklar
uv run systop                             # dashboard
uv tool install . --force --reinstall     # `systop` ni PATH'ga qo'yadi
```

### Homebrew

```bash
# brew install systop      # tez orada
```

---

## Ishlatish

Argumentsiz `systop` interaktiv dashboard'ni ochadi. Quyidagi har bir buyruq
bir martalik, scriptlarga mos chaqiriq sifatida ham ishlaydi.

```bash
systop                       # interaktiv TUI dashboard (default)

systop speed                 # download / upload / latency / jitter
systop ping                  # lokal gateway + global nishonlar
systop ping --watch          # jonli ping monitor (Ctrl+C to'xtatadi)
systop ping --ipv6           # IPv6 global nishonlarni ham qo'shadi
systop ping --targets 1.1.1.1,8.8.8.8   # aniq nishonlar

systop trace 1.1.1.1         # traceroute
systop trace 1.1.1.1 --continuous   # `mtr` bilan bir xil
systop mtr 1.1.1.1           # jonli mtr-uslubi: per-hop loss% / avg / best / worst

systop scan example.com                 # TCP port skaner (keng tarqalgan portlar)
systop scan example.com --ports 22,80,443
systop scan example.com --ports 1-1024

systop dns example.com       # resolve + ommaviy DNS serverlar latency'sini taqqoslash
systop lan                   # LAN host discovery (IP / MAC / vendor / hostname)

systop bw                    # per-interfeys bandwidth (RX/TX) snapshot
systop bw --watch            # jonli bandwidth monitor

systop tls example.com       # TLS sertifikat: muddat, issuer, SAN, versiya
systop tls example.com:8443 --warn-days 30
systop http https://example.com   # HTTP status, redirect, vaqt

systop conn                  # faol tarmoq ulanishlari
systop conn --listen         # faqat LISTEN holatdagilar

systop info                  # interfeyslar, gateway, public IP
systop config                # konfiguratsiya fayli yo'li + samarali sozlamalar
```

### Scripting: JSON, CSV va exit kodlari

Har bir buyruq global bayroqlarni qabul qiladi. `--json` / `--format csv`
rejimida stdout mashinaga toza qoladi (status va izohlar stderr'ga boradi).

```bash
systop speed --json
systop ping --format csv
systop tls example.com --json | jq '.days_left'
systop scan host --ports 1-1024 --json

# Bayroqlar: --json, --format {table,json,csv}, -q/--quiet, -v/--verbose, --no-color
# NO_COLOR env ham hurmat qilinadi.
```

**Exit kodlari** (skriptlar farqlay olsin):

| Kod | Ma'no |
|-----|-------|
| `0` | Muvaffaqiyat |
| `1` | Umumiy xato (noto'g'ri argument, ichki xato) |
| `2` | Yetib bo'lmaydi: host o'lik, port yopiq, sertifikat muddati tugagan/yaqin yoki resolve bo'lmadi |

```bash
# Misol: sertifikat 30 kun ichida tugasa CI'ni yiqitish
systop tls example.com --warn-days 30 --json || echo "sertifikat yangilanishi kerak"
```

---

## Dashboard tugmalari

TUI status-bar (gateway / public IP / interfeys), jonli tezlik va ping
panellari, hamda 6-tabli diagnostika panelini (LAN, traceroute, port skan, DNS,
bandwidth, ulanishlar) ko'rsatadi.

| Tugma | Vazifa |
|-------|--------|
| `s`   | Tezlik testi |
| `r`   | Ping yangilash |
| `l`   | LAN skan |
| `t`   | Traceroute fokusi |
| `d`   | Tema (yorug' / qorong'i) |
| `?`   | Yordam |
| `q`   | Chiqish |

---

## Konfiguratsiya

systop ixtiyoriy TOML faylni `~/.config/systop/config.toml` dan o'qiydi (yo'lni
`SYSTOP_CONFIG` atrof-muhit o'zgaruvchisi bilan o'zgartirish mumkin). Fayl yo'q
yoki buzuq bo'lsa, oqilona default qiymatlar jim ishlatiladi — noto'g'ri
qiymatlar e'tiborsiz qoldiriladi, hech qachon halokatli emas.

```toml
# ~/.config/systop/config.toml

ping_targets   = ["1.1.1.1", "8.8.8.8"]   # qo'shimcha ping nishonlari
dns_resolvers  = ["1.1.1.1", "9.9.9.9"]   # `dns` da taqqoslanadigan serverlar
speed_duration = 10.0                       # tezlik testi davomiyligi (soniya)
speed_parallel = 4                          # parallel tezlik oqimlari
theme          = "dark"                     # "dark" yoki "light"
scan_ports     = "1-1024"                   # `scan` uchun default portlar
```

```bash
systop config           # yo'l, mavjudlik, env override, samarali sozlamalar
systop config --path    # faqat konfiguratsiya fayli yo'li (scriptga mos)
systop config --show    # samarali sozlamalarni jadval bilan
systop config --json    # config + _config_path + _config_exists
```

---

## Dasturlash

```bash
uv sync --extra dev               # dev bog'liqliklarini o'rnatadi

uv run pytest                     # offline test to'plamini ishga tushiradi
uv run pytest tests/test_core.py::test_interface_cidr   # bitta test
uv run ruff check .               # lint
uv run ruff format .              # format

uv run textual run --dev systop.app:SystopApp   # TUI dev rejimda
# (jonli loglar uchun boshqa terminalda `textual console`)
```

Kod qat'iy ikki qismga ajratilgan: UI'dan mustaqil async `core/` qatlam va uning
ikki chaqiruvchisi (`cli.py` va Textual `widgets/`). Konvensiyalar (offline-test
qoidasi va o'zbekcha UI-matn qoidasi) uchun [CONTRIBUTING.md](CONTRIBUTING.md)
ga qarang.

---

## Ruxsatlar haqida eslatma (ICMP)

`ping`, `traceroute` va `mtr` `privileged=False` (unprivileged ICMP datagram
soketlar) rejimida ishlaydi, shuning uchun macOS va Linux'da root kerak emas.
Agar tizimingiz unprivileged ICMP soketlarni bloklasa, `sudo` bilan ishga
tushiring yoki core funksiyalarda `privileged=True` qo'ying. Faol ulanishlar
ko'rinishi (`conn`) macOS'da root bilan to'liqroq jadval ko'rsatishi mumkin.

---

## Litsenziya

[MIT](LICENSE) © 2026 Azizbek
