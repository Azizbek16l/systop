# systop

> Sysadminlar uchun root talab qilmaydigan terminal tarmoq tooli (TUI + CLI) —
> tezlik, ping, traceroute/mtr, LAN discovery, port skan, DNS, bandwidth,
> TLS/HTTP va ulanishlar — barchasi bitta toolda.

[English](README.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

[![CI](https://img.shields.io/badge/CI-pending-lightgrey)](#)
[![PyPI](https://img.shields.io/badge/PyPI-soon-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

<!-- Terminal yozuvini `demo.tape` dan charmbracelet/vhs bilan yasash mumkin
     (`vhs demo.tape`); hozircha repoga qo'shilmagan, shuning uchun rasm yo'q. -->

---

## Nega systop?

Tarmoqni diagnostika qilish odatda bir nechta tor-maxsus toolni qatorlashni
anglatadi: `ping`, `mtr`, `traceroute`, `dig`, `nmap`, `openssl s_client`,
`iftop`, `ss`/`netstat`, ustiga brauzerda ochilgan speed-test sahifasi. Har
birining o'z bayroqlari, o'z chiqish formati bor; ba'zilari root talab qiladi.

`systop` sysadminning kundalik tarmoq vazifalarini **bitta toolga** jamlaydi:

- **Uch platformada, root kerak emas.** **Linux, Windows va macOS** da ishlaydi.
  ICMP Linux/macOS'da unprivileged datagram soketlar (`SOCK_DGRAM`), Windows'da
  esa Win32 `IcmpSendEcho` API orqali — ya'ni `ping`, `traceroute` va `mtr`
  hech qaysi platformada `sudo`/Administrator talab qilmaydi. Platformaga oid
  bir nechta chegara uchun [Platforma qo'llovi](#platforma-qollovi) ga qarang.
- **Ikki xil rejim.** Interaktiv monitoring uchun to'liq-ekran **Textual TUI
  dashboard**, qolgan hamma narsa uchun **bir martalik CLI buyruqlari**.
- **Scriptlarga mos.** Har bir buyruq `--json` / `--format csv` ni qo'llaydi,
  stdout toza qoladi va **mazmunli exit kodlar** qaytaradi — monitoring
  skriptlari, CI tekshiruvlari va cron ishlariga bevosita ulanadi.
- **Offline sinaladigan va yengil.** Sof Python core, `nmap`/`scapy`/
  `speedtest-cli` ishlatmaydi. OUI (MAC vendor) jadvali ichida keladi.

Tarmoq mantiqi UI'dan mustaqil `core/` qatlamida — bir xil async funksiyalar
TUI, CLI va testlarni ta'minlaydi. Test to'plami butunlay offline ishlaydi
(`uv run pytest` tarmoqqa umuman chiqmaydi).

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
| **Boshqaruv paneli topish**|   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Muammoni avto topish**   |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **IPv6 (skan + discovery)**|   ✅   |  —    |   —    |  ✅ |   —   |    —      |
| **LAN bo'ylab port sweep** |   ✅   |  —    |   —    |  —  |   ✅  |    —      |
| **Xizmat bannerlari (-sV)**|   ✅   |  —    |   —    |  —  |   ✅  |    —      |
| **Xom TCP/TLS mijoz**      |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Soat siljishi (SNTP)**   |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Marshrut + next-hop**    |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Path MTU aniqlash**      |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Rogue DHCP aniqlash**    |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **ARP/NDP o'zgarish kuzatuvi** | ✅ |  —    |   —    |  —  |   —   |    —      |
| **Wi-Fi signal / kanal**   |   ✅   |  —    |   —    |  —  |   —   |    —      |
| Interaktiv TUI             |   ✅   |  ✅   |   ✅   |  —  |   —   |    ✅     |
| JSON chiqish               |   ✅   |  —    |   ✅   |  ✅ |   ✅  |    —      |
| Root kerak emas            |   ✅   |  ✅   |  ⚠️*  |  ✅ |   ✅  |   ⚠️*    |
| Bitta toolda yuqoridagilar |   ✅   |  —    |   —    |  —  |   —   |    —      |

<sub>✅ qo'llab-quvvatlanadi · — bu toolning vazifasi emas · ⚠️ platforma/rejimga
bog'liq. Bu jadval har bir toolning asosiy maqsadini aks ettiradi;
mutaxassislar odatda o'z sohasida chuqurroq ishlaydi.</sub>

---

## O'rnatish

systop **Python 3.11+** talab qiladi va **Linux, Windows hamda macOS** da
ishlaydi.

### Mustaqil binar (Python kerak emas)

Har bir teg qo'yilgan reliz sahifasida
([Releases](https://github.com/azizbek/systop/releases)) har platforma uchun
o'zi-yetarli bajariladigan fayl bo'ladi — yuklab oling, bajariladigan qiling,
ishga tushiring:

| Platforma | Fayl |
|-----------|------|
| Windows   | `systop-windows-x86_64.exe` |
| Linux     | `systop-linux-x86_64` |
| macOS     | `systop-macos-arm64` |

```powershell
# Windows (PowerShell)
.\systop-windows-x86_64.exe
```
```bash
# Linux / macOS
chmod +x systop-linux-x86_64 && ./systop-linux-x86_64
```

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
systop dashboard             # xuddi shu, ochiq yozilgani

systop speed                 # download / upload / latency / jitter
systop speed --local         # lokal (IX) endpointlarni ham o'lchaydi (speed_local_urls)
systop speed --local-url URL # bir martalik lokal endpoint (bir necha marta berish mumkin)
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
systop scan 10.0.0.0/24 --top 20        # LAN bo'ylab port sweep
systop scan example.com --banner        # xizmat versiyasi (yengil -sV)
systop scan -6 example.com              # IPv6 skan (-4 majburan IPv4)

systop nc example.com 25                # xom TCP ulanish (ncat uslubi)
systop nc example.com 6379 --send 'PING\r\n'
systop nc example.com 443 --tls --hex   # TLS handshake, javob hexdump bilan

systop dns example.com       # resolve + ommaviy DNS serverlar latency'sini taqqoslash
systop lan                   # LAN host discovery (IP / MAC / vendor / hostname)
systop lan -6                # IPv6 ham (ff02::1 multicast + NDP jadval)
systop lan -6 --global-only  # link-local (fe80::) manzillarni chiqarib tashlash

systop bw                    # per-interfeys bandwidth (RX/TX) snapshot
systop bw --watch            # jonli bandwidth monitor

systop tls example.com       # TLS sertifikat: muddat, issuer, SAN, versiya
systop tls example.com:8443 --warn-days 30
systop http https://example.com   # HTTP status, redirect, vaqt

systop conn                  # faol tarmoq ulanishlari
systop conn --listen         # faqat LISTEN holatdagilar

systop web                   # LAN'dagi web xizmatlar + boshqaruv panellari
systop web --http80          # faqat 80-port: lokal HTTP ochiqligini topish
systop web --mgmt            # faqat tarmoq qurilmalari (router/firewall/switch/NVR)
systop web --polite          # sekin rejim (IPS/anti-scan bor tarmoq uchun)

systop doctor                # tarmoq muammolarini jiddiylik bo'yicha avto topish
systop doctor --quick        # tez rejim (web skan va IPv6 tashlanadi)

systop ntp                   # soat siljishi (SNTP) — auth/TLS jimgina buzilishining sababi
systop route                 # marshrut jadvali + next-hop yetishuvi
systop mtu                   # path MTU (DF-ping ikkilik qidiruv, default 1.1.1.1)
systop mtu example.com --low 1200 --high 1500
systop dhcp                  # DHCP server(lar)ni aniqlash — rogue DHCP ni topadi
systop arpwatch              # oxirgi ishga tushishdan beri ARP/NDP o'zgarishi
systop wifi                  # Wi-Fi signal / SNR / kanal / diapazon / PHY
systop wifi --neighbours     # atrofdagi AP'lar (kanal tiqilinchi)

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

### `speed_local_urls` — lokal (IX) tezlik endpointlari

`systop speed --local` lokal endpointlargacha tezlikni o'lchab, uni xalqaro
natija bilan yonma-yon qo'yadi. Bu speed-test sayti javob bera olmaydigan
savolni yechadi: "kanalim sekinmi, yoki faqat chet elga chiqish yo'li
sekinmi?"

Endpointlar **ataylab kodga yozilmagan** — ular har mamlakatda boshqacha.
TAS-IX mirrorlarini manbaga yozib qo'yish tool'ni bitta mamlakatga bog'lab
qo'yardi va boshqa yurtda jimgina noto'g'ri raqam berardi. Shuning uchun
`core/config.py` default'i bo'sh, ro'yxatni o'zingiz berasiz. Oddiy HTTP
mirror uchun ham kodni o'zgartirish shart emas: `config.py` allaqachon
`http://` va `https://` ni ikkalasini ham qabul qiladi (qolgan hammasi
tashlanadi).

```toml
speed_local_urls = [
  "https://speedtest.uz/backend/garbage.php?ckSize=100",
  "http://speedtest.spy.uz/backend/garbage.php?ckSize=100",  # http:// — sertifikat boshqa nomga
  "http://mirror.dc.uz/rockylinux/9/isos/x86_64/Rocky-9-latest-x86_64-boot.iso",
]
```

Yuqoridagi ro'yxat — ishlaydigan O'zbekiston (TAS-IX) to'plami. Boshqa yurtda
o'sha yurtning IX mirroriga yo'naltiring: katta faylni HTTP(S) orqali
beradigan har qanday URL yaraydi. Bir martalik o'lchov uchun config fayli
umuman shart emas:

```bash
systop speed --local                     # config'dagi speed_local_urls
systop speed --local-url https://mirror.example.uz/100MB.bin   # takrorlanadi
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

## Platforma qo'llovi

systop **Linux, Windows va macOS** da ishlaydi va har bir buyruq oddiy
foydalanuvchi huquqi bilan ishlashga mo'ljallangan. OS buni imkonsiz qilgan
joyda systop yiqilmaydi — zaifroq manbaga tushadi va buni chiqishida ochiq
aytadi.

| Soha | Linux | Windows | macOS |
|------|-------|---------|-------|
| `ping` / `trace` / `mtr` (IPv4) | `icmplib`, `SOCK_DGRAM`, root kerak emas | Win32 `IcmpSendEcho` (ctypes), Administrator kerak emas | `icmplib`, `SOCK_DGRAM`, root kerak emas |
| `trace` IPv6'da | root kerak emas | Administrator kerak emas | **root talab qiladi** — macOS'da ICMPv6 datagram soketi privileged. Bu OS cheklovi, systop xatosi emas |
| `conn` | psutil (jarayon nomlari bilan) | psutil (jarayon nomlari bilan) | psutil root'siz HAR DOIM `AccessDenied` beradi, shuning uchun `netstat -an -p tcp` ga tushiladi — portlar to'liq, lekin **PID/jarayon nomi yo'q**. Manba `--json` da ko'rsatiladi |
| `mtu` | `ping -M do` | `ping -f -l` | `ping -D` ("Message too long" **stderr**'ga chiqadi, systop uni ham o'qiydi) |
| `route` | `ip route` | `route print` | `netstat -rn` |
| `wifi` | `iw dev <iface> link` / `scan` | `netsh wlan show interfaces` (chiqish mahalliylashtirilgan — systop bir necha tilni parse qiladi) | `system_profiler SPAirPortDataType` (`airport -I` macOS 14.4 dan olib tashlangan, `wdutil` esa sudo talab qiladi — ikkalasi ham ishlatilmaydi) |
| `dhcp` | `dhclient` lease fayllari | `ipconfig /all` | `ipconfig getpacket` |
| Konsol kodlash / belgilar | UTF-8 | OEM codepage ochiq dekodlanadi; eski `cmd.exe` da Unicode belgilar ASCII ga tushadi | UTF-8 |

Platformaga bog'liq xulq bitta joyda — `core/_platform.py` da, shuning uchun
hech bir buyruq o'z subprocess/kodlash mantig'ini yozmaydi.

### Ruxsatlar haqida eslatma (ICMP)

`sudo` kerak emas. `ping`, `traceroute` va `mtr` `icmplib`ga hamma joyda
`privileged=False` beradi (Linux/macOS'da unprivileged ICMP datagram soketlar),
Windows'da esa Administrator talab qilmaydigan `IcmpSendEcho` API ishlatiladi.
Yuqoridagi ikki istisnodan boshqasi yo'q: macOS'da IPv6 `trace` va macOS'da
`conn` ning jarayon-nomi ustuni.

---

## Litsenziya

[MIT](LICENSE) © 2026 Azizbek
