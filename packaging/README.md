# systop — standalone binar yig'ish (packaging/)

Maqsad: Python o'rnatilmagan mashinaga bitta fayl tashlab, `systop` ishlasin.

```
packaging/
  systop.spec        PyInstaller spec (onefile, console) — uchala OS uchun BITTA fayl
  _common.sh         build-linux.sh / build-macos.sh uchun umumiy mantiq
  build-linux.sh     Linux'da ishga tushiriladi
  build-macos.sh     macOS'da ishga tushiriladi
  build-windows.ps1  Windows'da ishga tushiriladi
  smoke_test.py      yig'ilgan binarni HAQIQATAN tekshiradi (TUI'ni ham)
```

---

## 1. Qaysi artefaktni QAYERDA yig'sa bo'ladi

| Artefakt | Yig'ish mumkin bo'lgan joy | macOS'dan yig'sa bo'ladimi? |
|---|---|---|
| `systop-linux-x86_64` | Linux x86_64 | **Yo'q** |
| `systop-windows-x86_64.exe` | Windows x86_64 | **Yo'q** |
| `systop-macos-arm64` | Apple Silicon Mac | Ha (host arxitekturasi) |
| `systop-macos-x86_64` | Intel Mac | Yo'q (arm64 Mac'da emas) |

### Nega Windows .exe ni macOS/Linux'da yasab BO'LMAYDI

PyInstaller (va Nuitka) **cross-compiler emas**. Yig'ilgan binar ichida:

1. **host OS'ning CPython kutubxonasi** — macOS'da `libpython3.x.dylib`,
   Windows'da `python3xx.dll`, Linux'da `libpython3.x.so`;
2. **host uchun kompilyatsiya qilingan bootloader** (C dasturi, `PyInstaller/bootloader/`
   ichida faqat joriy platforma uchun tayyor nusxa bor);
3. **host uchun qurilgan C-kengaytmalar** — `psutil._psutil_osx.so` va h.k.

Bularning hech biri boshqa OS'da almashtirilmaydi. Rasmiy pozitsiya ham shu:
<https://pyinstaller.org/en/stable/usage.html#supporting-multiple-operating-systems>

> Wine orqali "Windows exe" yasash yo'li texnik jihatdan mavjud, lekin biz uni
> ATAYIN qo'shmadik: C-kengaytmalar Wine ostida ishonchsiz bog'lanadi va natija
> "yig'ildi, lekin foydalanuvchida yiqiladi" toifasidagi artefakt bo'ladi.
> Sinadigan artefakt — yo'qdan battar.

**Windows .exe olishning yagona to'g'ri yo'li** — `.github/workflows/release.yml`
dagi `windows-latest` matritsasi (yoki qo'lingizdagi Windows mashina).

---

## 2. Bitta buyruq bilan yig'ish

```bash
# Linux'da
./packaging/build-linux.sh

# macOS'da
./packaging/build-macos.sh
```

```powershell
# Windows'da
.\packaging\build-windows.ps1
```

Har bir skript: muhit tayyorlaydi → yig'adi → nomlaydi + SHA256 → **smoke test**.

**Muhit**: `uv` bo'lsa `uv run --with pyinstaller` ishlatiladi — loyihaning
`.venv` iga va `pyproject.toml` ga **tegilmaydi**. `uv` bo'lmasa
`build/.buildenv` da oddiy venv yaratiladi. Shu sababli `pyinstaller` ni
`pyproject.toml` ga dev-qaramlik sifatida qo'shish **shart emas** va qo'shilmadi.

Natija:

```
dist/systop                  # asosiy binar
dist/systop-<os>-<arch>      # nomlangan nusxa
dist/systop-<os>-<arch>.sha256
```

---

## 3. Smoke test nega `--help` dan ko'proq ish qiladi

`src/systop/app.py:59` da:

```python
CSS_PATH = Path(__file__).parent / "styles.tcss"
```

Muzlatilgan holatda `systop.app.__file__` = `<_MEIPASS>/systop/app.pyc`, demak
`styles.tcss` bundle ichida **aynan `systop/` papkasida** turishi shart. Spec
buni `datas` orqali kafolatlaydi.

Muhim nozik joy: agar `styles.tcss` bundle'ga tushmasa, **`--help` baribir
`exit 0` qaytaradi** (argparse textual'ga umuman yetib bormaydi), TUI esa
foydalanuvchi qo'lida yiqiladi. Shuning uchun `smoke_test.py`:

1. `--help` → exit 0 + `usage` bor
2. `--version`
3. **bundle TOC'da `systop/styles.tcss` bormi** (uchala OS'da ishlaydi)
4. `doctor --quick --json` → exit ∈ {0,2} + `json.loads()` muvaffaqiyatli
5. **TUI'ni haqiqiy PTY'da ochadi**, `q` yuboradi, chiqishda `Traceback` /
   `StylesheetError` / `ModuleNotFoundError` yo'qligini va ANSI chizilganini
   tekshiradi (POSIX; Windows'da 3-qadam o'rnini bosadi)

```bash
python3 packaging/smoke_test.py dist/systop
```

---

## 4. Tekshirilgan natijalar

| Platforma | Yig'ildi | Hajm | Smoke |
|---|---|---|---|
| macOS arm64 (Darwin 25.5, py3.11.15) | ha | 17.1 MiB | 5/5 |
| Linux x86_64 (Ubuntu 26.04, py3.14.4, glibc 2.43) | ha | 16.5 MiB | 5/5 |
| Windows x86_64 | **CI kutilmoqda** | — | — |

### ⚠️ glibc ogohlantirishi

Linux binari **yig'ilgan mashinaning glibc'idan pastroq** tizimda ishlamaydi.
Yuqoridagi nusxa `glibc 2.43` (Ubuntu 26.04) da yig'ilgan → Ubuntu 22.04/24.04,
Debian 12, RHEL 9 da **ishlamaydi** (`GLIBC_2.4x not found`).

Shu sababli CI'da `ubuntu-22.04` tanlangan (`ubuntu-latest` emas) — eskiroq
glibc = kengroq moslik. Umumiy tarqatish uchun binarni eng eski
qo'llab-quvvatlanadigan distroda yoki `manylinux` konteynerida yig'ing.

---

## 5. Manba kodi haqiqatan yashiriladimi? — YO'Q

**Halol javob: onefile PyInstaller manba kodini YASHIRMAYDI.** U faqat
`.py` → `.pyc` (bytecode) ga aylantiradi va arxivga joylaydi.

Buni shu repodagi binarda amalda tekshirdik:

```
CArchive TOC yozuvlari: 415
PYZ ichidagi modullar: 1275
systop modullari: 36  ['systop', 'systop.__main__', 'systop._render', 'systop.app', ...]
ochiq satr konstantalar: docstring'lar TO'LIQ, o'zgarishsiz
```

`dis.dis()` bilan mantiq to'liq o'qiladi, docstring va URL'lar umuman
shifrlanmagan. Tashqi vosita ham kerak emas — PyInstaller'ning **o'z** o'quvchisi
(`CArchiveReader` / `ZlibArchiveReader`) yetarli. `pyinstxtractor` +
`decompyle3`/`pycdc` esa deyarli asl `.py` ni tiklaydi.

Bu **PyInstaller kamchiligi emas** — u obfuskator emas, u to'plovchi (bundler).
PyInstaller 6.x da eski `--key` AES shifrlash **butunlay olib tashlangan**,
chunki kalit baribir binar ichida bo'lgan → soxta himoya edi.

**Amaliy darajalar:**

| Daraja | Vosita | Beradigan himoyasi |
|---|---|---|
| 0 | wheel / sdist | hech qanday — `.py` ochiq |
| 1 | **PyInstaller onefile (hozirgi)** | tasodifiy ko'rishdan; bytecode tiklanadi |
| 2 | PyInstaller + `pyarmor gen` | jiddiy to'siq, lekin buziladi; litsenziya pullik |
| 3 | **Nuitka `--standalone`** | haqiqiy mashina kodi, bytecode YO'Q |
| 4 | kritik mantiqni serverga ko'chirish | yagona haqiqiy himoya |

Agar maqsad **"tasodifan ochib o'qib qo'ymasin"** bo'lsa — hozirgi yechim
yetarli. Agar maqsad **raqobatchidan yoki litsenziya buzilishidan himoya**
bo'lsa — 1-daraja **yetarli emas**, bunga ishonmang.

### Nuitka arziydimi?

Nuitka Python'ni C ga o'giradi va kompilyatsiya qiladi — natijada `.pyc` umuman
bo'lmaydi, faqat mashina kodi. Himoya jihatidan sezilarli ustunlik.

Narxi: build vaqti **~30 soniyadan ~10–20 daqiqagacha** ko'tariladi (bu yerda
uchala OS × CI = sezilarli), har bir OS'da C toolchain kerak (Windows'da MSVC
yoki MinGW), va textual/rich kabi ko'p dinamik import qiluvchi paketlarda
qo'shimcha `--include-package` sozlash talab qilinadi — ya'ni yangi nosozlik
manbai. **Tavsiya: hozircha yo'q.** systop — ochiq MIT tarmoq utilitasi
(`LICENSE` shuni aytadi), sir saqlaydigan mantiq yo'q. Nuitka'ga o'tish faqat
yopiq/tijoriy versiya paydo bo'lsa mantiqiy bo'ladi.

---

## 6. Sysadmin uchun eng sodda o'rnatish UX'i

**Umumiy tavsiya: PATH'dagi bitta binar.** systop — bitta fayl, demoni yo'q,
konfig fayli ixtiyoriy, xizmat ro'yxatga olinmaydi. `.deb`/`MSI` bu yerda
faqat qo'shimcha ish (paket metadata, repo, imzo) beradi, foyda bermaydi.

### Linux
```bash
curl -fsSLO https://github.com/<org>/systop/releases/latest/download/systop-linux-x86_64
sudo install -m 0755 systop-linux-x86_64 /usr/local/bin/systop
systop --version
```
`.deb` faqat ichki APT repo bo'lsa va konfiguratsiya boshqaruvi (Ansible)
paket versiyasini kuzatishi kerak bo'lsa arziydi. Aks holda ortiqcha.

### macOS
```bash
sudo install -m 0755 systop-macos-arm64 /usr/local/bin/systop
xattr -d com.apple.quarantine /usr/local/bin/systop   # notarizatsiya bo'lmaguncha
```
Binar **ad-hoc imzolangan**, notarizatsiya qilinmagan → boshqa Mac'da
Gatekeeper "damaged" deydi. To'g'ri yechim: Apple Developer ID + `notarytool`.
Keng tarqatish uchun eng yaxshi UX — **Homebrew tap** (`brew install <org>/tap/systop`),
u quarantine'ni o'zi hal qiladi.

### Windows
**`scoop` eng sodda** — administrator huquqi kerak emas, PATH'ni o'zi
sozlaydi, yangilanish `scoop update systop`:

```json
{
  "version": "0.9.0",
  "url": "https://github.com/<org>/systop/releases/download/v0.9.0/systop-windows-x86_64.exe#/systop.exe",
  "bin": "systop.exe",
  "hash": "<SHA256SUMS.txt dan>"
}
```

`winget` kengroq auditoriya, lekin manifest markaziy repoga PR talab qiladi va
ko'rib chiqish kutiladi. **MSI** faqat GPO orqali korporativ tarqatish kerak
bo'lsagina arziydi — WiX loyihasi qo'shiladi, ya'ni sezilarli qo'shimcha ish.

**Imzo eslatmasi:** imzolanmagan `.exe` SmartScreen "Windows protected your PC"
ogohlantirishini beradi. Buni faqat Authenticode sertifikati hal qiladi
(EV sertifikat reputatsiyani darhol beradi).

---

## 7. Nozik joylar (spec ichida izohlangan)

- **UPX o'chirilgan.** ~30% hajm tejaydi, lekin macOS imzosini buzadi va
  Windows Defender / EDR uchun false-positive manbai. Arzimaydi.
- **`console=True` majburiy.** `--windowed` Windows'da stdout/stderr'ni
  yo'qotadi → `--json` chiqishi yo'qoladi va TUI umuman ishga tushmaydi.
- **`collect_submodules("psutil")` ATAYIN ishlatilmagan** — u noto'g'ri
  platforma modulini (`_pswindows`) majburan import qilib, build'ni yiqitadi.
  PyInstaller'ning o'z hook'i psutil'ni to'g'ri hal qiladi.
- **`strip` faqat Linux'da** — macOS'da imzoni buzadi.
- **`anyio._backends._asyncio`** qo'lda `hiddenimports` ga qo'shilgan (httpx uni
  satr orqali dinamik import qiladi).
