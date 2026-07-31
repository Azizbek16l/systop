# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for systop — onefile, console, cross-platform.

Ishlatish (repo ildizidan):
    pyinstaller --noconfirm packaging/systop.spec

Nega .spec, `--add-data` bayroqlari emas:
  `--add-data` ajratuvchisi OS'ga bog'liq (POSIX `:`, Windows `;`), shuning
  uchun bitta buyruq uchala OS'da ishlamaydi. Spec ichida `datas` oddiy
  Python tuple ro'yxati — ajratuvchi muammosi umuman yo'q.

ENG MUHIM JOY — styles.tcss:
  `src/systop/app.py` da:
      CSS_PATH = Path(__file__).parent / "styles.tcss"
  Muzlatilgan (frozen) holatda `systop.app.__file__` = `<_MEIPASS>/systop/app.pyc`,
  demak `Path(__file__).parent` = `<_MEIPASS>/systop`. Shuning uchun styles.tcss
  AYNAN `systop/` papkasiga joylanishi shart. Aks holda TUI ishga tushishda
  yiqiladi (`--help` esa bemalol ishlayveradi — shuning uchun faqat `--help`
  bilan tekshirish yetarli EMAS, smoke_test.py TUI'ni haqiqatan ochib ko'radi).
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

# SPECPATH — PyInstaller spec parse qilayotganda beradigan global (packaging/).
REPO_ROOT = Path(SPECPATH).resolve().parent  # noqa: F821
SRC = REPO_ROOT / "src"

# systop'ni build vaqtida import qilish mumkin bo'lsin (collect_submodules uchun).
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

datas: list[tuple[str, str]] = []
binaries: list[tuple[str, str]] = []
hiddenimports: list[str] = []

# --- 1. systop'ning O'Z asset'lari -------------------------------------------
# styles.tcss — TUI mavjudligining sharti (yuqoridagi izohga qarang).
_tcss = SRC / "systop" / "styles.tcss"
if not _tcss.is_file():
    raise SystemExit(f"systop.spec: kutilgan asset topilmadi: {_tcss}")
datas.append((str(_tcss), "systop"))

# py.typed — zarar qilmaydi, paket to'liqligi uchun.
_typed = SRC / "systop" / "py.typed"
if _typed.is_file():
    datas.append((str(_typed), "systop"))

# systop submodullari: cli.py hamma `core.*` / `widgets.*` ni to'g'ridan-to'g'ri
# import qiladi, lekin kelajakda lazy import qo'shilsa ham sinmasin.
hiddenimports += collect_submodules("systop")

# --- 2. textual + rich: data fayllari BILAN ----------------------------------
# textual o'zining `.tcss` / `.css` / widget asset'larini paket ichida olib
# yuradi (masalan `textual/widgets/*.tcss`, `textual/tree-sitter/*`).
# collect_all = submodullar + data + binary, uchalasi ham kerak.
for _pkg in ("textual", "rich"):
    _d, _b, _h = collect_all(_pkg)
    datas += _d
    binaries += _b
    hiddenimports += _h

# --- 3. Runtime'da dinamik import qilinadigan narsalar ------------------------
# anyio backend'ni satr orqali import qiladi (httpx -> anyio).
hiddenimports += ["anyio._backends._asyncio"]

# certifi — httpx TLS ildiz sertifikatlari (cacert.pem data fayli).
try:
    datas += collect_data_files("certifi")
    hiddenimports += ["certifi"]
except Exception:  # pragma: no cover - certifi bo'lmasa httpx o'zi hal qiladi
    pass

# icmplib sof-python, kichkina — to'liq yig'amiz.
hiddenimports += collect_submodules("icmplib")

# psutil: C kengaytmasi bor va platformaga qarab turlicha modul yuklaydi.
# collect_submodules("psutil") QILMAYMIZ — u `_pswindows`/`_psosx` ni MAJBURAN
# import qilishga urinadi va noto'g'ri platformada build'ni yiqitadi.
# PyInstaller'ning o'z hook'i psutil'ni to'g'ri hal qiladi; faqat top-level
# nomni kafolatlaymiz.
hiddenimports += ["psutil"]

# argcomplete — cli.py da `# PYTHON_ARGCOMPLETE_OK`, import qilinadi.
hiddenimports += ["argcomplete"]

# Takrorlarni olib tashlaymiz (build loglarini toza saqlaydi).
hiddenimports = sorted(set(hiddenimports))

# --- 4. Kerak bo'lmagan og'ir paketlar ----------------------------------------
# Bular systop'ga kerak emas; muhitda tasodifan bo'lsa binarni shishirmasin.
excludes = [
    "tkinter",
    "unittest",
    "pydoc_data",
    "numpy",
    "matplotlib",
    "PIL",
    "pandas",
    "scipy",
    "IPython",
    "pytest",
    "_pytest",
    "mypy",
    "ruff",
    "setuptools",
    "pip",
]

block_cipher = None

a = Analysis(  # noqa: F821
    [str(SRC / "systop" / "__main__.py")],
    pathex=[str(SRC)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)  # noqa: F821

# strip: Linux'da bir necha MB tejaydi. macOS'da strip imzoni buzishi mumkin,
# Windows'da umuman qo'llanmaydi — shuning uchun faqat Linux'da yoqamiz.
_strip = sys.platform.startswith("linux")

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="systop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=_strip,
    # UPX: O'CHIRILGAN. macOS'da imzolangan binarni buzadi, Linux'da ba'zi
    # antivirus/EDR'lar UPX-packed ELF'ni heuristika bilan bloklaydi, va
    # Windows Defender uchun ham false-positive manbai. Foyda ~30% hajm,
    # zarari — "ishlamayapti" qo'ng'iroqlari. Arzimaydi.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=True MAJBURIY: systop terminal ilovasi. console=False (windowed)
    # Windows'da stdout/stderr'ni yo'q qiladi -> `--json` chiqishi yo'qoladi va
    # Textual TUI umuman ishga tushmaydi.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,  # native (macOS'da universal2 uchun "universal2")
    codesign_identity=None,
    entitlements_file=None,
)
