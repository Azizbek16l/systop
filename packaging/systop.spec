# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for systop — onefile, console, cross-platform.

Ishlatish (repo ildizidan):
    pyinstaller --noconfirm packaging/systop.spec

Why a .spec instead of `--add-data` flags:
  the `--add-data` separator is OS-dependent (POSIX `:`, Windows `;`), so a
  so no single command line works on all three OSes. Inside a spec, `datas` is
  a plain list of Python tuples — the separator problem disappears entirely.

ENG MUHIM JOY — styles.tcss:
  `src/systop/app.py` da:
      CSS_PATH = Path(__file__).parent / "styles.tcss"
  Muzlatilgan (frozen) holatda `systop.app.__file__` = `<_MEIPASS>/systop/app.pyc`,
  so `Path(__file__).parent` = `<_MEIPASS>/systop`. styles.tcss must therefore
  AYNAN `systop/` papkasiga joylanishi shart. Aks holda TUI ishga tushishda
  dies (while `--help` keeps working — which is why checking only `--help`
  is NOT enough; smoke_test.py actually opens the TUI).
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

# SPECPATH — PyInstaller spec parse qilayotganda beradigan global (packaging/).
REPO_ROOT = Path(SPECPATH).resolve().parent  # noqa: F821
SRC = REPO_ROOT / "src"

# Make systop importable at build time (needed by collect_submodules).
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

datas: list[tuple[str, str]] = []
binaries: list[tuple[str, str]] = []
hiddenimports: list[str] = []

# --- 1. systop's OWN assets --------------------------------------------------
# styles.tcss — TUI mavjudligining sharti (yuqoridagi izohga qarang).
_tcss = SRC / "systop" / "styles.tcss"
if not _tcss.is_file():
    raise SystemExit(f"systop.spec: kutilgan asset topilmadi: {_tcss}")
datas.append((str(_tcss), "systop"))

# py.typed — harmless, included for package completeness.
_typed = SRC / "systop" / "py.typed"
if _typed.is_file():
    datas.append((str(_typed), "systop"))

# systop submodules: cli.py imports every `core.*` / `widgets.*` directly, but
# collecting them keeps this working if a lazy import is added later.
hiddenimports += collect_submodules("systop")

# --- 2. textual + rich: WITH their data files --------------------------------
# textual carries its own `.tcss` / `.css` / widget assets inside the package,
# yuradi (masalan `textual/widgets/*.tcss`, `textual/tree-sitter/*`).
# collect_all = submodules + data + binaries; all three are needed.
for _pkg in ("textual", "rich"):
    _d, _b, _h = collect_all(_pkg)
    datas += _d
    binaries += _b
    hiddenimports += _h

# --- 3. Things imported dynamically at runtime -------------------------------
# anyio imports its backend by string (httpx -> anyio).
hiddenimports += ["anyio._backends._asyncio"]

# certifi — httpx TLS ildiz sertifikatlari (cacert.pem data fayli).
try:
    datas += collect_data_files("certifi")
    hiddenimports += ["certifi"]
except Exception:  # pragma: no cover - without certifi, httpx handles it itself
    pass

# icmplib is pure Python and small — collect all of it.
hiddenimports += collect_submodules("icmplib")

# psutil: C kengaytmasi bor va platformaga qarab turlicha modul yuklaydi.
# collect_submodules("psutil") QILMAYMIZ — u `_pswindows`/`_psosx` ni MAJBURAN
# would try to import and break the build on the wrong platform.
# PyInstaller's own hook handles psutil correctly; only the top-level
# nomni kafolatlaymiz.
hiddenimports += ["psutil"]

# argcomplete — cli.py da `# PYTHON_ARGCOMPLETE_OK`, import qilinadi.
hiddenimports += ["argcomplete"]

# Takrorlarni olib tashlaymiz (build loglarini toza saqlaydi).
hiddenimports = sorted(set(hiddenimports))

# --- 4. Heavy packages we do not need ----------------------------------------
# systop needs none of these; if they happen to be in the environment they must
# not bloat the binary.
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

# strip: saves a few MB on Linux. On macOS strip can break the signature and on
# Windows it does not apply at all — so it is enabled on Linux only.
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
    # UPX: DISABLED. It breaks a signed binary on macOS, some Linux
    # antivirus/EDR products block UPX-packed ELFs heuristically, and it is a
    # false-positive source for Windows Defender too. Gain: ~30% size.
    # Cost: "it doesn't work" support calls. Not worth it.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=True MAJBURIY: systop terminal ilovasi. console=False (windowed)
    # On Windows it discards stdout/stderr -> `--json` output disappears and
    # Textual TUI umuman ishga tushmaydi.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,  # native ("universal2" on macOS for a universal build)
    codesign_identity=None,
    entitlements_file=None,
)
