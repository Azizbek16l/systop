# systop — building a standalone binary (packaging/)

The goal: drop a single file onto a machine with no Python installed and have
`systop` run.

```
packaging/
  systop.spec        PyInstaller spec (onefile, console) — ONE file for all three OSes
  _common.sh         shared logic for build-linux.sh / build-macos.sh
  build-linux.sh     run this on Linux
  build-macos.sh     run this on macOS
  build-windows.ps1  run this on Windows
  smoke_test.py      REALLY exercises the built binary (the TUI included)
```

---

## 1. Which artifact can be built WHERE

| Artifact | Where it can be built | Buildable from macOS? |
|---|---|---|
| `systop-linux-x86_64` | Linux x86_64 | **No** |
| `systop-windows-x86_64.exe` | Windows x86_64 | **No** |
| `systop-macos-arm64` | Apple Silicon Mac | Yes (host architecture) |
| `systop-macos-x86_64` | Intel Mac | No (not on an arm64 Mac) |

### Why a Windows .exe CANNOT be produced on macOS/Linux

PyInstaller (and Nuitka) are **not cross-compilers**. The built binary contains:

1. **the host OS's CPython library** — `libpython3.x.dylib` on macOS,
   `python3xx.dll` on Windows, `libpython3.x.so` on Linux;
2. **a bootloader compiled for the host** (a C program; `PyInstaller/bootloader/`
   ships a prebuilt copy for the current platform only);
3. **C extensions built for the host** — `psutil._psutil_osx.so` and friends.

None of those can be swapped out for another OS. The official position says the
same:
<https://pyinstaller.org/en/stable/usage.html#supporting-multiple-operating-systems>

> There is a technically viable route to producing a "Windows exe" through Wine,
> but we left it out DELIBERATELY: C extensions link unreliably under Wine and
> the result is an artifact of the "it built, but it crashes for the user"
> variety. An artifact that breaks is worse than no artifact at all.

**The only correct way to get a Windows .exe** is the `windows-latest` matrix
entry in `.github/workflows/release.yml` (or a Windows machine you have on
hand).

---

## 2. Building with a single command

```bash
# on Linux
./packaging/build-linux.sh

# on macOS
./packaging/build-macos.sh
```

```powershell
# on Windows
.\packaging\build-windows.ps1
```

Each script: prepares the environment → builds → names the output + SHA256 →
**smoke test**.

**Environment**: if `uv` is available, `uv run --with pyinstaller` is used — the
project's `.venv` and `pyproject.toml` are **left untouched**. Without `uv`, a
plain venv is created in `build/.buildenv`. That is why adding `pyinstaller` to
`pyproject.toml` as a dev dependency is **unnecessary**, and it was not added.

Result:

```
dist/systop                  # the main binary
dist/systop-<os>-<arch>      # named copy
dist/systop-<os>-<arch>.sha256
```

---

## 3. Why the smoke test does more than `--help`

In `src/systop/app.py:59`:

```python
CSS_PATH = Path(__file__).parent / "styles.tcss"
```

In a frozen build `systop.app.__file__` = `<_MEIPASS>/systop/app.pyc`, which
means `styles.tcss` must sit **in exactly that `systop/` directory** inside the
bundle. The spec guarantees that through `datas`.

The subtle part: if `styles.tcss` does not make it into the bundle, **`--help`
still returns `exit 0`** (argparse never reaches textual at all) while the TUI
crashes in the user's hands. Hence `smoke_test.py`:

1. `--help` → exit 0 and `usage` present
2. `--version`
3. **is `systop/styles.tcss` in the bundle TOC** (works on all three OSes)
4. `doctor --quick --json` → exit ∈ {0,2} and `json.loads()` succeeds
5. **opens the TUI on a real PTY**, sends `q`, and checks that the output
   contains no `Traceback` / `StylesheetError` / `ModuleNotFoundError` and that
   ANSI was actually drawn (POSIX; on Windows this substitutes for step 3)

```bash
python3 packaging/smoke_test.py dist/systop
```

---

## 4. Verified results

| Platform | Built | Size | Smoke |
|---|---|---|---|
| macOS arm64 (Darwin 25.5, py3.11.15) | yes | 17.1 MiB | 5/5 |
| Linux x86_64 (Ubuntu 26.04, py3.14.4, glibc 2.43) | yes | 16.5 MiB | 5/5 |
| Windows x86_64 | **awaiting CI** | — | — |

### ⚠️ glibc warning

A Linux binary will not run on a system whose **glibc is older than the build
machine's**. The copy above was built against `glibc 2.43` (Ubuntu 26.04), so it
**will not run** on Ubuntu 22.04/24.04, Debian 12 or RHEL 9
(`GLIBC_2.4x not found`).

That is why CI pins `ubuntu-22.04` (not `ubuntu-latest`) — older glibc = wider
compatibility. For general distribution, build the binary on the oldest
supported distro or inside a `manylinux` container.

---

## 5. Does this actually hide the source code? — NO

**The honest answer: onefile PyInstaller does NOT hide source code.** All it
does is turn `.py` into `.pyc` (bytecode) and put it in an archive.

We verified this on the actual binary from this repo:

```
CArchive TOC entries: 415
modules inside the PYZ: 1275
systop modules: 36  ['systop', 'systop.__main__', 'systop._render', 'systop.app', ...]
plaintext string constants: docstrings FULLY INTACT, unchanged
```

`dis.dis()` reads the logic back in full, and docstrings and URLs are not
encrypted at all. You don't even need an external tool — PyInstaller's **own**
readers (`CArchiveReader` / `ZlibArchiveReader`) are enough. `pyinstxtractor` +
`decompyle3`/`pycdc` will get you almost back to the original `.py`.

This is **not a PyInstaller shortcoming** — it is not an obfuscator, it is a
bundler. PyInstaller 6.x **removed the old `--key` AES encryption entirely**,
because the key sat inside the binary anyway → it was fake protection.

**Practical levels:**

| Level | Tool | Protection it gives |
|---|---|---|
| 0 | wheel / sdist | none — the `.py` is right there |
| 1 | **PyInstaller onefile (current)** | against casual inspection; bytecode is recoverable |
| 2 | PyInstaller + `pyarmor gen` | a serious hurdle, but breakable; paid licence |
| 3 | **Nuitka `--standalone`** | real machine code, NO bytecode |
| 4 | move the critical logic server-side | the only real protection |

If the goal is **"don't let someone read it by accident"**, the current solution
is sufficient. If the goal is **protection from a competitor or from licence
violation**, level 1 is **not sufficient** — do not rely on it.

### Is Nuitka worth it?

Nuitka translates Python to C and compiles it — the result contains no `.pyc` at
all, only machine code. In protection terms that is a meaningful step up.

The price: build time goes from **~30 seconds to ~10–20 minutes** (multiplied by
three OSes × CI, that adds up), every OS needs a C toolchain (MSVC or MinGW on
Windows), and packages with a lot of dynamic imports such as textual/rich
require extra `--include-package` tuning — i.e. a new source of breakage.
**Recommendation: not for now.** systop is an open MIT network utility (as
`LICENSE` states) with no secret logic in it. Moving to Nuitka only makes sense
if a closed-source/commercial edition appears.

---

## 6. The simplest install UX for a sysadmin

**General recommendation: a single binary on the PATH.** systop is one file: no
daemon, an optional config file, no service registration. A `.deb`/`MSI` only
adds work here (package metadata, a repo, signing) without adding value.

### Linux
```bash
curl -fsSLO https://github.com/<org>/systop/releases/latest/download/systop-linux-x86_64
sudo install -m 0755 systop-linux-x86_64 /usr/local/bin/systop
systop --version
```
A `.deb` is only worth it if you run an internal APT repo and your configuration
management (Ansible) needs to track the package version. Otherwise it is
overhead.

### macOS
```bash
sudo install -m 0755 systop-macos-arm64 /usr/local/bin/systop
xattr -d com.apple.quarantine /usr/local/bin/systop   # until notarization is in place
```
The binary is **ad-hoc signed** and not notarized → on another Mac, Gatekeeper
calls it "damaged". The proper fix is an Apple Developer ID + `notarytool`. For
wide distribution the best UX is a **Homebrew tap**
(`brew install <org>/tap/systop`), which handles quarantine for you.

### Windows
**`scoop` is the simplest** — no administrator rights needed, it sets up PATH
itself, and updates are `scoop update systop`:

```json
{
  "version": "0.9.0",
  "url": "https://github.com/<org>/systop/releases/download/v0.9.0/systop-windows-x86_64.exe#/systop.exe",
  "bin": "systop.exe",
  "hash": "<from SHA256SUMS.txt>"
}
```

`winget` reaches a wider audience, but the manifest requires a PR to a central
repo plus a review wait. **MSI** is only worth it if you need corporate
distribution via GPO — it means adding a WiX project, i.e. significant extra
work.

**A note on signing:** an unsigned `.exe` triggers the SmartScreen "Windows
protected your PC" warning. Only an Authenticode certificate fixes that (an EV
certificate grants reputation immediately).

---

## 7. Subtleties (annotated inside the spec)

- **UPX is disabled.** It saves ~30% of the size, but it breaks the macOS
  signature and is a false-positive source for Windows Defender / EDR. Not worth
  it.
- **`console=True` is mandatory.** `--windowed` loses stdout/stderr on Windows →
  `--json` output disappears and the TUI does not start at all.
- **`collect_submodules("psutil")` is DELIBERATELY unused** — it force-imports
  the wrong platform module (`_pswindows`) and breaks the build. PyInstaller's
  own hook handles psutil correctly.
- **`strip` on Linux only** — it breaks the signature on macOS.
- **`anyio._backends._asyncio`** is added to `hiddenimports` by hand (httpx
  imports it dynamically by string).
