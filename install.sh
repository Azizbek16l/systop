#!/bin/sh
# systop — Linux va macOS uchun bir qatorlik o'rnatgich.
#
#   curl -fsSL https://raw.githubusercontent.com/Azizbek16l/systop/main/install.sh | sh
#
# Sozlash (muhit o'zgaruvchilari bilan — quvur rejimida yagona yo'l):
#   SYSTOP_VERSION=v0.10.0   aniq relise tegi (default: eng so'nggisi)
#   SYSTOP_INSTALL_DIR=...   o'rnatish katalogi (default: quyidagi mantiq)
#   SYSTOP_NO_SUDO=1         sudo ishlatilmasin, ~/.local/bin ga qo'yilsin
#
# DIQQAT — o'zgaruvchini QUVURNING QAYSI TOMONIGA qo'yish muhim:
#     SYSTOP_INSTALL_DIR=/opt/bin curl -fsSL ... | sh      # NOTO'G'RI
#     curl -fsSL ... | SYSTOP_INSTALL_DIR=/opt/bin sh      # to'g'ri
# Birinchi shaklda o'zgaruvchi `curl` ga beriladi, `sh` uni umuman ko'rmaydi
# va skript jimgina standart katalogga o'rnatadi.
#
# O'chirish:
#   curl -fsSL .../install.sh | sh -s -- --uninstall
#
# POSIX `sh` uchun yozilgan (bash EMAS): Debian/Ubuntu'da `sh` = dash,
# Alpine'da busybox ash. `[[ ]]`, massiv va `local` ATAYIN ishlatilmagan.

set -eu

REPO="Azizbek16l/systop"
BIN_NAME="systop"

# --- ko'rinish -------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_STEP=$(printf '\033[36m'); C_OK=$(printf '\033[32m')
    C_WARN=$(printf '\033[33m'); C_ERR=$(printf '\033[31m'); C_OFF=$(printf '\033[0m')
else
    C_STEP=''; C_OK=''; C_WARN=''; C_ERR=''; C_OFF=''
fi

step() { printf '%s==> %s%s\n' "$C_STEP" "$1" "$C_OFF"; }
ok()   { printf '%s    %s%s\n' "$C_OK" "$1" "$C_OFF"; }
warn() { printf '%s    %s%s\n' "$C_WARN" "$1" "$C_OFF"; }
die()  { printf '%sXATO: %s%s\n' "$C_ERR" "$1" "$C_OFF" >&2; exit 1; }

# --- argumentlar -----------------------------------------------------------

UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=1 ;;
        --version=*) SYSTOP_VERSION="${arg#--version=}" ;;
        --dir=*)     SYSTOP_INSTALL_DIR="${arg#--dir=}" ;;
        --help|-h)
            sed -n '2,20p' "$0" 2>/dev/null || printf 'Yordam faqat fayldan ishga tushirilganda.\n'
            exit 0 ;;
        *) die "noma'lum argument: $arg" ;;
    esac
done

VERSION="${SYSTOP_VERSION:-}"

# --- platforma aniqlash ----------------------------------------------------

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64|amd64) ASSET="systop-linux-x86_64" ;;
            aarch64|arm64)
                die "Linux ARM64 uchun tayyor binar yo'q.
     Manbadan yig'ing:  git clone https://github.com/$REPO && cd systop && ./packaging/build-linux.sh" ;;
            *) die "qo'llab-quvvatlanmaydigan arxitektura: $ARCH" ;;
        esac ;;
    Darwin)
        case "$ARCH" in
            arm64) ASSET="systop-macos-arm64" ;;
            x86_64) ASSET="systop-macos-x86_64" ;;
            *) die "qo'llab-quvvatlanmaydigan arxitektura: $ARCH" ;;
        esac ;;
    *) die "qo'llab-quvvatlanmaydigan OS: $OS (Windows uchun install.ps1)" ;;
esac

# --- o'rnatish katalogi ----------------------------------------------------
#
# Tartib: foydalanuvchi bergani > yozish mumkin bo'lgan /usr/local/bin >
# sudo bilan /usr/local/bin > ~/.local/bin.
#
# `sudo` MAJBURLANMAYDI: parol so'rab, quvurdan (`curl | sh`) o'qiyotgan
# skript stdin'ni band qilgani uchun terminal qotib qolardi. Buning o'rniga
# oldindan tekshiramiz.

NEED_SUDO=0
if [ -n "${SYSTOP_INSTALL_DIR:-}" ]; then
    DEST="$SYSTOP_INSTALL_DIR"
elif [ "${SYSTOP_NO_SUDO:-0}" = "1" ]; then
    DEST="$HOME/.local/bin"
elif [ -w /usr/local/bin ] 2>/dev/null; then
    DEST="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    DEST="/usr/local/bin"; NEED_SUDO=1
else
    DEST="$HOME/.local/bin"
fi

TARGET="$DEST/$BIN_NAME"

# --- o'chirish -------------------------------------------------------------

if [ "$UNINSTALL" = "1" ]; then
    step "systop o'chirilmoqda"
    for d in "$DEST" /usr/local/bin "$HOME/.local/bin"; do
        if [ -f "$d/$BIN_NAME" ]; then
            if [ -w "$d" ]; then rm -f "$d/$BIN_NAME"; else sudo rm -f "$d/$BIN_NAME"; fi
            ok "o'chirildi: $d/$BIN_NAME"
        fi
    done
    exit 0
fi

# --- yuklab olish ----------------------------------------------------------
#
# `releases/latest/download/...` — GitHub o'zi eng so'nggi relisega
# yo'naltiradi. `api.github.com` ATAYIN ishlatilmaydi: autentifikatsiyasiz
# soatiga 60 so'rov, korporativ NAT ortidagi bir necha mashina uni darrov
# tugatadi.
if [ -z "$VERSION" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
    VER_LABEL="eng so'nggi"
else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
    VER_LABEL="$VERSION"
fi

if command -v curl >/dev/null 2>&1; then
    DL='curl -fsSL --retry 3 -o'
elif command -v wget >/dev/null 2>&1; then
    DL='wget -q -O'
else
    die "curl ham, wget ham topilmadi"
fi

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t systop)
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT INT TERM

step "systop yuklab olinmoqda ($VER_LABEL, $ASSET)"
# shellcheck disable=SC2086
$DL "$TMP/$BIN_NAME" "$BASE/$ASSET" || die "yuklab bo'lmadi: $BASE/$ASSET"
SIZE=$(wc -c < "$TMP/$BIN_NAME" | tr -d ' ')
[ "$SIZE" -gt 1000000 ] || die "yuklangan fayl juda kichik ($SIZE bayt) — relise topilmadimi?"
ok "yuklandi: $SIZE bayt"

# --- SHA256 tekshiruvi -----------------------------------------------------
# Tekshirmaslik — o'rnatgichdagi eng keng tarqalgan kamchilik: yarim
# yuklangan yoki almashtirilgan fayl JIMGINA o'rnatiladi.

step "SHA256 tekshirilmoqda"
if command -v sha256sum >/dev/null 2>&1; then
    HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    HASH_CMD="shasum -a 256"
else
    HASH_CMD=""
fi

VERIFIED=0
if [ -n "$HASH_CMD" ]; then
    # shellcheck disable=SC2086
    if $DL "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt" 2>/dev/null; then
        EXPECTED=$(grep -E "[[:space:]]\*?$ASSET\$" "$TMP/SHA256SUMS.txt" 2>/dev/null | awk '{print $1}' | head -1)
        ACTUAL=$($HASH_CMD "$TMP/$BIN_NAME" | awk '{print $1}')
        if [ -z "$EXPECTED" ]; then
            warn "SHA256SUMS.txt da '$ASSET' yozuvi yo'q — tekshirib bo'lmadi"
        elif [ "$EXPECTED" != "$ACTUAL" ]; then
            die "SHA256 MOS KELMADI.
     Kutilgan: $EXPECTED
     Olingan:  $ACTUAL
     Fayl o'rnatilMADI."
        else
            ok "sha256 mos: $(echo "$ACTUAL" | cut -c1-16)..."
            VERIFIED=1
        fi
    else
        warn "SHA256SUMS.txt olinmadi — tekshiruvsiz davom etilyapti"
    fi
else
    warn "sha256sum/shasum topilmadi — tekshirib bo'lmadi"
fi
[ "$VERIFIED" = "1" ] || warn "OGOHLANTIRISH: yuklama tekshirilmadi."

chmod +x "$TMP/$BIN_NAME"

# macOS: yuklangan faylga karantin bayrog'i qo'yiladi va Gatekeeper
# "damaged / cannot be opened" deydi. Binar ad-hoc imzolangan (Apple
# Developer ID emas), shuning uchun bayroqni olib tashlaymiz.
if [ "$OS" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$TMP/$BIN_NAME" 2>/dev/null || true
fi

# --- ishlaydimi? -----------------------------------------------------------
# PATH'ga qo'yishdan OLDIN sinaymiz. Linux'da eng ko'p uchraydigan xato —
# glibc mos kelmasligi; uni "systop ishlamayapti" emas, aniq sabab bilan
# aytish kerak.

step "binar tekshirilmoqda"
if ! VER_OUT=$("$TMP/$BIN_NAME" --version 2>&1); then
    case "$VER_OUT" in
        *GLIBC*|*glibc*)
            die "Bu binar tizimingizdagidan YANGIROQ glibc talab qiladi.
     $VER_OUT
     Sizda: $(ldd --version 2>/dev/null | head -1)
     Yechim: manbadan yig'ing —
       git clone https://github.com/$REPO && cd systop && ./packaging/build-linux.sh" ;;
        *) die "binar ishga tushmadi: $VER_OUT" ;;
    esac
fi
ok "$VER_OUT"

# --- joyiga qo'yish --------------------------------------------------------

step "o'rnatilmoqda: $TARGET"
if [ "$NEED_SUDO" = "1" ]; then
    warn "/usr/local/bin ga yozish uchun sudo so'raladi"
    sudo install -m 0755 "$TMP/$BIN_NAME" "$TARGET" || die "o'rnatib bo'lmadi"
else
    mkdir -p "$DEST"
    install -m 0755 "$TMP/$BIN_NAME" "$TARGET" 2>/dev/null \
        || { cp "$TMP/$BIN_NAME" "$TARGET" && chmod 0755 "$TARGET"; } \
        || die "o'rnatib bo'lmadi: $TARGET"
fi
ok "$TARGET"

# --- PATH ------------------------------------------------------------------
# POSIX shell boshqa jarayonning PATH'ini o'zgartira olmaydi va foydalanuvchi
# rc-fayliga jimgina yozish qo'pol. Shuning uchun aniq ko'rsatma beramiz.

case ":$PATH:" in
    *":$DEST:"*) ;;
    *)
        printf '\n%sPATH sozlanishi kerak%s — %s hozircha PATH da emas:\n' "$C_WARN" "$C_OFF" "$DEST"
        SHELL_NAME=$(basename "${SHELL:-sh}")
        case "$SHELL_NAME" in
            zsh)  RC="$HOME/.zshrc" ;;
            bash) RC="$HOME/.bashrc" ;;
            fish) RC="$HOME/.config/fish/config.fish" ;;
            *)    RC="$HOME/.profile" ;;
        esac
        if [ "$SHELL_NAME" = "fish" ]; then
            printf '\n  echo \x27fish_add_path %s\x27 >> %s\n' "$DEST" "$RC"
        else
            printf '\n  echo \x27export PATH="%s:$PATH"\x27 >> %s\n' "$DEST" "$RC"
        fi
        printf '  exec %s\n' "$SHELL_NAME"
        ;;
esac

printf '\n%sTayyor.%s\n' "$C_OK" "$C_OFF"
printf '  systop doctor        tarmoq muammolarini avtomatik topish\n'
printf '  systop wifi          Wi-Fi signal/SNR/kanal\n'
printf '  systop lan -6        LAN inventari (IPv4 + IPv6)\n'
printf '  systop               to%sliq TUI dashboard\n' "'"
