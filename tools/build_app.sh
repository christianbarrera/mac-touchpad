#!/bin/bash
# Build, sign and install "Mac Touchpad.app" (full, self-contained bundle).
#
#   tools/build_app.sh               build into build/, sign, install into /Applications (asks for sudo)
#   tools/build_app.sh --no-install  build and sign only
#
# Signing identity: "Mac Touchpad Code Signing" in its own locked keychain, made once
# with tools/setup_signing.sh. The build asks for that keychain's password just before
# signing and locks it again straight after. TOUCHPAD_SIGN_IDENTITY="-" makes an
# ad-hoc test build instead (macOS treats each one as a new app, so no Accessibility).
#
# What goes in the bundle:
#   Contents/MacOS/Mac Touchpad          tools/launcher.c, embeds Python (isolated mode)
#   Contents/Frameworks/                 libpython3.13 + OpenSSL, copied from Homebrew
#   Contents/Resources/python/           the Python standard library (trimmed)
#   Contents/Resources/site-packages/    packages from .venv (installed from the hashed requirements.txt)
#   Contents/Resources/app/              server/ and web/ from this repo
# Nothing in the finished app loads code from Homebrew, the venv or this repo.
#
# macOS bash 3.2: no `set -u`, no bash-4 features.
set -eo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="Mac Touchpad"
BUNDLE_ID="local.mac-touchpad"
BUILD="$DIR/build"
APP="$BUILD/$NAME.app"
C="$APP/Contents"
DEST="/Applications/$NAME.app"
LABEL="local.mac-touchpad"
IDENTITY="${TOUCHPAD_SIGN_IDENTITY:-Mac Touchpad Code Signing}"
SIGN_KC="$HOME/Library/Keychains/mac-touchpad-signing.keychain-db"
PYBIN="/opt/homebrew/opt/python@3.13/bin/python3.13"
VENV_PY="$DIR/.venv/bin/python"
INSTALL=1

for a in "$@"; do
  case "$a" in
    --no-install) INSTALL=0 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a" >&2; exit 1 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(uname)" == Darwin ]] || die "macOS only."
# hw.optional.arm64 is 1 on Apple Silicon even in a Rosetta terminal.
[[ "$(sysctl -n hw.optional.arm64 2>/dev/null)" == 1 ]] || \
  die "This build script supports Apple Silicon Macs only (arm64, Homebrew in /opt/homebrew)."
[[ -x "$PYBIN" ]] || die "Homebrew Python 3.13 not found at $PYBIN (brew install python@3.13)."
PYHOME="$("$PYBIN" -c 'import sys; print(sys.base_prefix)')"
[[ -f "$PYHOME/Python" && -d "$PYHOME/include/python3.13" ]] || die "Unexpected Python layout under $PYHOME."

# ---------------------------------------------------------------- identity
if [[ "$IDENTITY" == "-" ]]; then
  echo "NOTE: ad-hoc signing. macOS will treat every build as a new app (test builds only)."
else
  [[ -e "$SIGN_KC" ]] || die "No signing keychain yet. Run tools/setup_signing.sh once first."
fi

# ---------------------------------------------------------------- venv
say "Checking the Python environment (.venv, hash-pinned)"
if [[ ! -x "$VENV_PY" ]]; then "$PYBIN" -m venv "$DIR/.venv"; fi
"$VENV_PY" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 13))' \
  || die ".venv is not Python 3.13. Delete .venv and run ./touchpad devices to recreate it."
"$VENV_PY" -m pip install -q --require-hashes -r "$DIR/requirements.txt"
SITE="$("$VENV_PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"

# ---------------------------------------------------------------- layout
say "Assembling $APP"
rm -rf "$APP"
mkdir -p "$C/MacOS" "$C/Frameworks" "$C/Resources/python/lib" "$C/Resources/site-packages" \
         "$C/Resources/app/server" "$C/Resources/app/web"

cp "$PYHOME/Python" "$C/Frameworks/libpython3.13.dylib"
chmod u+w "$C/Frameworks/libpython3.13.dylib"
install_name_tool -id "@executable_path/../Frameworks/libpython3.13.dylib" "$C/Frameworks/libpython3.13.dylib" 2>/dev/null

# Standard library, minus tests, GUI toolkits and modules whose Homebrew libraries
# we'd otherwise have to bundle (sqlite, mpdecimal: decimal falls back to pure
# Python, lzma, readline, curses, dbm).
rsync -a \
  --exclude 'site-packages' --exclude 'test/' --exclude 'tests/' --exclude 'idlelib/' --exclude 'tkinter/' \
  --exclude 'turtledemo/' --exclude 'ensurepip/' --exclude 'config-3.13-darwin/' --exclude '__pycache__/' \
  --exclude '*.pyc' --exclude '_tkinter*' --exclude '_sqlite3*' --exclude '_decimal*' --exclude '_lzma*' \
  --exclude 'readline*' --exclude '_curses*' --exclude '_dbm*' --exclude '_gdbm*' \
  --exclude 'lib-dynload/_test*' --exclude 'lib-dynload/_xxtest*' --exclude 'lib-dynload/xxlimited*' \
  "$PYHOME/lib/python3.13" "$C/Resources/python/lib/"

# Third-party packages (exactly what requirements.txt installed), without pip and tests.
rsync -a \
  --exclude 'pip/' --exclude 'pip-*' --exclude 'setuptools*' --exclude '_distutils_hack/' --exclude 'pkg_resources/' \
  --exclude '*.pth' --exclude 'PyObjCTest/' --exclude '__pycache__/' --exclude '*.pyc' \
  "$SITE/" "$C/Resources/site-packages/"

cp "$DIR"/server/*.py "$DIR/server/setup.html" "$C/Resources/app/server/"
rsync -a --exclude '.DS_Store' "$DIR/web/" "$C/Resources/app/web/"

# ---------------------------------------------------------------- launcher
say "Compiling the launcher"
clang -O2 -Wall -Wextra -Wno-unused-parameter -arch arm64 -mmacosx-version-min=15.0 \
  -I"$PYHOME/include/python3.13" "$DIR/tools/launcher.c" "$C/Frameworks/libpython3.13.dylib" \
  -Wl,-headerpad_max_install_names -o "$C/MacOS/$NAME"

# ---------------------------------------------------------------- libraries
say "Copying the libraries Homebrew's Python links against into the bundle"
macho_files() {
  find "$C" -type f \( -name '*.so' -o -name '*.dylib' -o -path "$C/MacOS/*" \)
}
external_deps() {   # dependencies outside the system and outside the bundle
  otool -L "$1" | tail -n +2 | awk '{print $1}' | grep -E '^(/opt/homebrew|/usr/local)/' || true
}
changed=1
while [[ $changed == 1 ]]; do
  changed=0
  while IFS= read -r f; do
    for dep in $(external_deps "$f"); do
      base="$(basename "$dep")"
      if [[ ! -f "$C/Frameworks/$base" ]]; then
        cp -L "$dep" "$C/Frameworks/$base"
        chmod u+w "$C/Frameworks/$base"
        install_name_tool -id "@executable_path/../Frameworks/$base" "$C/Frameworks/$base" 2>/dev/null
        echo "    bundled $base"
      fi
      install_name_tool -change "$dep" "@executable_path/../Frameworks/$base" "$f" 2>/dev/null
      changed=1
    done
  done < <(macho_files)
done
# Homebrew links everything with an rpath into /opt/homebrew/lib, a folder anything
# running as you can write to: a library planted there could be loaded. Remove them.
external_rpaths() {
  otool -l "$1" | awk '/cmd LC_RPATH/{getline; getline; print $2}' | grep -E '^(/opt/homebrew|/usr/local)/' || true
}
while IFS= read -r f; do
  for rp in $(external_rpaths "$f"); do install_name_tool -delete_rpath "$rp" "$f" 2>/dev/null; done
done < <(macho_files)
left=""
while IFS= read -r f; do
  d="$(external_deps "$f")"
  r="$(external_rpaths "$f")"
  [[ -z "$d$r" ]] || left="$left
  $f: $d $r"
done < <(macho_files)
[[ -z "$left" ]] || die "Libraries outside the bundle are still referenced:$left"

# ---------------------------------------------------------------- bytecode
say "Precompiling Python files"
# checked-hash: a .pyc is only used if it matches its source file exactly.
"$PYBIN" -m compileall -q -j0 --invalidation-mode checked-hash \
  "$C/Resources/python/lib/python3.13" "$C/Resources/site-packages" "$C/Resources/app/server" >/dev/null \
  || echo "    (a few files didn't compile; they're unused and stay as source)"

# ---------------------------------------------------------------- Info.plist + icon
VERSION="1.0"
BUILD_NO="$(date +%Y%m%d.%H%M%S)"
COMMIT="$(git -C "$DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
git -C "$DIR" diff --quiet HEAD -- server web tools 2>/dev/null || COMMIT="$COMMIT+local changes"
cat > "$C/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleName</key><string>$NAME</string>
  <key>CFBundleDisplayName</key><string>$NAME</string>
  <key>CFBundleExecutable</key><string>$NAME</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD_NO</string>
  <key>MacTouchpadCommit</key><string>$COMMIT</string>
  <key>LSMinimumSystemVersion</key><string>15.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Runs on this Mac only.</string>
</dict>
</plist>
EOF
plutil -lint "$C/Info.plist" >/dev/null

ICONSET="$BUILD/AppIcon.iconset"
rm -rf "$ICONSET"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s "$DIR/web/icon-512.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2)); [[ $d -le 512 ]] && sips -z $d $d "$DIR/web/icon-512.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$C/Resources/AppIcon.icns"
rm -rf "$ICONSET"

# ---------------------------------------------------------------- sign
say "Signing (hardened runtime)"
chmod -R u+w,go-w "$APP"
xattr -cr "$APP"
NESTED=()
while IFS= read -r f; do NESTED+=("$f"); done < <(find "$C" -type f \( -name '*.so' -o -name '*.dylib' \) | sort)
KC_ARGS=()
if [[ "$IDENTITY" == "-" ]]; then
  SIGN_ID="-"
else
  echo "    Enter the signing keychain password (from tools/setup_signing.sh). It is locked again right after."
  trap 'security lock-keychain "$SIGN_KC" 2>/dev/null || true' EXIT
  security unlock-keychain "$SIGN_KC"
  if [[ "$IDENTITY" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    SIGN_ID="$IDENTITY"
  else
    SIGN_ID="$(security find-identity -p codesigning "$SIGN_KC" \
               | sed -n "s/^ *[0-9]*) \([0-9A-F]\{40\}\) \"$IDENTITY\".*/\1/p" | sort -u)"
    [[ -n "$SIGN_ID" && "$SIGN_ID" != *$'\n'* ]] || die "Expected one identity named \"$IDENTITY\" in $SIGN_KC."
  fi
  KC_ARGS=(--keychain "$SIGN_KC")
fi
# One codesign run for everything: nested code first, the app last.
if ! out="$(codesign --force --timestamp=none --options runtime --entitlements "$DIR/tools/entitlements.plist" \
             "${KC_ARGS[@]}" --sign "$SIGN_ID" "${NESTED[@]}" "$APP" 2>&1)"; then
  printf '%s\n' "$out" | grep -v 'replacing existing signature' >&2
  die "Signing failed."
fi
[[ "$IDENTITY" == "-" ]] || security lock-keychain "$SIGN_KC"
codesign --verify --strict --deep "$APP"
echo "    signed and verified: $APP"
codesign -d -r- "$APP" 2>&1 | sed -n 's/^designated => /    designated requirement: /p'

say "Self-test (imports, TLS, PyObjC, and no library loaded from outside the bundle)"
"$C/MacOS/$NAME" --selftest | cut -c1-60 || die "The built app failed its self-test."

if [[ $INSTALL == 0 ]]; then
  echo
  echo "Built $APP (not installed)."
  [[ "$SIGN_ID" == "-" ]] || echo "NOTE: this copy is signed like the real app, so macOS gives it the same Accessibility
permission and keychain access, but anything running as you can change its files. Delete it when done:
  rm -rf \"$APP\""
  exit 0
fi

# ---------------------------------------------------------------- install
say "Installing to $DEST (root-owned, so nothing running as you can change its code)"
echo "    sudo may ask for your Mac password."
sudo rm -rf "$DEST.new" "$DEST.old"
sudo ditto "$APP" "$DEST.new"
sudo chown -R root:wheel "$DEST.new"
sudo chmod -R a+rX,go-w "$DEST.new"
[[ -e "$DEST" ]] && sudo mv "$DEST" "$DEST.old"
sudo mv "$DEST.new" "$DEST"
sudo rm -rf "$DEST.old"
codesign --verify --strict --deep "$DEST"
echo "    installed $DEST"
# The copy in build/ is signed identically (same permissions) but writable by anything
# running as you, so it mustn't linger.
rm -rf "$APP"

say "Checking Accessibility and the CA key as macOS sees the new build"
echo "    A new build has to be allowed to read the CA key from the keychain once. If macOS asks"
echo "    \"Mac Touchpad wants to access key 'Mac Touchpad: certificate authority key'\", enter your"
echo "    login password and click Always Allow (it applies to this exact build only)."
open -W -n "$DEST" --args --check
tail -n 4 "$HOME/Library/Logs/Mac Touchpad/check.log" | sed 's/^/    /'

if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 \
   && launchctl print "gui/$(id -u)/$LABEL" | grep -q "program = $DEST/"; then
  say "Restarting the running login item"
  launchctl kickstart -k "gui/$(id -u)/$LABEL"
fi
echo
echo "Done. First install? Start it at login with:  ./touchpad install-agent"
