#!/bin/bash
# One-time setup: the code-signing identity for Mac Touchpad.app, in its own keychain.
#
#   tools/setup_signing.sh
#
# macOS ties the app's Accessibility permission and its Keychain access to this
# identity, so whoever can sign with it can make an app macOS treats as Mac Touchpad.
# The key therefore lives in a separate keychain that stays locked except while
# tools/build_app.sh is signing (it asks for that keychain's password once per build,
# then locks it again). The keychain also locks itself after 5 idle minutes and when
# the Mac sleeps, and it isn't on the keychain search list, so other apps never see it.
#
# The identity: a self-signed RSA-3072 certificate, "Mac Touchpad Code Signing",
# valid 10 years, code signing only, private key non-extractable. No Apple account.
#
# macOS bash 3.2: no `set -u`, no bash-4 features.
set -eo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KC="$HOME/Library/Keychains/mac-touchpad-signing.keychain-db"
NAME="Mac Touchpad Code Signing"
LOGIN_KC="$HOME/Library/Keychains/login.keychain-db"
VENV_PY="$DIR/.venv/bin/python"

die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(uname)" == Darwin ]] || die "macOS only."
[[ -e "$KC" ]] && die "Already set up: $KC exists. To start over, delete it first:
  security delete-keychain \"$KC\"
(the app then needs Accessibility granted again after the next build)."
[[ -x "$VENV_PY" ]] || die "No .venv yet. Run ./touchpad devices once to create it."

TMP="$(mktemp -d)"
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
PASS="$(openssl rand -hex 16)"   # protects only the temporary .p12 for the few seconds it exists

echo "Creating the signing certificate..."
HASH="$("$VENV_PY" "$DIR/tools/make_signing_identity.py" "$TMP" "$NAME" "$PASS")"

echo
echo "Now choose a password for the new signing keychain. You'll type it once per build."
echo "(Your Mac login password works, but a separate one is a little safer.)"
# The current search list, one path per array item (paths may contain spaces).
SEARCH=()
while IFS= read -r kc; do
  kc="${kc#"${kc%%[![:space:]]*}"}"; kc="${kc%"${kc##*[![:space:]]}"}"   # trim
  kc="${kc#\"}"; kc="${kc%\"}"
  if [[ -n "$kc" ]]; then SEARCH+=("$kc"); fi
done < <(security list-keychains -d user)
[[ ${#SEARCH[@]} -gt 0 ]] || die "Couldn't read the keychain search list."
security create-keychain "$KC"
# create-keychain adds it to the search list; take it off again so other apps never see it.
security list-keychains -d user -s "${SEARCH[@]}"
chmod 600 "$KC"
security set-keychain-settings -l -u -t 300 "$KC"
security import "$TMP/identity.p12" -k "$KC" -P "$PASS" -T /usr/bin/codesign -x >/dev/null
echo
echo "Type the signing keychain password once more, to let codesign use the key while the keychain is unlocked:"
security set-key-partition-list -S apple-tool:,apple: -s "$KC" >/dev/null
security lock-keychain "$KC"
echo
echo "Signing identity ready: \"$NAME\" (SHA-1 $HASH) in $KC (locked)."

# The certificate made earlier in Keychain Access isn't needed any more.
OLD="$(security find-identity -p codesigning "$LOGIN_KC" | sed -n "s/^ *[0-9]*) \([0-9A-F]\{40\}\) \"$NAME\".*/\1/p" | sort -u)"
for h in $OLD; do
  echo
  read -r -p "Delete the older \"$NAME\" certificate (SHA-1 $h) from your login keychain? [Y/n] " ans
  if [[ ! "$ans" =~ ^[Nn] ]]; then
    security delete-identity -Z "$h" "$LOGIN_KC" && echo "Deleted."
  fi
done
echo
echo "Next: tools/build_app.sh"
