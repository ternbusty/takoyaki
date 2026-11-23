#!/bin/bash
set -eu

ARCH=$(uname -m)
BASE=https://github.com/ternbusty/takoyaki/releases/latest/download
BIN=/usr/local/bin/takoyaki

echo "Installing takoyaki for $ARCH ..."

# -f makes HTTP errors fail instead of saving the error page; download next to
# the target so a failure leaves an existing binary in place.
curl -fsSL -o "$BIN.tmp" "$BASE/takoyaki-linux-$ARCH"
chmod +x "$BIN.tmp"
mv "$BIN.tmp" "$BIN"

# AppArmor profile (Ubuntu 24.04+)
if command -v apparmor_parser >/dev/null 2>&1; then
    profile=$(mktemp)
    if curl -fsSL -o "$profile" "$BASE/apparmor-profile"; then
        install -m 0644 "$profile" /etc/apparmor.d/takoyaki
        apparmor_parser -r /etc/apparmor.d/takoyaki
        echo "AppArmor profile loaded."
    else
        echo "No AppArmor profile in this release; skipped." >&2
    fi
    rm -f "$profile"
fi

echo "Installed $("$BIN" --version) to $BIN"
