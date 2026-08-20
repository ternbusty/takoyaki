#!/bin/bash
set -eu

ARCH=$(uname -m)
BASE=https://github.com/ternbusty/takoyaki/releases/latest/download
BIN=/usr/local/bin/takoyaki

echo "Installing takoyaki for $ARCH ..."

curl -sSL -o "$BIN" "$BASE/takoyaki-linux-$ARCH"
chmod +x "$BIN"

# AppArmor profile (Ubuntu 24.04+)
if command -v apparmor_parser >/dev/null 2>&1; then
    curl -sSL -o /etc/apparmor.d/takoyaki "$BASE/apparmor-profile"
    apparmor_parser -r /etc/apparmor.d/takoyaki
    echo "AppArmor profile loaded."
fi

echo "Installed $("$BIN" --version) to $BIN"
