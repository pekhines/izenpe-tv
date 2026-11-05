#!/usr/bin/env bash
# Install the "izenpelogin" one-click launcher for the current user.
#
#   packaging/install-izenpelogin.sh [ICON.png]
#
# Creates ~/.local/bin/izenpelogin, a menu entry and a desktop icon. Uses the repo's
# .venv (needs requests, cryptography, PyQt6, PyQt6-WebEngine).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/.venv/bin/python"
[ -x "$PY" ] || { echo "missing virtualenv: $PY (create it with the 'webview' extra)" >&2; exit 1; }

DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN="$HOME/.local/bin"
APPS="$DATA/applications"
ICONS="$DATA/icons"
mkdir -p "$BIN" "$APPS" "$ICONS"

cat > "$BIN/izenpelogin" <<EOF
#!/bin/sh
export PYTHONPATH="$REPO/src"
exec "$PY" -m izenpe_tv.launcher "\$@"
EOF
chmod 755 "$BIN/izenpelogin"

if [ -n "${1:-}" ] && [ -f "$1" ]; then
    install -m 644 "$1" "$ICONS/izenpelogin.png"
fi
ICON=security-high
[ -f "$ICONS/izenpelogin.png" ] && ICON="$ICONS/izenpelogin.png"

cat > "$APPS/izenpelogin.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=izenpelogin
GenericName=Izenpe Tarjeta Virtual
Comment=Activate the Izenpe virtual card (DNI/NIE + password + SMS)
Comment[eu]=Izenpeko txartel birtuala aktibatu (NAN + pasahitza + SMS)
Comment[es]=Activar la tarjeta virtual de Izenpe (DNI/NIE + contraseña + SMS)
Exec=$BIN/izenpelogin
Icon=$ICON
Terminal=false
Categories=Utility;Security;
StartupNotify=true
EOF
chmod 644 "$APPS/izenpelogin.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" 2>/dev/null || true

DESK="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
[ -n "$DESK" ] || DESK="$HOME/Desktop"
if [ -d "$DESK" ]; then
    install -m 755 "$APPS/izenpelogin.desktop" "$DESK/izenpelogin.desktop"
    echo "desktop icon: $DESK/izenpelogin.desktop"
fi
echo "launcher:     $BIN/izenpelogin"
echo "menu entry:   $APPS/izenpelogin.desktop"
