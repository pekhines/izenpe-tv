#!/usr/bin/env bash
# izenpe-tv — erabiltzaile-instalatzailea (ez du root behar, Idazkirentzat izan ezik).
#
#   ./install.sh [--msi TarjetaVirtual-Setup-X.Y.Z.msi] [--no-apps] [--yes]
#   ./install.sh --uninstall
#
# Instalatzen du:
#   ~/.local/lib/izenpe-tv/libizenpe-pkcs11.so   PKCS#11 modulua
#   ~/.local/share/izenpe-tv/venv/               Python ingurunea (agentea + login leihoa)
#   ~/.local/bin/{izenpe-tv,izenpelogin}         komandoak
#   ~/.local/share/applications/izenpelogin.desktop
# eta aukeran modulua erregistratzen du: p11-kit, ~/.pki/nssdb (Chrome, AutoFirma),
# Firefox profilak, flatpak baimenak eta Idazki Desktop.
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
LIBDIR="$HOME/.local/lib/izenpe-tv"
MODULE="$LIBDIR/libizenpe-pkcs11.so"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
VENV="$DATA/izenpe-tv/venv"
BIN="$HOME/.local/bin"
APPS="$DATA/applications"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/izenpe-tv"
P11KIT="${XDG_CONFIG_HOME:-$HOME/.config}/pkcs11/modules/izenpe-tv.module"
IDAZKI_PROPS=/usr/local/idazki-desktop/pkcs11.properties
MODNAME="Izenpe Tarjeta Virtual"
FLATPAK_APPS=(org.mozilla.firefox org.mozilla.thunderbird es.gob.afirma)

MSI="" APPS_ON=1 YES=0 UNINSTALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --msi) MSI="$2"; shift 2 ;;
        --no-apps) APPS_ON=0; shift ;;
        --yes|-y) YES=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "aukera ezezaguna: $1" >&2; exit 2 ;;
    esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31merrorea:\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { # ask "galdera" → 0 = bai
    [ "$YES" = 1 ] && return 0
    local a; read -r -p "    $1 [B/e] " a || true
    case "${a,,}" in ""|b|bai|y|yes|s|si) return 0 ;; *) return 1 ;; esac
}
have() { command -v "$1" >/dev/null 2>&1; }

nss_dbs() { # NSS datu-baseak: partekatua + Firefox profilak (natiboa eta flatpak)
    [ -f "$HOME/.pki/nssdb/cert9.db" ] && echo "$HOME/.pki/nssdb"
    local d
    for d in "$HOME"/.mozilla/firefox/*/ "$HOME"/.var/app/org.mozilla.firefox/.mozilla/firefox/*/ "$HOME"/.var/app/org.mozilla.firefox/config/mozilla/firefox/*/ \
             "$HOME"/.thunderbird/*/ "$HOME"/.var/app/org.mozilla.thunderbird/.thunderbird/*/; do
        [ -f "$d/cert9.db" ] && echo "${d%/}"
    done
    return 0
}

# ------------------------------------------------------------------ desinstalatu
if [ "$UNINSTALL" = 1 ]; then
    say "Desinstalatzen"
    systemctl --user stop izenpe-tv-agent izenpelogin-reminder.timer 2>/dev/null || true
    if have modutil; then
        while read -r db; do
            modutil -dbdir "sql:$db" -delete "$MODNAME" -force >/dev/null 2>&1 \
                && ok "NSS: kenduta ($db)" || true
        done < <(nss_dbs)
    fi
    rm -f "$P11KIT" "$BIN/izenpe-tv" "$BIN/izenpelogin" "$BIN/izenpe-tv-agent" \
          "$APPS/izenpelogin.desktop"
    rm -rf "$VENV" "$LIBDIR"
    ok "fitxategiak kenduta"
    if have flatpak; then
        for app in "${FLATPAK_APPS[@]}"; do
            flatpak override --user --nofilesystem="$LIBDIR" --nofilesystem=xdg-run/izenpe-tv \
                "$app" 2>/dev/null || true
        done
    fi
    [ -f "$IDAZKI_PROPS" ] && grep -q izenpe-tv "$IDAZKI_PROPS" && \
        warn "Idazki: kendu eskuz lerroa: sudo sed -i '/izenpe-tv/d' $IDAZKI_PROPS"
    warn "kredentzialak eta saioa ez dira ezabatu: $CONF (eta ~/.local/share/izenpe-tv)"
    exit 0
fi

# ------------------------------------------------------------------ aurrebaldintzak
say "Aurrebaldintzak egiaztatzen"
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
    if have "$c" && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
        PY="$(command -v "$c")"; break
    fi
done
[ -n "$PY" ] || die "Python ≥ 3.10 behar da"
"$PY" -c 'import venv, ensurepip' 2>/dev/null \
    || die "python venv falta da (Debian/Ubuntu: sudo apt install python3-venv)"
ok "python: $PY ($("$PY" -V 2>&1))"
CC=""; for c in cc gcc clang; do have "$c" && { CC="$c"; break; }; done
[ -n "$CC" ] || die "C konpilatzailea behar da (Debian/Ubuntu: sudo apt install build-essential; Fedora: sudo dnf install gcc make)"
have make || die "make behar da"
ok "konpilatzailea: $CC"
have systemd-run || warn "systemd-run ez dago: agentea eskuz abiarazi beharko duzu (izenpe-tv-agent)"

# ------------------------------------------------------------------ 1. PKCS#11 modulua
say "PKCS#11 modulua konpilatzen"
make -s -C "$REPO/pkcs11" CC="$CC" clean >/dev/null
make -s -C "$REPO/pkcs11" CC="$CC" >/dev/null
install -Dm755 "$REPO/pkcs11/libizenpe-pkcs11.so" "$MODULE"
ok "$MODULE"

# ------------------------------------------------------------------ 2. Python + agentea
say "Python ingurunea sortzen ($VENV)"
[ -x "$VENV/bin/python" ] || "$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install -q --upgrade pip
"$VENV/bin/python" -m pip install -q "$REPO[webview]" \
    || die "pip install-ek huts egin du (sarea?)"
ok "izenpe-tv instalatuta (PyQt6 WebEngine barne)"

mkdir -p "$BIN" "$APPS"
for cmd in izenpe-tv izenpelogin izenpe-tv-agent; do
    ln -sf "$VENV/bin/$cmd" "$BIN/$cmd"
done
ok "komandoak: $BIN/izenpe-tv, $BIN/izenpelogin"
case ":$PATH:" in *":$BIN:"*) ;; *) warn "$BIN ez dago PATH-ean; gehitu zure ~/.profile-n" ;; esac

ICON=security-high
[ -f "$REPO/packaging/izenpelogin.png" ] && {
    install -Dm644 "$REPO/packaging/izenpelogin.png" "$DATA/icons/izenpelogin.png"
    ICON="$DATA/icons/izenpelogin.png"; }
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
have update-desktop-database && update-desktop-database "$APPS" 2>/dev/null || true
ok "menuko sarrera: izenpelogin"

# ------------------------------------------------------------------ 3. kredentzialak
say "OAuth kredentzialak"
if [ -f "$CONF/client.toml" ]; then
    ok "badaude ($CONF/client.toml)"
else
    if [ -z "$MSI" ]; then
        MSI="$(ls -1t "$REPO"/TarjetaVirtual-Setup-*.msi "$HOME"/Downloads/TarjetaVirtual-Setup-*.msi \
               "$HOME"/Deskargak/TarjetaVirtual-Setup-*.msi "$HOME"/Descargas/TarjetaVirtual-Setup-*.msi \
               2>/dev/null | head -1 || true)"
    fi
    if [ -n "$MSI" ] && [ -f "$MSI" ]; then
        "$VENV/bin/izenpe-tv" setup-credentials "$MSI" && ok "atera dira: $MSI"
    else
        warn "Ez dut aurkitu Izenperen instalatzaile ofiziala (TarjetaVirtual-Setup-*.msi)."
        warn "Deskargatu Izenperen webgunetik (Windows bertsioa) eta exekutatu:"
        warn "  izenpe-tv setup-credentials ~/Deskargak/TarjetaVirtual-Setup-X.Y.Z.msi"
    fi
fi

# ------------------------------------------------------------------ 4. aplikazioak
if [ "$APPS_ON" = 1 ]; then
    say "Aplikazioetan erregistratzen"

    mkdir -p "$(dirname "$P11KIT")"
    echo "module: $MODULE" > "$P11KIT"
    ok "p11-kit ($P11KIT)"

    if have modutil; then
        while read -r db; do
            if modutil -dbdir "sql:$db" -list 2>/dev/null | grep -q "$MODNAME"; then
                ok "NSS: badago ($db)"
            elif ask "Modulua erregistratu NSS datu-basean $db ? (itxi Firefox lehenago)"; then
                cp -a "$db" "$db.bak-izenpe-tv-$(date +%F)" 2>/dev/null || true
                modutil -dbdir "sql:$db" -add "$MODNAME" -libfile "$MODULE" -force >/dev/null \
                    && ok "NSS: erregistratuta ($db)" || warn "NSS: huts ($db)"
            fi
        done < <(nss_dbs)
        [ -n "$(nss_dbs)" ] || warn "ez da NSS datu-baserik aurkitu (ireki Firefox behin eta exekutatu berriro)"
    else
        warn "modutil ez dago (Debian/Ubuntu: libnss3-tools; Fedora: nss-tools)."
        warn "Firefox: Ezarpenak → Pribatutasuna eta segurtasuna → Segurtasun-gailuak → Kargatu → $MODULE"
    fi

    if have flatpak; then
        for app in "${FLATPAK_APPS[@]}"; do
            flatpak info "$app" >/dev/null 2>&1 || continue
            flatpak override --user --filesystem="$LIBDIR:ro" --filesystem=xdg-run/izenpe-tv "$app"
            ok "flatpak baimenak: $app"
        done
    fi

    if [ -f "$IDAZKI_PROPS" ]; then
        if grep -qF "$MODULE" "$IDAZKI_PROPS"; then
            ok "Idazki Desktop: badago"
        elif ask "Idazki Desktop aurkitu da. Modulua gehitu (sudo behar du)?"; then
            printf '\n%s\n' "$MODULE" | sudo tee -a "$IDAZKI_PROPS" >/dev/null \
                && ok "Idazki Desktop: gehituta" || warn "Idazki: huts"
        fi
    fi
fi

# ------------------------------------------------------------------ amaiera
say "Eginda"
cat <<EOF
    Hurrengo pausua: ireki "izenpelogin" (menuan) edo exekutatu: izenpelogin
    NAN/AIZ + pasahitza + SMS kodea sartu ondoren, ziurtagiria Firefox, Chrome,
    AutoFirma, LibreOffice eta Idazki Desktop-en agertuko da (PINik ez da behar;
    eskatzen badu, edozer).
    Flatpak aplikazioak (Firefox, AutoFirma) berrabiarazi baimen berriak har ditzaten.
EOF
