# Installing & using the PKCS#11 module

The Linux client has two parts:

1. **`izenpe-tv-agent`** — a background process that holds your OAuth session and performs
   the remote signatures.
2. **`libizenpe-pkcs11.so`** — the PKCS#11 module that Firefox / Chrome / AutoFirma /
   LibreOffice / Thunderbird load; it forwards everything to the agent.

```
app ──PKCS#11──► libizenpe-pkcs11.so ──unix socket──► izenpe-tv-agent ──HTTPS──► Izenpe HSM
```

## 1. Build the module

```bash
sudo apt install build-essential        # one-time; a C compiler (no -dev headers needed)
make -C pkcs11                           # produces pkcs11/libizenpe-pkcs11.so
```

Install it somewhere stable, e.g.:

```bash
install -Dm755 pkcs11/libizenpe-pkcs11.so ~/.local/lib/izenpe-tv/libizenpe-pkcs11.so
```

## 2. Install the Python package

```bash
pip install -e .            # or pipx install .
```

## 3. Log in and start the agent

```bash
izenpe-tv --env profesional login --dni <YOUR_DNI>   # browser: password + SMS
izenpe-tv-agent --env profesional                    # keep running (or use the systemd unit)
```

The agent listens on `$XDG_RUNTIME_DIR/izenpe-tv/agent.sock`.

### systemd user service (optional)

```bash
mkdir -p ~/.config/systemd/user
cp packaging/izenpe-tv-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now izenpe-tv-agent
```

## 4. Register the module in applications

### Flatpak Firefox / Thunderbird
The sandbox must see the module and the agent socket directory:
```bash
flatpak override --user --filesystem=~/.local/lib/izenpe-tv:ro \
                        --filesystem=xdg-run/izenpe-tv org.mozilla.firefox
```
Restart Firefox afterwards. (Same for `org.mozilla.thunderbird_esr`.)

### Firefox / Thunderbird (NSS)
Settings → Privacy & Security → Security Devices → **Load**:
- Module name: `Izenpe Tarjeta Virtual`
- Module filename: `~/.local/lib/izenpe-tv/libizenpe-pkcs11.so`

Or from the CLI:
```bash
modutil -dbdir sql:$HOME/.mozilla/firefox/<profile> -add "Izenpe Tarjeta Virtual" \
        -libfile ~/.local/lib/izenpe-tv/libizenpe-pkcs11.so
```

### System-wide via p11-kit (Chrome, AutoFirma, LibreOffice, OpenSSL)
```bash
mkdir -p ~/.config/pkcs11/modules
cat > ~/.config/pkcs11/modules/izenpe-tv.module <<EOF
module: $HOME/.local/lib/izenpe-tv/libizenpe-pkcs11.so
EOF
```
Then `p11-kit list-modules` should show the Izenpe token, and
`pkcs11-tool --module ~/.local/lib/izenpe-tv/libizenpe-pkcs11.so -O` lists your cert+key.

## Notes / limitations

- The token is **read-only** and advertises a *protected authentication path* (no PIN
  prompt): authentication happens in the agent via the browser login.
- Supported signing mechanisms: `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS`, and the combined
  `CKM_{SHA1,SHA256,SHA384,SHA512}_RSA_PKCS[_PSS]`.
- Certificates become usable ~15 min after login (then refreshed via the OAuth refresh
  token); if signing fails with an auth error, re-run `izenpe-tv login`.
- The module links only against libc/pthread, so the binary built on one machine runs on
  older glibc too (built here against ≤ GLIBC_2.14).

## AutoFirma (Linux, 1.9)

AutoFirma looks for Firefox in `~/.mozilla/firefox/profiles.ini`; with flatpak Firefox it
falls back to the **shared NSS DB `~/.pki/nssdb`** and loads the external PKCS#11 modules
listed in its `pkcs11.txt`. So register the module there (also used by Chrome/Chromium):

```bash
cp -a ~/.pki/nssdb ~/.pki/nssdb.bak-$(date +%F)       # backup first
flatpak run --filesystem=~/.pki/nssdb --command=modutil org.freedesktop.Sdk//25.08 \
    -dbdir sql:$HOME/.pki/nssdb -add "Izenpe Tarjeta Virtual" \
    -libfile $HOME/.local/lib/izenpe-tv/libizenpe-pkcs11.so -force
```

Flatpak AutoFirma (`es.gob.afirma`) also needs to see the module and the agent socket:

```bash
flatpak override --user --filesystem=~/.local/lib/izenpe-tv:ro \
                        --filesystem=xdg-run/izenpe-tv es.gob.afirma
```

Verified at the Java level: `keytool` with `SunPKCS11` (`library=` the module) lists the
certificate as a `PrivateKeyEntry` and signs a CSR that OpenSSL verifies.

## Idazki Desktop (Linux, 4.0.4)

Idazki runs unsandboxed with its own JRE (`/usr/local/idazki-desktop/jre`, Java 11).
With `enablePkcs11=true` (default in `izenpesigner-desktop.properties`) it tries every
library listed in **`/usr/local/idazki-desktop/pkcs11.properties`** (one path per line).
Add the module there (host terminal, needs sudo):

```bash
printf '\n%s\n' "$HOME/.local/lib/izenpe-tv/libizenpe-pkcs11.so" | \
    sudo tee -a /usr/local/idazki-desktop/pkcs11.properties
```

The shipped file has **no trailing newline**: a plain `echo >>` glues the path onto the
last line (`…/opensc-pkcs11.so/home/…`) and Idazki silently falls back to PKCS#12.
An update of Idazki may overwrite the file: re-check after upgrading.

If Idazki asks for a PIN, any value works: authentication happens in the agent.
Verified with Idazki's own Java 11 (`keytool` + `SunPKCS11`: lists the key, signs a CSR).
Alternative (not needed): `enableMozillaKeyStore=true` + `mozillaUserProfile=<NSS dir>`.
