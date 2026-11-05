# izenpe-tv — Linux client for Izenpe's Tarjeta Virtual

Unofficial client that lets **Linux** applications use your Izenpe **cloud certificates**
(BakQ / Profesional) for authentication and signing. Izenpe only ships official clients
for Windows, macOS and mobile; this fills the gap.

The private key never leaves Izenpe's HSM: you log in (DNI/NIE + password + SMS code),
and every signature is performed remotely. The protocol was reverse-engineered from the
official Windows app for **interoperability** (EU Directive 2009/24/EC art. 6); you only
ever use **your own** certificate. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

> ⚠️ Not affiliated with or endorsed by Izenpe. Use at your own risk.

## Status

**Milestone 1 (in progress): protocol CLI.** Log in, list your identities, download your
certificate, and sign a hash — to validate the full flow end-to-end.

Next: a background agent + a **PKCS#11** module so Firefox, Chrome, AutoFirma,
LibreOffice and Thunderbird see the certificate like a smartcard.

## Install (dev)

```bash
pip install -e .           # requests + cryptography; optional: pip install -e '.[keyring]'
```

## One-click: `izenpelogin`

```bash
packaging/install-izenpelogin.sh [icon.png]   # menu entry + desktop icon + ~/.local/bin/izenpelogin
```

Clicking **izenpelogin** starts the agent if needed, opens the Izenpe login window
(you type DNI/NIE, password and the SMS code), checks the certificate is reachable and
shows a notification with the time the session stays active. A reminder pops up five
minutes before it expires. Log: `~/.cache/izenpe-tv/izenpelogin.log`.

## Usage

```bash
# Profesional (default). Opens an embedded login window (needs the `webview` extra:
# pip install -e '.[webview]'); falls back to the external browser otherwise.
izenpe-tv --env profesional login --dni 12345678Z
# force a specific login UI:  --method webview | browser | manual

izenpe-tv whoami                     # your user info (name, CIF, …)
izenpe-tv identities                 # list signing identities + ids
izenpe-tv cert <identity_id>         # certificate summary (--pem / --out cert.der)
echo -n "hola" | izenpe-tv sign <identity_id> --hash sha256   # remote signature (base64)
```

Profiles: `profesional`, `ciudadano` (BakQ) and their `-desa` (test) variants via `--env`.

## Layout

```
src/izenpe_tv/
  config.py   environments, endpoints, scopes, acr_values, client creds
  oauth.py    authorization-code flow + token refresh
  api.py      users/me, sign_identities, remote signature (server/raw)
  login.py    browser login + redirect capture
  storage.py  token persistence (Secret Service or 0600 file)
  cli.py      command-line interface
docs/PROTOCOL.md   full reverse-engineered protocol
```
