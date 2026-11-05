# Izenpe Tarjeta Virtual — protocol (reverse-engineered)

Source: official Windows app **v4.0.9** (`TarjetaVirtual-Setup-4.0.9.msi`).
The app is **Flutter** (UI in `data/app.so`) plus native C++ helpers:

- `izenpe_sign_bridge.dll` — talks to the Izenpe REST API (OAuth + signing).
- `izenpe_ksp.dll` — Windows CNG **Key Storage Provider** ("Izenpe KSP"), a read-only
  provider exposing the remote keys; forwards every `NCryptSignHash` to the bridge.
- A **SignBroker** named pipe `\\.\pipe\Izenpe_TV_Bridge` lets the KSP (possibly in an
  AppContainer) reach the running app to perform a signature.

> The private key **never** exists locally. Each signature is one HTTPS POST of the hash
> to Izenpe's HSM-backed "Remote Signing Engine" (Entrust TrustedX eIDAS, ex-Safelayer).

The whole thing is what we must reproduce on Linux as a **PKCS#11** module (instead of CNG KSP).

---

## 1. Environments

| Perfil | PROD | DESA (dev) |
|---|---|---|
| **Profesional** | `https://eidas-prof.izenpe.eus` | `https://eidas-profdes.izenpe.eus:8082` |
| **Ciudadano / BakQ** | `https://eidas.izenpe.com` | `https://eidasdes.izenpe.com:8082` |

Stored under HKLM `SOFTWARE\Izenpe\TarjetaVirtual\Environment` on Windows.
We keep it in `~/.config/izenpe-tv/config.toml`.

## 2. OAuth2 (Authorization Code)

- **authorize:** `{base}/trustedx-authserver/oauth/izenpe`
- **token:** `{base}/trustedx-authserver/oauth/izenpe/token`
- **redirect_uri:** `oauth-swift://oauth-callback` (custom scheme, intercepted by the app's WebView)
- **response_type:** `code`
- **scope:** `urn:izenpe:identity:global urn:safelayer:eidas:sign:identity:register urn:safelayer:eidas:sign:identity:profile`
- **acr_values:**
  - profesional: `urn:izenpe:authentication:flow:bak_otp|urn:safelayer:tws:policies:authentication:flow:izmobileid:prof`
  - ciudadano:  `urn:safelayer:tws:policies:authentication:flow:bakq|urn:safelayer:tws:policies:authentication:flow:izmobileid:citizen`
- extra params observed: `state`, `ui_locales` (es/eu), `login_hint` (DNI), `app_arch`, `app_platform`, `app_version`

Authorize query template (values URL-encoded):

```
{base}/trustedx-authserver/oauth/izenpe
  ?client_id={CLIENT_ID}
  &response_type=code
  &redirect_uri=oauth-swift://oauth-callback
  &scope=urn:izenpe:identity:global urn:safelayer:eidas:sign:identity:register urn:safelayer:eidas:sign:identity:profile
  &acr_values={ACR}
  &state={random}
  &ui_locales={es|eu}
  &login_hint={dni}
```

The user authenticates on Izenpe's web page: **DNI/NIE + password + SMS code**, then
authorises the sign-identity registration. The server 302-redirects to
`oauth-swift://oauth-callback?code=...&state=...`.

**Token exchange** — `POST {token}` form-encoded:

```
grant_type=authorization_code&code={code}&client_id={ID}&client_secret={SECRET}&redirect_uri=oauth-swift://oauth-callback
```

Response JSON: `{access_token, refresh_token, token_type:"Bearer", expires_in}`.

**Refresh** — `grant_type=refresh_token&refresh_token=...&client_id=...&client_secret=...`.

### Embedded client credentials

The app is a *confidential* client with an embedded id/secret (public by nature of a
desktop app; reused for interoperability). **These are deliberately not stored in this
repo.** Extract them from the official app and configure them locally (env vars or
`~/.config/izenpe-tv/client.toml`, see `client.toml.example`).

Where to find them in the Windows app `TarjetaVirtual.exe` (Flutter string table): the
`client_id` candidates and `client_secret` (a PROD and a DESA value) appear next to the
strings `oauth_profile`, `legacy` and `vsc2026`. `izenpe-tv login` tries each configured
`client_id` candidate and persists the one the token endpoint accepts. Nothing here is a
*user* secret.

## 3. REST API (Bearer access_token)

Header: `Authorization: Bearer {access_token}`.

| Method | Path | Purpose |
|---|---|---|
| GET  | `/trustedx-resources/openid/v1/users/me` | user info: `labels`, `organization`, DNI/CIF, `self_url` |
| GET  | `/trustedx-resources/esigp/v1/sign_identities/` | list signing identities |
| GET  | `/trustedx-resources/esigp/v1/sign_identities/{id}` | identity detail → `certificate` (base64 DER) |
| POST | `/trustedx-resources/esigp/v1/signatures/server/raw` | **remote signature** |

**Identity labels** distinguish profiles:
- `bakq` → ciudadano (BakQ) certificate
- `CIF:<cif>` → profesional certificate; the app keeps only those whose CIF matches the
  logged-in user's CIF.

### Remote signature

`POST /trustedx-resources/esigp/v1/signatures/server/raw`, `Content-Type: application/json`:

```json
{
  "sign_identity_id": "<id>",
  "digest_value": "<base64 raw hash>",       // for rsa-sha256/384/512
  "signature_algorithm": "rsa-sha256"
}
```
or, for legacy PKCS#1 with a full DigestInfo:
```json
{ "sign_identity_id": "<id>", "data": "<base64 DigestInfo>", "signature_algorithm": "rsa-sha256" }
```

`signature_algorithm` ∈ `rsa-sha1`, `rsa-sha256`, `rsa-sha384`, `rsa-sha512`,
`rsa-pss-mgf1-sha1`, `rsa-pss-mgf1-sha256`, `rsa-pss-mgf1-sha384`, `rsa-pss-mgf1-sha512`.

Hash size → algorithm mapping the bridge uses:
- 20 bytes raw → sha1, 32 → sha256, 48 → sha384, 64 → sha512
- 35/51/67/83 bytes → DigestInfo ASN.1 (strip prefix to get the raw hash)
- TLS 1.0/1.1 36-byte MD5+SHA1 combo is **not** supported by the HSM (needs TLS ≥1.2).

Response: the signature bytes (base64, or a `{"bytes":[...],"subtype":...}` JSON wrapper).

## 4. Windows specifics (for reference, not needed on Linux)

- KSP registered under `SYSTEM\...\Cryptography\Providers\Izenpe KSP` and
  `SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Izenpe KSP`, `Functions=KEY_STORAGE`.
- `p11rss.dll` was the PKCS#11 lib in the older (2.3.x) client; the 4.x client uses the
  CNG KSP + sign bridge instead.
- Tokens stored in Windows Credential Manager as `Izenpe_TarjetaVirtual_*` /
  `Izenpe Tarjeta virtual - OAuth Token`.
- Certificate ↔ identity mapping cached as `sign_identity_by_thumbprint_*`,
  `user_type_by_thumbprint_*`.

## 5. Linux design (target)

```
 app (Firefox/Chrome/AutoFirma/LibreOffice)
        │  PKCS#11
        ▼
 libizenpe-pkcs11.so  ──unix socket──►  izenpe-tv-agent (daemon)
                                          ├─ OAuth login (system browser + oauth-swift:// handler)
                                          ├─ token store (Secret Service / libsecret)
                                          ├─ identity + cert cache
                                          └─ remote sign  → Izenpe REST
```

Milestones: **(1)** CLI that logs in, lists identities, downloads cert, signs a hash
(validates the protocol end-to-end). **(2)** agent + PKCS#11 module. **(3)** NSS/p11-kit
registration + packaging (.deb/.rpm) + systemd user service.
