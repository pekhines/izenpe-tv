"""Environment and OAuth client configuration for Izenpe Tarjeta Virtual.

Values reverse-engineered from the official Windows client v4.0.9. See docs/PROTOCOL.md.
Nothing here is a user secret; the client_id/secret are embedded in the public desktop app
and reused for interoperability (the user signs with their own certificate).
"""
from __future__ import annotations

from dataclasses import dataclass

# acr_values per profile (pipe-separated list of allowed authentication flows)
ACR_PROFESIONAL = (
    "urn:izenpe:authentication:flow:bak_otp"
    "|urn:safelayer:tws:policies:authentication:flow:izmobileid:prof"
)
ACR_CIUDADANO = (
    "urn:safelayer:tws:policies:authentication:flow:bakq"
    "|urn:safelayer:tws:policies:authentication:flow:izmobileid:citizen"
)

SCOPE = (
    "urn:izenpe:identity:global "
    "urn:safelayer:eidas:sign:identity:register "
    "urn:safelayer:eidas:sign:identity:profile"
)

REDIRECT_URI = "oauth-swift://oauth-callback"

# API resource paths (relative to the environment base URL)
PATH_AUTHORIZE = "/trustedx-authserver/oauth/izenpe"
PATH_TOKEN = "/trustedx-authserver/oauth/izenpe/token"
PATH_USERINFO = "/trustedx-resources/openid/v1/users/me"
PATH_SIGN_IDENTITIES = "/trustedx-resources/esigp/v1/sign_identities/"
PATH_SIGN_RAW = "/trustedx-resources/esigp/v1/signatures/server/raw"


@dataclass(frozen=True)
class Environment:
    name: str
    profile: str  # "profesional" | "ciudadano"
    base_url: str
    acr_values: str
    # id/secret candidates; resolved (and persisted) at first successful login
    client_id: str
    client_secret: str


# The embedded OAuth client credentials (client_id / client_secret) are NOT hardcoded
# here. They live in the official desktop app's binary; extract them and put them in
# ~/.config/izenpe-tv/client.toml (or set env vars). See docs/PROTOCOL.md §2 and
# `load_client_credentials()` below. This keeps secrets out of version control.
_CLIENT_ID_CANDIDATES: list[str] = []
_CLIENT_SECRET: dict[str, str] = {"prod": "", "desa": ""}


def load_client_credentials() -> None:
    """Populate client_id candidates and secrets from env or ~/.config/izenpe-tv/client.toml.

    Env vars: IZENPE_TV_CLIENT_IDS (comma-separated), IZENPE_TV_CLIENT_SECRET_PROD,
    IZENPE_TV_CLIENT_SECRET_DESA.
    TOML keys: client_ids = ["..."], client_secret_prod = "...", client_secret_desa = "..."
    """
    import os
    ids = os.environ.get("IZENPE_TV_CLIENT_IDS")
    sec_prod = os.environ.get("IZENPE_TV_CLIENT_SECRET_PROD")
    sec_desa = os.environ.get("IZENPE_TV_CLIENT_SECRET_DESA")

    if not (ids and sec_prod):
        path = os.path.join(
            os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
            "izenpe-tv", "client.toml",
        )
        if os.path.exists(path):
            try:
                import tomllib
                with open(path, "rb") as f:
                    data = tomllib.load(f)
                ids = ids or ",".join(data.get("client_ids", []))
                sec_prod = sec_prod or data.get("client_secret_prod", "")
                sec_desa = sec_desa or data.get("client_secret_desa", "")
            except Exception:
                pass

    if ids:
        _CLIENT_ID_CANDIDATES[:] = [s.strip() for s in ids.split(",") if s.strip()]
    if sec_prod:
        _CLIENT_SECRET["prod"] = sec_prod
    if sec_desa:
        _CLIENT_SECRET["desa"] = sec_desa
    _rebuild_environments()


def credentials_present() -> bool:
    return bool(_CLIENT_ID_CANDIDATES and _CLIENT_SECRET.get("prod"))

# base_url + acr + which secret (prod/desa) per environment; client_id filled at runtime
_ENV_DEFS = {
    "profesional":      ("profesional", "https://eidas-prof.izenpe.eus",         ACR_PROFESIONAL, "prod"),
    "profesional-desa": ("profesional", "https://eidas-profdes.izenpe.eus:8082", ACR_PROFESIONAL, "desa"),
    "ciudadano":        ("ciudadano",   "https://eidas.izenpe.com",              ACR_CIUDADANO,   "prod"),
    "ciudadano-desa":   ("ciudadano",   "https://eidasdes.izenpe.com:8082",      ACR_CIUDADANO,   "desa"),
}

ENVIRONMENTS: dict[str, Environment] = {}


def _rebuild_environments() -> None:
    cid = _CLIENT_ID_CANDIDATES[0] if _CLIENT_ID_CANDIDATES else ""
    for name, (profile, base, acr, sec) in _ENV_DEFS.items():
        ENVIRONMENTS[name] = Environment(
            name=name, profile=profile, base_url=base, acr_values=acr,
            client_id=cid, client_secret=_CLIENT_SECRET.get(sec, ""),
        )


_rebuild_environments()

# Exposed as a module-level reference; always read via this name (it is refreshed
# in-place when credentials load).
CLIENT_ID_CANDIDATES = _CLIENT_ID_CANDIDATES
