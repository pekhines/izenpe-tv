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

# Order as sent by the official client (global, profile, register)
SCOPE = (
    "urn:izenpe:identity:global "
    "urn:safelayer:eidas:sign:identity:profile "
    "urn:safelayer:eidas:sign:identity:register"
)

REDIRECT_URI = "oauth-swift://oauth-callback"

# The official app always appends these three params. Values captured from the real
# Windows client v4.0.9 authorize URL (its own log). Override per-call if needed.
DEFAULT_APP_PARAMS = {
    "app_version": "4.0.9",
    "app_platform": "windows",
    "app_arch": "x64",
}
# The official client's OAuth profile name IS its client_id (captured from its log:
# "client_id=vsc2026"). The id is public; only the secret is kept out of the repo.
DEFAULT_CLIENT_ID = "vsc2026"

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
    client_id: str
    client_secret: str


# The client_secret is NOT hardcoded here: it lives in the official app's binary.
# Put candidates in ~/.config/izenpe-tv/client.toml (or env vars); the token exchange
# tries them in order and remembers the one that works. Keeps secrets out of git.
_CLIENT_ID = [DEFAULT_CLIENT_ID]
_SECRET_CANDIDATES: list[str] = []


def load_client_credentials() -> None:
    """Load client_id and client_secret candidates.

    Env: IZENPE_TV_CLIENT_ID, IZENPE_TV_CLIENT_SECRETS (comma-separated).
    ~/.config/izenpe-tv/client.toml:
        client_id = "vsc2026"
        client_secrets = ["...", "..."]
    """
    import os
    cid = os.environ.get("IZENPE_TV_CLIENT_ID")
    secs = os.environ.get("IZENPE_TV_CLIENT_SECRETS")
    secret_list = [x.strip() for x in secs.split(",") if x.strip()] if secs else []

    path = os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
        "izenpe-tv", "client.toml",
    )
    if os.path.exists(path):
        try:
            import tomllib
            with open(path, "rb") as f:
                data = tomllib.load(f)
            cid = cid or data.get("client_id")
            if not secret_list:
                secret_list = [str(x) for x in data.get("client_secrets", [])]
        except Exception:
            pass

    if cid:
        _CLIENT_ID[0] = cid
    if secret_list:
        _SECRET_CANDIDATES[:] = secret_list
    _rebuild_environments()


def credentials_present() -> bool:
    return bool(_CLIENT_ID[0] and _SECRET_CANDIDATES)


def client_secret_candidates() -> list[str]:
    return list(_SECRET_CANDIDATES)


_ENV_DEFS = {
    "profesional":      ("profesional", "https://eidas-prof.izenpe.eus",         ACR_PROFESIONAL),
    "profesional-desa": ("profesional", "https://eidas-profdes.izenpe.eus:8082", ACR_PROFESIONAL),
    "ciudadano":        ("ciudadano",   "https://eidas.izenpe.com",              ACR_CIUDADANO),
    "ciudadano-desa":   ("ciudadano",   "https://eidasdes.izenpe.com:8082",      ACR_CIUDADANO),
}

ENVIRONMENTS: dict[str, Environment] = {}


def _rebuild_environments() -> None:
    secret = _SECRET_CANDIDATES[0] if _SECRET_CANDIDATES else ""
    for name, (profile, base, acr) in _ENV_DEFS.items():
        ENVIRONMENTS[name] = Environment(
            name=name, profile=profile, base_url=base, acr_values=acr,
            client_id=_CLIENT_ID[0], client_secret=secret,
        )


_rebuild_environments()
