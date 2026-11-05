"""OAuth2 authorization-code flow against the TrustedX authserver."""
from __future__ import annotations

import secrets
import time
import urllib.parse as urlparse
from dataclasses import dataclass, field

import requests

from . import config
from .config import Environment


@dataclass
class Token:
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int = 0
    obtained_at: float = field(default_factory=time.time)

    @property
    def expires_at(self) -> float:
        return self.obtained_at + self.expires_in

    def is_expired(self, skew: int = 60) -> bool:
        if not self.expires_in:
            return False
        return time.time() >= (self.expires_at - skew)

    def to_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "obtained_at": self.obtained_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Token":
        return cls(
            access_token=d["access_token"],
            refresh_token=d.get("refresh_token"),
            token_type=d.get("token_type", "Bearer"),
            expires_in=int(d.get("expires_in", 0) or 0),
            obtained_at=float(d.get("obtained_at", time.time())),
        )


def build_authorize_url(
    env: Environment,
    *,
    state: str | None = None,
    ui_locales: str = "eu",
    login_hint: str | None = None,
    client_id: str | None = None,
    app_params: dict | None = None,
) -> tuple[str, str]:
    """Return (authorize_url, state), built to match the official app exactly.

    Encoding notes recovered from the Windows client:
      * parameter order: client_id, response_type, redirect_uri, scope, acr_values,
        state, ui_locales, login_hint, (app_version, app_platform, app_arch)
      * scope's three URNs are joined with '+'; every URN is fully %-encoded (':' -> %3A)
      * acr_values is one fully %-encoded string ('|' -> %7C)
    We omit the telemetry app_* params by default (the server rejected app_platform=linux
    with "invalid request"); pass `app_params` to include them if ever needed.
    """
    state = state or secrets.token_urlsafe(16)
    q = urlparse.quote

    def enc(v: str) -> str:
        return q(v, safe="")

    scope_val = "+".join(enc(s) for s in config.SCOPE.split())
    parts = [
        f"client_id={enc(client_id or env.client_id)}",
        "response_type=code",
        f"redirect_uri={enc(config.REDIRECT_URI)}",
        f"scope={scope_val}",
        f"acr_values={enc(env.acr_values)}",
        f"state={enc(state)}",
        f"ui_locales={enc(ui_locales)}",
    ]
    if login_hint:
        parts.append(f"login_hint={enc(login_hint)}")
    for k in ("app_version", "app_platform", "app_arch"):
        if app_params and app_params.get(k) is not None:
            parts.append(f"{k}={enc(str(app_params[k]))}")
    return f"{env.base_url}{config.PATH_AUTHORIZE}?" + "&".join(parts), state


def parse_redirect(redirect: str, *, expected_state: str | None = None) -> str:
    """Extract the authorization `code` from an oauth-swift://oauth-callback?... URL."""
    parsed = urlparse.urlparse(redirect)
    qs = urlparse.parse_qs(parsed.query)
    if "error" in qs:
        raise OAuthError(f"authorization error: {qs['error'][0]} {qs.get('error_description',[''])[0]}")
    code = qs.get("code", [None])[0]
    if not code:
        raise OAuthError(f"no authorization code in redirect: {redirect!r}")
    if expected_state is not None:
        got = qs.get("state", [None])[0]
        if got != expected_state:
            raise OAuthError(f"state mismatch (csrf): expected {expected_state!r}, got {got!r}")
    return code


def exchange_code(env: Environment, code: str, *, client_id: str | None = None,
                  session: requests.Session | None = None) -> Token:
    s = session or requests.Session()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id or env.client_id,
        "client_secret": env.client_secret,
        "redirect_uri": config.REDIRECT_URI,
    }
    r = s.post(f"{env.base_url}{config.PATH_TOKEN}", data=data,
               headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=30)
    return _token_from_response(r)


def refresh_token(env: Environment, refresh: str, *, client_id: str | None = None,
                  session: requests.Session | None = None) -> Token:
    s = session or requests.Session()
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "client_id": client_id or env.client_id,
        "client_secret": env.client_secret,
    }
    r = s.post(f"{env.base_url}{config.PATH_TOKEN}", data=data,
               headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=30)
    tok = _token_from_response(r)
    if not tok.refresh_token:
        tok.refresh_token = refresh  # some servers omit it on refresh
    return tok


def _token_from_response(r: requests.Response) -> Token:
    if r.status_code != 200:
        raise OAuthError(f"token endpoint returned HTTP {r.status_code}: {r.text[:300]}")
    try:
        j = r.json()
    except ValueError:
        raise OAuthError(f"token endpoint returned non-JSON: {r.text[:300]}")
    if "access_token" not in j:
        raise OAuthError(f"no access_token in response: {j}")
    return Token.from_dict(j)


class OAuthError(RuntimeError):
    pass
