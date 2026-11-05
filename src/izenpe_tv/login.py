"""Interactive login: open the system browser and capture the oauth-swift:// redirect.

Two capture strategies:
  * "handler": register a desktop handler for the oauth-swift:// scheme that writes the
    redirect URL to a FIFO we listen on. Requires one-time `install-handler`.
  * "manual": the user copies the final oauth-swift://... URL from the browser's error /
    address bar and pastes it. Zero dependencies — always available.
"""
from __future__ import annotations

import webbrowser

import requests

from . import config, oauth, storage
from .config import Environment
from .oauth import Token


def _resolve_client_and_exchange(env: Environment, code: str) -> tuple[Token, str]:
    """Exchange the code, trying each candidate client_id until one works."""
    last = None
    s = requests.Session()
    for cid in config.CLIENT_ID_CANDIDATES:
        try:
            tok = oauth.exchange_code(env, code, client_id=cid, session=s)
            return tok, cid
        except oauth.OAuthError as e:
            last = e
    raise oauth.OAuthError(f"token exchange failed for all client_id candidates: {last}")


def login_manual(env: Environment, *, ui_locales: str = "eu",
                 login_hint: str | None = None, open_browser: bool = True) -> Token:
    url, state = oauth.build_authorize_url(env, ui_locales=ui_locales, login_hint=login_hint)
    print("\nOpen this URL and sign in (DNI/NIE + password + SMS):\n")
    print("  " + url + "\n")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    print("After authorising, your browser will try to open a link starting with")
    print(f"  {config.REDIRECT_URI}?code=...")
    print("Copy that full URL and paste it here.\n")
    redirect = input("Paste redirect URL: ").strip()
    code = oauth.parse_redirect(redirect, expected_state=state)
    token, cid = _resolve_client_and_exchange(env, code)
    storage.save_token(env.profile, token)
    print(f"\nLogged in (client_id={cid}). Token expires in {token.expires_in}s.")
    return token


def ensure_token(env: Environment) -> Token:
    """Return a valid token, refreshing if needed; raise if not logged in."""
    tok = storage.load_token(env.profile)
    if tok is None:
        raise oauth.OAuthError(f"not logged in for profile {env.profile!r}; run `izenpe-tv login`")
    if tok.is_expired() and tok.refresh_token:
        tok = oauth.refresh_token(env, tok.refresh_token)
        storage.save_token(env.profile, tok)
    return tok
