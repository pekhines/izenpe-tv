"""Interactive login: open the system browser and capture the oauth-swift:// redirect.

Two capture strategies:
  * "handler": register a desktop handler for the oauth-swift:// scheme that writes the
    redirect URL to a FIFO we listen on. Requires one-time `install-handler`.
  * "manual": the user copies the final oauth-swift://... URL from the browser's error /
    address bar and pastes it. Zero dependencies — always available.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import webbrowser

import requests

from . import config, oauth, storage
from .callback import login_socket_path
from .config import Environment
from .oauth import Token

SCHEME = "oauth-swift"
DESKTOP_ID = "izenpe-tv-callback.desktop"


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


def _callback_exe() -> str:
    exe = shutil.which("izenpe-tv-callback")
    if exe:
        return f"{exe} %u"
    # dev fallback: run the module with the current interpreter, carrying the src path
    src_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return f"env PYTHONPATH={src_root} {sys.executable} -m izenpe_tv.callback %u"


def install_scheme_handler() -> str:
    """Register this app as the handler for oauth-swift:// . Returns the .desktop path."""
    apps = os.path.join(
        os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"),
        "applications",
    )
    os.makedirs(apps, exist_ok=True)
    desktop = os.path.join(apps, DESKTOP_ID)
    content = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Izenpe TV OAuth callback\n"
        f"Exec={_callback_exe()}\n"
        "NoDisplay=true\n"
        "Terminal=false\n"
        f"MimeType=x-scheme-handler/{SCHEME};\n"
    )
    with open(desktop, "w") as f:
        f.write(content)
    try:
        subprocess.run(["update-desktop-database", apps], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass
    try:
        subprocess.run(["xdg-mime", "default", DESKTOP_ID, f"x-scheme-handler/{SCHEME}"],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass
    return desktop


def login_auto(env: Environment, *, ui_locales: str = "eu", login_hint: str | None = None,
               timeout: float = 300.0) -> Token:
    """Browser login that captures the oauth-swift:// redirect automatically."""
    install_scheme_handler()
    sock_path = login_socket_path()
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(1)
    srv.settimeout(timeout)

    url, state = oauth.build_authorize_url(env, ui_locales=ui_locales, login_hint=login_hint)
    print("\nOpening your browser to sign in (DNI/NIE + password + SMS)...\n")
    print("  " + url + "\n")
    opened = webbrowser.open(url)
    if not opened:
        print("Could not open a browser automatically; open the URL above manually.")
    print("Waiting for the login to complete (the browser will hand the code back)...")

    try:
        conn, _ = srv.accept()
        data = b""
        conn.settimeout(10)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        conn.close()
        redirect = data.decode().strip()
    except socket.timeout:
        srv.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        raise oauth.OAuthError(
            "timed out waiting for the browser redirect. If your browser showed an "
            "'oauth-swift://…' link or error, copy that URL and run `izenpe-tv login --manual`."
        )
    finally:
        srv.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)

    code = oauth.parse_redirect(redirect, expected_state=state)
    token, cid = _resolve_client_and_exchange(env, code)
    storage.save_token(env.profile, token)
    print(f"\nLogged in (client_id={cid}). Token expires in {token.expires_in}s.")
    return token


def login_webview(env: Environment, *, ui_locales: str = "eu",
                  login_hint: str | None = None) -> Token:
    """Preferred login: embedded Qt WebEngine browser (mirrors the official client)."""
    from . import webview_login as wv
    redirect, state = wv.webview_login(env, ui_locales=ui_locales, login_hint=login_hint)
    code = oauth.parse_redirect(redirect, expected_state=state)
    token, cid = _resolve_client_and_exchange(env, code)
    storage.save_token(env.profile, token)
    print(f"\nLogged in (client_id={cid}). Token expires in {token.expires_in}s.")
    return token


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
