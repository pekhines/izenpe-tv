"""Token + state persistence.

Prefers the Secret Service (via `keyring`) when available; otherwise falls back to a
0600 JSON file under $XDG_CONFIG_HOME/izenpe-tv/.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .oauth import Token

APP = "izenpe-tv"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = Path(base) / APP
    d.mkdir(parents=True, exist_ok=True)
    return d


def _token_path(profile: str) -> Path:
    return config_dir() / f"token-{profile}.json"


def _try_keyring():
    try:
        import keyring  # type: ignore
        return keyring
    except Exception:
        return None


def save_token(profile: str, token: Token) -> None:
    payload = json.dumps(token.to_dict())
    kr = _try_keyring()
    if kr is not None:
        try:
            kr.set_password(APP, f"token-{profile}", payload)
            return
        except Exception:
            pass
    p = _token_path(profile)
    p.write_text(payload)
    os.chmod(p, 0o600)


def load_token(profile: str) -> Token | None:
    kr = _try_keyring()
    if kr is not None:
        try:
            raw = kr.get_password(APP, f"token-{profile}")
            if raw:
                return Token.from_dict(json.loads(raw))
        except Exception:
            pass
    p = _token_path(profile)
    if p.exists():
        return Token.from_dict(json.loads(p.read_text()))
    return None


def clear_token(profile: str) -> None:
    kr = _try_keyring()
    if kr is not None:
        try:
            kr.delete_password(APP, f"token-{profile}")
        except Exception:
            pass
    p = _token_path(profile)
    if p.exists():
        p.unlink()
