"""izenpelogin — one-click activation of the Izenpe virtual card.

1. make sure izenpe-tv-agent is running (as a systemd --user unit),
2. open the embedded Izenpe login window (the user types DNI/NIE, password, SMS code),
3. check the certificate is reachable and tell the user until when it is active,
4. schedule a reminder shortly before the session expires.

Meant to be started from a desktop launcher, so it logs to
~/.cache/izenpe-tv/izenpelogin.log and reports through desktop notifications.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import subprocess
import sys
import time
import traceback

from . import agent, api, config, login, oauth

UNIT = "izenpe-tv-agent"
APP_NAME = "Izenpe Tarjeta Virtual"
REMIND_BEFORE_S = 5 * 60


def _log_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    d = os.path.join(base, "izenpe-tv")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "izenpelogin.log")


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(_log_path(), "a") as f:
        f.write(line + "\n")


def notify(title: str, body: str, *, urgency: str = "normal", icon: str | None = None) -> None:
    exe = shutil.which("notify-send")
    if not exe:
        return
    cmd = [exe, "-a", APP_NAME, "-u", urgency]
    icon = icon or _icon()
    if icon:
        cmd += ["-i", icon]
    subprocess.run(cmd + [title, body], check=False)


def _icon() -> str | None:
    p = os.path.expanduser("~/.local/share/icons/izenpelogin.png")
    return p if os.path.exists(p) else "security-high"


def _src_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def agent_alive(sock: str) -> bool:
    import socket
    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(3)
        c.connect(sock)
        c.sendall(agent.BINARY_MAGIC + bytes([agent.OP_PING]))
        ok = c.recv(1) == b"\x00"
        c.close()
        return ok
    except OSError:
        return False


def ensure_agent(env_name: str) -> None:
    sock = agent.default_socket_path()
    if agent_alive(sock):
        log(f"agent already running ({sock})")
        return
    log("starting agent")
    subprocess.run(["systemctl", "--user", "stop", UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "--user", "reset-failed", UNIT], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    r = subprocess.run(
        ["systemd-run", "--user", f"--unit={UNIT}", "--collect",
         f"--setenv=PYTHONPATH={_src_dir()}",
         sys.executable, "-m", "izenpe_tv.agent", "--env", env_name],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"could not start agent: {r.stderr.strip()}")
    for _ in range(50):
        if agent_alive(sock):
            log("agent started")
            return
        time.sleep(0.2)
    raise RuntimeError("agent did not come up (see: journalctl --user -u izenpe-tv-agent)")


def schedule_reminder(expires_at: float) -> None:
    delay = int(expires_at - time.time() - REMIND_BEFORE_S)
    if delay <= 0 or not shutil.which("notify-send"):
        return
    until = dt.datetime.fromtimestamp(expires_at).strftime("%H:%M")
    subprocess.run(["systemctl", "--user", "stop", "izenpelogin-reminder.timer"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(
        ["systemd-run", "--user", "--unit=izenpelogin-reminder", "--collect",
         f"--on-active={delay}s", shutil.which("notify-send"), "-a", APP_NAME,
         "-u", "critical", "-i", _icon() or "security-high",
         "Izenpe saioa iraungitzear",
         f"Txartel birtuala {until}etan desaktibatuko da. Ireki izenpelogin berriz."],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"reminder scheduled in {delay}s")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="izenpelogin")
    p.add_argument("--env", default="profesional", choices=list(config.ENVIRONMENTS))
    p.add_argument("--locale", default="eu", choices=["eu", "es"])
    args = p.parse_args(argv)

    log(f"=== izenpelogin start (env={args.env}) ===")
    try:
        config.load_client_credentials()
        if not config.credentials_present():
            raise RuntimeError("OAuth client not configured (~/.config/izenpe-tv/client.toml)")
        env = config.ENVIRONMENTS[args.env]

        ensure_agent(args.env)

        log("opening login window")
        token = login.login_webview(env, ui_locales=args.locale)

        client = api.ApiClient(env, token.access_token)
        certs = []
        for ident in client.list_identities():
            if args.env.startswith("profesional") and not ident.is_profesional:
                continue
            certs.append(ident.id)
        if not certs:
            raise RuntimeError("logged in, but no certificate found for this profile")

        until = dt.datetime.fromtimestamp(token.expires_at).strftime("%H:%M")
        log(f"ready: {len(certs)} certificate(s), active until {until}")
        notify("Izenpe txartel birtuala prest",
               f"Ziurtagiri profesionala aktibo {until} arte.\n"
               "Firefox, AutoFirma eta Idazki-n erabil dezakezu.")
        schedule_reminder(token.expires_at)
        return 0
    except oauth.OAuthError as e:
        log(f"login failed: {e}")
        notify("Izenpe: saioa ez da hasi", str(e)[:200], urgency="critical")
        return 1
    except Exception as e:  # noqa: BLE001
        log("error: " + "".join(traceback.format_exception(e)))
        notify("Izenpe: errorea", f"{e}"[:200] + f"\nXehetasunak: {_log_path()}",
               urgency="critical")
        return 2


if __name__ == "__main__":
    sys.exit(main())
