"""`izenpe-tv-callback` — tiny helper registered as the oauth-swift:// scheme handler.

When the browser is redirected to oauth-swift://oauth-callback?code=..., the desktop
launches this with the URL as argv[1]; it hands the URL to the waiting `izenpe-tv login`
process over a local socket.
"""
from __future__ import annotations

import os
import socket
import sys


def login_socket_path() -> str:
    run = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    if not os.path.isdir(run):
        run = os.path.expanduser("~/.cache")
    return os.environ.get("IZENPE_TV_LOGIN_SOCK", os.path.join(run, "izenpe-tv-login.sock"))


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: izenpe-tv-callback <redirect-url>", file=sys.stderr)
        return 2
    url = argv[0]
    path = login_socket_path()
    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(path)
        c.sendall(url.encode())
        c.close()
    except OSError:
        # No login waiting: show the URL so the user can paste it manually.
        print("No izenpe-tv login is waiting. Paste this URL into `izenpe-tv login`:")
        print(url)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
