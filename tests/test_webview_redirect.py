"""Offline test: the embedded WebView must capture an HTTP 302 -> oauth-swift:// redirect.

Starts a local HTTP server that mimics Izenpe's final step (/oauth/authz/flow answering
302 Location: oauth-swift://oauth-callback?code=...&state=...), points the webview login
at it and checks the code is captured. No network to Izenpe. Needs the `webview` extra.

    QT_QPA_PLATFORM=offscreen .venv/bin/python tests/test_webview_redirect.py
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from izenpe_tv import config, oauth, webview_login  # noqa: E402

STATE = "TESTSTATE123"
CODE = "TESTCODE456"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/start"):
            # first hop: ordinary 302 to another http URL (like authorize -> izenpe/...)
            self.send_response(302)
            self.send_header("Location", "/oauth/authz/flow")
            self.end_headers()
        elif self.path.startswith("/oauth/authz/flow"):
            self.send_response(302)
            self.send_header("Location",
                             f"oauth-swift://oauth-callback?code={CODE}&state={STATE}")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def main() -> int:
    if not webview_login.available():
        print("SKIP: PyQt6-WebEngine not installed")
        return 0
    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    oauth.build_authorize_url = lambda env, **k: (f"http://127.0.0.1:{port}/start", STATE)
    env = config.ENVIRONMENTS["profesional"]
    try:
        redirect, state = webview_login.webview_login(env, timeout=15.0)
    except oauth.OAuthError as e:
        print(f"FAIL: {e}")
        return 1
    finally:
        srv.shutdown()
    code = oauth.parse_redirect(redirect, expected_state=state)
    assert code == CODE, code
    print(f"PASS: captured code via redirect ({redirect})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
