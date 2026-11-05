"""Embedded-WebView login using Qt WebEngine (Chromium).

This mirrors the official client: it opens the OAuth authorize page inside an embedded
browser with a *clean* (off-the-record) session and intercepts the redirect to
oauth-swift://oauth-callback?code=... from inside the engine — which a normal external
browser cannot follow (it lands on the server's welcome.xhtml / error.xhtml instead).

Requires PyQt6 + PyQt6-WebEngine (optional dependency group `webview`).
"""
from __future__ import annotations

import sys

from . import config, oauth
from .config import Environment


def available() -> bool:
    try:
        import PyQt6.QtWebEngineCore  # noqa: F401
        return True
    except Exception:
        return False


def webview_login(env: Environment, *, ui_locales: str = "eu",
                  login_hint: str | None = None, timeout: float = 300.0,
                  debug: bool = True) -> tuple[str, str]:
    """Open the login window; return (redirect_url, state). Raises on cancel/timeout."""
    from PyQt6.QtCore import QUrl, QTimer
    from PyQt6.QtWebEngineCore import (
        QWebEnginePage, QWebEngineProfile, QWebEngineUrlScheme,
        QWebEngineUrlSchemeHandler,
    )
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWidgets import QApplication

    url, state = oauth.build_authorize_url(env, ui_locales=ui_locales, login_hint=login_hint)

    # The custom scheme must be registered before the QApplication is created.
    scheme_name = b"oauth-swift"
    if not QApplication.instance():
        s = QWebEngineUrlScheme(scheme_name)
        s.setFlags(QWebEngineUrlScheme.Flag.SecureScheme
                   | QWebEngineUrlScheme.Flag.LocalScheme
                   | QWebEngineUrlScheme.Flag.LocalAccessAllowed)
        QWebEngineUrlScheme.registerScheme(s)

    app = QApplication.instance() or QApplication(sys.argv)

    captured: dict[str, str] = {}

    class CallbackHandler(QWebEngineUrlSchemeHandler):
        def requestStarted(self, job):
            u = job.requestUrl().toString()
            if debug:
                print(f"[webview] callback scheme hit: {u}")
            captured["url"] = u
            app.quit()

    handler = CallbackHandler()
    profile = QWebEngineProfile()  # off-the-record: no stale cookies
    profile.installUrlSchemeHandler(scheme_name, handler)

    class Page(QWebEnginePage):
        def __init__(self):
            super().__init__(profile, None)

        def acceptNavigationRequest(self, qurl, nav_type, is_main_frame):
            s = qurl.toString()
            if debug:
                print(f"[webview] navigate: {s}")
            if s.startswith("oauth-swift://"):
                captured["url"] = s
                app.quit()
                return False
            return super().acceptNavigationRequest(qurl, nav_type, is_main_frame)

    view = QWebEngineView()
    page = Page()
    view.setPage(page)
    view.setWindowTitle("Izenpe Tarjeta Virtual - Autentifikazioa")
    view.resize(520, 720)
    page.load(QUrl(url))
    view.show()

    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(app.quit)
    timer.start(int(timeout * 1000))

    app.exec()

    redirect = captured.get("url")
    if not redirect:
        raise oauth.OAuthError("login window closed before completing authentication")
    return redirect, state
