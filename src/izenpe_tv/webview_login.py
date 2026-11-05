"""Embedded-WebView login using Qt WebEngine (Chromium).

This mirrors the official client: it opens the OAuth authorize page inside an embedded
browser with a *clean* (off-the-record) session and intercepts the redirect to
oauth-swift://oauth-callback?code=... from inside the engine — which a normal external
browser cannot follow (it lands on the server's welcome.xhtml / error.xhtml instead).

Requires PyQt6 + PyQt6-WebEngine (optional dependency group `webview`).
"""
from __future__ import annotations

import os
import sys
import time

from . import config, oauth
from .config import Environment


def _debug_log_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    d = os.path.join(base, "izenpe-tv")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "login-debug.log")


def _log(msg: str) -> None:
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line)
    try:
        with open(_debug_log_path(), "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def available() -> bool:
    try:
        import PyQt6.QtWebEngineCore  # noqa: F401
        return True
    except Exception:
        return False


def webview_login(env: Environment, *, ui_locales: str = "eu",
                  login_hint: str | None = None, timeout: float = 300.0,
                  debug: bool = True, client_id: str | None = None,
                  app_params: dict | None = None) -> tuple[str, str]:
    """Open the login window; return (redirect_url, state). Raises on cancel/timeout."""
    from PyQt6.QtCore import QUrl, QTimer
    from PyQt6.QtWebEngineCore import (
        QWebEngineLoadingInfo, QWebEnginePage, QWebEngineProfile,
        QWebEngineUrlRequestInterceptor, QWebEngineUrlScheme, QWebEngineUrlSchemeHandler,
    )
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWidgets import QApplication

    url, state = oauth.build_authorize_url(env, ui_locales=ui_locales, login_hint=login_hint,
                                           client_id=client_id, app_params=app_params)
    _log(f"[webview] debug log: {_debug_log_path()}")
    _log(f"[webview] authorize URL: {url}")

    # The custom scheme must be registered before the QApplication is created.
    scheme_name = b"oauth-swift"
    if not QApplication.instance():
        s = QWebEngineUrlScheme(scheme_name)
        # NOT LocalScheme: Chromium refuses https -> local-scheme redirects with
        # net::ERR_UNSAFE_REDIRECT, which is exactly the final OAuth hop.
        s.setFlags(QWebEngineUrlScheme.Flag.SecureScheme)
        QWebEngineUrlScheme.registerScheme(s)

    app = QApplication.instance() or QApplication(sys.argv)

    captured: dict[str, str] = {}

    def capture(u: str, how: str) -> None:
        if "url" not in captured and u.startswith("oauth-swift://"):
            _log(f"[webview] captured callback via {how}")
            captured["url"] = u
            QTimer.singleShot(0, app.quit)

    class Interceptor(QWebEngineUrlRequestInterceptor):
        # sees every request, including the hop a server 302 points at
        def interceptRequest(self, info):
            u = info.requestUrl().toString()
            if u.startswith("oauth-swift://"):
                info.block(True)
                capture(u, "request interceptor")

    class CallbackHandler(QWebEngineUrlSchemeHandler):
        def requestStarted(self, job):
            u = job.requestUrl().toString()
            _log("[webview] callback scheme hit")
            capture(u, "scheme handler")

    handler = CallbackHandler()
    profile = QWebEngineProfile()  # off-the-record: no stale cookies
    profile.installUrlSchemeHandler(scheme_name, handler)
    interceptor = Interceptor()
    profile.setUrlRequestInterceptor(interceptor)

    class Page(QWebEnginePage):
        def __init__(self):
            super().__init__(profile, None)

        def acceptNavigationRequest(self, qurl, nav_type, is_main_frame):
            s = qurl.toString()
            _log(f"[webview] navigate ({'main' if is_main_frame else 'sub'}): {s}")
            if s.startswith("oauth-swift://"):
                capture(s, "navigation request")
                return False
            return super().acceptNavigationRequest(qurl, nav_type, is_main_frame)

    view = QWebEngineView()
    page = Page()
    view.setPage(page)
    page.urlChanged.connect(lambda q: _log(f"[webview] urlChanged: {q.toString()}"))

    def on_load_finished(ok):
        u = page.url().toString()
        _log(f"[webview] loadFinished ok={ok} url={u} title={page.title()!r}")
        if "error" in u.lower() or "error" in (page.title() or "").lower():
            def dump(html):
                import re
                text = re.sub(r"<[^>]+>", " ", html)
                text = re.sub(r"\s+", " ", text).strip()
                _log(f"[webview] ERROR PAGE TEXT: {text[:1500]}")
            page.toHtml(dump)

    page.loadFinished.connect(on_load_finished)

    def on_loading_changed(info):
        st = info.status()
        if st == QWebEngineLoadingInfo.LoadStatus.LoadFailedStatus:
            _log(f"[webview] load failed: url={info.url().toString()} "
                 f"error={info.errorCode()} {info.errorString()!r}")
            try:  # Qt >= 6.6 exposes the response headers of the failed load
                hdrs = info.responseHeaders()
                for k, v in hdrs.items():
                    key = bytes(k).decode(errors="replace")
                    if key.lower() == "location":
                        capture(bytes(v).decode(errors="replace"), "Location header")
            except Exception:
                pass

    page.loadingChanged.connect(on_loading_changed)
    view.setWindowTitle("Izenpe Tarjeta Virtual - Autentifikazioa")
    view.resize(520, 720)
    page.load(QUrl(url))
    view.show()

    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(app.quit)
    timer.start(int(timeout * 1000))

    app.exec()

    # Tear down page before its profile (otherwise QtWebEngine may crash on exit).
    timer.stop()
    view.hide()
    try:
        from PyQt6 import sip
        sip.delete(view)
        sip.delete(page)
        sip.delete(profile)
    except Exception:
        pass

    redirect = captured.get("url")
    if not redirect:
        raise oauth.OAuthError("login window closed before completing authentication")
    return redirect, state
