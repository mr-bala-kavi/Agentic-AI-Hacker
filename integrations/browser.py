"""Browser / web-agent integration.

For indirect prompt-injection testing we host a *controlled* attacker page and
ask the target agent to fetch/summarise it. A real Playwright browser is used if
installed; otherwise we operate in "content-serving" mode where the malicious
page content is delivered to the agent via its own fetch/RAG channel. This keeps
the capability testable without a heavyweight browser dependency.
"""
from __future__ import annotations

import http.server
import socketserver
import threading
from typing import Optional

from config import get_logger

log = get_logger(__name__)

try:  # optional real browser
    from playwright.sync_api import sync_playwright  # type: ignore

    _HAS_PLAYWRIGHT = True
except Exception:
    _HAS_PLAYWRIGHT = False


class ControlledPageServer:
    """Serves a single attacker-controlled HTML page for injection testing."""

    def __init__(self, html: str, port: int = 0) -> None:
        self.html = html
        self._httpd: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port = port
        self.url = ""

    def start(self) -> str:
        html = self.html

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))

            def log_message(self, *_args):  # silence
                return

        self._httpd = socketserver.TCPServer(("127.0.0.1", self.port), Handler)
        self.port = self._httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/attacker.html"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        log.info("Controlled injection page served at %s", self.url)
        return self.url

    def stop(self) -> None:
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass


def browser_available() -> bool:
    return _HAS_PLAYWRIGHT
