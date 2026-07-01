#!/usr/bin/env python3
"""Entrypoint: launch the E2EE messenger web-based GUI client (React
frontend running inside a native window via pywebview, talking to
client/api.py over the JS bridge).

Usage:
    python main_client_web.py            # loads the built frontend/dist
    python main_client_web.py --dev      # loads the Vite dev server (hot reload)
"""
from __future__ import annotations

import argparse
import os

import webview

from client.api import Api

FRONTEND_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "dist", "index.html")
DEV_SERVER_URL = "http://localhost:5173"


def main() -> None:
    parser = argparse.ArgumentParser(description="E2EE messenger (web UI)")
    parser.add_argument("--dev", action="store_true", help="load the Vite dev server instead of the built frontend")
    args = parser.parse_args()

    if args.dev:
        url = DEV_SERVER_URL
    else:
        if not os.path.exists(FRONTEND_DIST):
            raise SystemExit(
                f"Built frontend not found at {FRONTEND_DIST}.\n"
                "Run `cd frontend && npm install && npm run build` first, "
                "or use --dev with `npm run dev` running."
            )
        url = FRONTEND_DIST

    api = Api()
    window = webview.create_window("Messages", url, js_api=api, width=1000, height=680, min_size=(760, 480))
    api.window = window

    def on_closed() -> None:
        api.close()

    window.events.closed += on_closed

    webview.start()


if __name__ == "__main__":
    main()
