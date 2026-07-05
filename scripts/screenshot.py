#!/usr/bin/env python3
"""
Capture a real screenshot of the live dashboard with headless Chromium.

Self-contained: it boots the DNS + web server, sends a realistic burst of
queries so the dashboard has data, loads the page in Playwright, waits for the
live feed to populate, and writes a PNG.

    # one-time setup
    python -m pip install playwright        # or: pip install -r requirements-dev.txt
    playwright install chromium

    # capture (starts its own server on dev ports, cleans up after)
    python scripts/screenshot.py                       # → docs/dashboard.png

    # or screenshot a server you already have running
    python scripts/screenshot.py --url http://127.0.0.1:8053 --no-server

Options: --out, --web-port, --dns-port, --host, --width, --scale, --seconds.
"""
from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# A realistic browsing mix: popular sites (some repeated → cache hits), a few
# AAAA/MX, and ad/tracker domains that will be blocked.
TRAFFIC = [
    ("google.com", "A"), ("www.google.com", "A"), ("github.com", "A"),
    ("doubleclick.net", "A"), ("wikipedia.org", "A"), ("google-analytics.com", "A"),
    ("cloudflare.com", "AAAA"), ("reddit.com", "A"), ("github.com", "A"),
    ("googlesyndication.com", "A"), ("stackoverflow.com", "A"), ("amazon.com", "A"),
    ("tracker.doubleclick.net", "A"), ("netflix.com", "A"), ("apple.com", "A"),
    ("google.com", "A"), ("scorecardresearch.com", "A"), ("mozilla.org", "A"),
    ("gmail.com", "MX"), ("python.org", "A"), ("adservice.google.com", "A"),
    ("news.ycombinator.com", "A"), ("wikipedia.org", "A"), ("ads.example.com", "A"),
    ("cloudflare.com", "AAAA"), ("bbc.co.uk", "A"), ("nytimes.com", "A"),
    ("doubleclick.net", "A"), ("spotify.com", "A"), ("openai.com", "A"),
    ("wikipedia.org", "A"), ("github.com", "A"), ("reddit.com", "A"),
]


def wait_for_http(url: str, timeout: float = 15.0) -> None:
    """Poll until the web server answers, so we don't screenshot a blank page."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"web server never came up at {url}")


def send_traffic(host: str, port: int) -> None:
    """Drive real queries straight at the resolver over UDP (no dig needed)."""
    from dns_server.records import RecordType
    from dns_server.wire import Message

    for i, (name, qtype) in enumerate(TRAFFIC):
        q = Message.make_query(name, RecordType[qtype], id=i & 0xFFFF).to_bytes()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        try:
            s.sendto(q, (host, port))
            s.recvfrom(4096)
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.05)


def capture(url: str, out: Path, width: int, height: int, scale: int) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(
            viewport={"width": width, "height": height},
            device_scale_factor=scale,  # 2 = retina-crisp
        )
        # NOT "networkidle": the dashboard holds an SSE connection open forever,
        # so the network is never idle. Wait for the DOM, then for real rows.
        page.goto(url, wait_until="domcontentloaded")
        # Wait until the live log actually has rows (the SSE feed populated it).
        page.wait_for_function("document.querySelectorAll('#log tr').length > 5", timeout=10_000)
        time.sleep(2.5)  # let a few more live events stream in and animations settle
        # A viewport-clipped "hero" frame (not full_page): the right-hand
        # top-lists are much taller than the capped query log, so a full-page
        # shot would leave a big empty gap below the log. This crops to a clean
        # above-the-fold view.
        page.screenshot(path=str(out))
        browser.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Screenshot the live dashboard.")
    ap.add_argument("--out", default=str(ROOT / "docs" / "dashboard.png"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--web-port", type=int, default=18080)
    ap.add_argument("--dns-port", type=int, default=15353)
    ap.add_argument("--url", default=None, help="screenshot this URL instead of starting a server")
    ap.add_argument("--no-server", action="store_true", help="assume a server is already running")
    ap.add_argument("--width", type=int, default=1240)
    ap.add_argument("--height", type=int, default=920, help="viewport/frame height")
    ap.add_argument("--scale", type=int, default=2)
    ap.add_argument("--seconds", type=float, default=0.0, help="extra time to keep streaming before capture")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    url = args.url or f"http://{args.host}:{args.web_port}"

    proc = None
    try:
        if not args.no_server:
            print(f"▶ starting server (dns :{args.dns_port}, web :{args.web_port})")
            proc = subprocess.Popen(
                [sys.executable, "-m", "dns_server.main",
                 "--host", args.host, "--port", str(args.dns_port),
                 "--web-port", str(args.web_port),
                 "--blocklist", "blocklists/sample.txt", "--log", "warning"],
                cwd=str(ROOT),
            )
            wait_for_http(f"{url}/api/stats")
            print("▶ sending demo traffic")
            send_traffic(args.host, args.dns_port)

        if args.seconds:
            time.sleep(args.seconds)

        print(f"▶ capturing {url} → {out}")
        capture(url, out, args.width, args.height, args.scale)
        print(f"✔ wrote {out}")
        return 0
    except ModuleNotFoundError:
        print("error: Playwright isn't installed.\n"
              "  python -m pip install playwright && playwright install chromium", file=sys.stderr)
        return 1
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
