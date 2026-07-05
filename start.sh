#!/usr/bin/env bash
# Start the DNS server + live dashboard and open it in the browser.
#
# Usage:  ./start.sh                 # dashboard :8053, DNS :15353 (dev ports)
#         WEB_PORT=9000 ./start.sh   # override the dashboard port
#         DNS_PORT=53 ./start.sh     # DNS on :53 (needs sudo)
#         DEMO=1 ./start.sh          # also stream demo traffic so it's lively
#         MODE=forward ./start.sh    # forward to an upstream instead of recursing
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

HOST="${HOST:-127.0.0.1}"
WEB_PORT="${WEB_PORT:-8053}"
DNS_PORT="${DNS_PORT:-15353}"
MODE="${MODE:-recursive}"
BLOCKLIST="${BLOCKLIST:-blocklists/sample.txt}"
URL="http://${HOST}:${WEB_PORT}"

open_browser() {
  if command -v open >/dev/null 2>&1; then open "$URL"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
  else echo "Open this URL manually: $URL"; fi
}

# Is the port already taken? If it's OUR server, just open it. If it's some
# other app, bail with a clear message rather than fighting over the port.
holder="$(lsof -ti "tcp:${WEB_PORT}" -sTCP:LISTEN 2>/dev/null | head -1 || true)"
if [ -n "$holder" ]; then
  if ps -p "$holder" -o command= 2>/dev/null | grep -q 'dns_server\.main'; then
    echo "Dashboard already running — opening ${URL}"
    open_browser
    exit 0
  fi
  cmd="$(ps -p "$holder" -o comm= 2>/dev/null || echo unknown)"
  echo "Port ${WEB_PORT} is in use by another app (pid ${holder}: ${cmd})." >&2
  echo "Pick a free port, e.g.:  WEB_PORT=8899 ./start.sh" >&2
  exit 1
fi

echo "Starting DNS server (dns :${DNS_PORT}, dashboard :${WEB_PORT}, mode=${MODE})"
python3 -m dns_server.main \
  --host "$HOST" --port "$DNS_PORT" --web-port "$WEB_PORT" \
  --mode "$MODE" --blocklist "$BLOCKLIST" &
SERVER_PID=$!

DEMO_PID=""
cleanup() {
  [ -n "$DEMO_PID" ] && kill "$DEMO_PID" 2>/dev/null || true
  kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for the dashboard to answer before opening it.
for _ in $(seq 1 50); do
  if curl -sS -o /dev/null "${URL}/api/stats" 2>/dev/null; then break; fi
  # Bail early if the server died (e.g. port 53 without sudo).
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "Server exited early — check the output above." >&2; exit 1; }
  sleep 0.1
done

# Optionally stream demo traffic so the live dashboard has something to show.
if [ "${DEMO:-0}" = "1" ]; then
  echo "Streaming demo traffic (DEMO=1)…"
  ./demo-traffic.sh "$DNS_PORT" "$HOST" >/dev/null 2>&1 &
  DEMO_PID=$!
fi

echo "Dashboard → ${URL}"
open_browser
echo "Press Ctrl+C to stop."
wait "$SERVER_PID"
