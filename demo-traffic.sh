#!/usr/bin/env bash
#
# demo-traffic.sh — a steady stream of realistic DNS lookups against your
# resolver, so the live dashboard always has something to show.
#
# Usage:
#   ./demo-traffic.sh                 # default: 127.0.0.1 port 15353
#   ./demo-traffic.sh 5353            # custom port
#   ./demo-traffic.sh 53 192.168.1.10 # custom port + host
#   DELAY=0.2 ./demo-traffic.sh       # faster (default DELAY=0.7s)
#
# Ctrl-C to stop. Popular sites repeat (→ cache hits) and ad/tracker domains
# get blocked, so you see all three result types stream by.

set -u
PORT="${1:-15353}"
HOST="${2:-127.0.0.1}"
DELAY="${DELAY:-0.7}"

# Popular destinations — repeats here become cache hits on the 2nd+ lookup.
SITES=(
  google.com www.google.com github.com www.github.com wikipedia.org
  en.wikipedia.org cloudflare.com reddit.com stackoverflow.com amazon.com
  netflix.com apple.com mozilla.org python.org news.ycombinator.com
  spotify.com openai.com nytimes.com bbc.co.uk example.com
)
# Ad/tracker domains — these get blocked if they're on your blocklist.
ADS=(
  doubleclick.net tracker.doubleclick.net google-analytics.com
  googlesyndication.com scorecardresearch.com adservice.google.com
  ads.example.com
)
# Occasionally ask for non-A record types to exercise the parser.
TYPES=(A A A A A AAAA MX)

if ! command -v dig >/dev/null 2>&1; then
  echo "error: 'dig' not found. Install bind-tools / dnsutils." >&2
  exit 1
fi

echo "▶ sending demo traffic to ${HOST}:${PORT}  (Ctrl-C to stop)"
echo "  dashboard → http://${HOST%:*}:8080"
echo

pick() { local arr=("$@"); echo "${arr[$((RANDOM % ${#arr[@]}))]}"; }

while true; do
  # ~1 in 4 queries targets an ad/tracker domain.
  if (( RANDOM % 4 == 0 )); then
    name="$(pick "${ADS[@]}")"; type="A"
  else
    name="$(pick "${SITES[@]}")"; type="$(pick "${TYPES[@]}")"
  fi

  answer="$(dig @"$HOST" -p "$PORT" "$name" "$type" +short +tries=1 +time=2 2>/dev/null | head -1)"
  if [ "$answer" = "0.0.0.0" ] || [ "$answer" = "::" ]; then
    answer="$answer  ⛔ blocked"
  elif [ -z "$answer" ]; then
    answer="(no records)"          # e.g. a name with no AAAA/MX — NODATA, not blocked
  fi
  printf '  %-28s %-4s → %s\n' "$name" "$type" "$answer"

  sleep "$DELAY"
done
