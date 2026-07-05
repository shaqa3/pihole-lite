#!/usr/bin/env bash
# Stop the DNS server + dashboard by freeing its ports.
#
# Usage:  ./stop.sh                 # frees dashboard :8080 and DNS :15353
#         WEB_PORT=9000 DNS_PORT=53 ./stop.sh
set -euo pipefail

WEB_PORT="${WEB_PORT:-8080}"
DNS_PORT="${DNS_PORT:-15353}"

free_port() {
  local port="$1" label="$2"
  local pids
  # Only the LISTENer (our server) — not client connections like an open
  # browser tab that also shows up on the port.
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  # DNS also listens on UDP; catch that too.
  pids="${pids} $(lsof -ti "udp:${port}" 2>/dev/null || true)"
  pids="$(echo "$pids" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u || true)"

  if [ -z "$pids" ]; then
    echo "Nothing listening on ${label} port ${port}."
    return 0
  fi
  echo "Stopping ${label} on port ${port}: $(echo "$pids" | tr '\n' ' ')"
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null || true
  sleep 0.3
  # Force-kill any survivors.
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
  fi
}

free_port "$WEB_PORT" "dashboard"
free_port "$DNS_PORT" "DNS"
echo "Stopped."
