#!/usr/bin/env bash
# Stop the DNS server + dashboard by freeing its ports.
#
# Usage:  ./stop.sh                 # frees dashboard :8053 and DNS :15353
#         WEB_PORT=9000 DNS_PORT=53 ./stop.sh
set -euo pipefail

WEB_PORT="${WEB_PORT:-8053}"
DNS_PORT="${DNS_PORT:-15353}"

is_our_server() {  # true only if the pid is running `python -m dns_server.main`
  ps -p "$1" -o command= 2>/dev/null | grep -q 'dns_server\.main'
}

free_port() {
  local port="$1" label="$2" pids p cmd killed=0
  # LISTENer only (not client connections like an open browser tab); + UDP.
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  pids="${pids} $(lsof -ti "udp:${port}" 2>/dev/null || true)"
  pids="$(printf '%s\n' $pids | grep -E '^[0-9]+$' | sort -u || true)"

  if [ -z "$pids" ]; then
    echo "Nothing on ${label} port ${port}."
    return 0
  fi
  for p in $pids; do
    if is_our_server "$p"; then
      echo "Stopping ${label} (pid ${p}) on port ${port}"
      kill "$p" 2>/dev/null || true
      killed=1
    else
      # NEVER kill someone else's process that merely shares the port.
      cmd="$(ps -p "$p" -o comm= 2>/dev/null || echo unknown)"
      echo "⚠ port ${port} is held by another app (pid ${p}: ${cmd}) — leaving it alone."
    fi
  done
  # Force-kill only our own survivors.
  if [ "$killed" = 1 ]; then
    sleep 0.3
    for p in $(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true); do
      is_our_server "$p" && kill -9 "$p" 2>/dev/null || true
    done
  fi
}

free_port "$WEB_PORT" "dashboard"
free_port "$DNS_PORT" "DNS"
echo "Stopped."
