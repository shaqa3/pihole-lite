# DNS Server — terminal cheatsheet

Everything below assumes you're in the project directory. The **dev port is
`15353`** (no root needed); swap in `53` once you trust it.

---

## Start the server

```bash
# Recursive-from-root + ad-blocking + dashboard (dev port, no sudo)
python3 -m dns_server.main --port 15353 --web-port 8080 --blocklist blocklists/sample.txt

# Forwarding mode instead (let 1.1.1.1 do the recursion; faster to start)
python3 -m dns_server.main --port 15353 --web-port 8080 \
    --mode forward --upstream 1.1.1.1 --blocklist blocklists/sample.txt

# Block with NXDOMAIN instead of a 0.0.0.0 sinkhole
python3 -m dns_server.main --port 15353 --block-mode nxdomain --blocklist blocklists/sample.txt

# For real, on port 53 (privileged → needs sudo), reachable on your LAN
sudo python3 -m dns_server.main --host 0.0.0.0 --port 53 --web-port 8080 \
    --blocklist blocklists/sample.txt

# See all options
python3 -m dns_server.main --help
```

## Generate traffic for the dashboard

```bash
./demo-traffic.sh                 # steady stream → 127.0.0.1:15353
./demo-traffic.sh 53              # target port 53
DELAY=0.2 ./demo-traffic.sh       # go faster
```

## Query it with `dig`

```bash
dig @127.0.0.1 -p 15353 example.com               # basic A lookup
dig @127.0.0.1 -p 15353 example.com +short        # just the IP(s)
dig @127.0.0.1 -p 15353 cloudflare.com AAAA       # IPv6
dig @127.0.0.1 -p 15353 gmail.com MX              # mail servers
dig @127.0.0.1 -p 15353 github.com TXT            # text records
dig @127.0.0.1 -p 15353 +tcp example.com          # force TCP
dig @127.0.0.1 -p 15353 doubleclick.net           # a blocked domain → 0.0.0.0
dig @127.0.0.1 -p 15353 no-such-name-12345.example  # → NXDOMAIN

# Prove caching: run twice; the 2nd has a lower TTL and returns instantly
dig @127.0.0.1 -p 15353 example.com | grep -E 'IN\s+A'
```

Handy `dig` flags: `+short` (answers only), `+noall +answer` (clean answer
section), `+stats` (timing), `+tries=1 +time=2` (fail fast).

## Watch it work

```bash
open http://127.0.0.1:8080                         # the live dashboard (macOS)

curl -s http://127.0.0.1:8080/api/stats | python3 -m json.tool   # JSON snapshot
curl -N  http://127.0.0.1:8080/events              # raw live event stream (SSE)
```

## Regenerate the dashboard screenshot

```bash
python -m pip install -r requirements-dev.txt   # playwright
playwright install chromium                     # one-time browser download
python scripts/screenshot.py                    # boots server, drives traffic → docs/dashboard.png
python scripts/screenshot.py --url http://127.0.0.1:8080 --no-server   # shoot a running instance
```

## Run the tests

```bash
pytest -q                                          # if pytest is installed

# Zero-dependency runner (no pytest needed):
python3 -c "import sys; sys.path.insert(0,'.'); \
import tests.test_wire as w, tests.test_cache_blocklist as c; \
[getattr(m,n)() for m in (w,c) for n in dir(m) if n.startswith('test_')]; \
print('all tests passed')"
```

## Docker

```bash
docker compose up --build                          # DNS :53 + dashboard :8080
docker compose up -d                               # detached
docker compose logs -f                             # follow logs
docker compose down                                # stop
```

## Point a machine at it (do ONE machine first!)

```bash
# ── macOS ──────────────────────────────────────────────────────────
networksetup -listallnetworkservices               # find your service name
networksetup -setdnsservers "Wi-Fi" 127.0.0.1      # use this resolver
networksetup -setdnsservers "Wi-Fi" empty          # revert to DHCP/default
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder   # flush DNS cache

# ── Linux (systemd-resolved / resolv.conf) ─────────────────────────
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
resolvectl flush-caches                            # flush cache
```

> Pointing a machine at `127.0.0.1` only works if the server binds a reachable
> address. For other devices on your LAN, run with `--host 0.0.0.0 --port 53`
> and point them at **this host's LAN IP** (e.g. `192.168.1.x`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Address already in use` on **:5353** | macOS mDNSResponder owns 5353 — use another port (we default to 15353). |
| `Permission denied` binding **:53** | Ports < 1024 need root: prefix with `sudo`. |
| `dig` times out | Is the server running? Check the port matches `-p`. |
| Changes to blocklist ignored | Blocked answers have a short TTL (60s); flush your OS DNS cache. |
| Browser still shows ads | DNS blocking can't stop first-party ads or filter inside HTTPS — that's expected. |
| Stuck stale answer | Restart the server (the cache is in-memory) or wait out the TTL. |

## What each layer is doing (quick map)

```
your query ──▶ BlockingResolver ──▶ RecursiveResolver ──▶ Cache
               (ads die here)        (root→TLD→auth)      (TTL countdown)
                     │                     │                  │
                     └───────── every query → Stats → dashboard (SSE)
```
