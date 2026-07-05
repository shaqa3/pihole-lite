"""
The composition root: wire every layer together and run the whole thing.

    python -m dns_server.main --port 15353 --web-port 8080 \
        --blocklist blocklists/sample.txt --mode recursive

Resolver stack (outermost first — the order a query flows through):

    BlockingResolver         ← ad/tracker names die here, before any network I/O
      └─ RecursiveResolver   ← walks root→TLD→authoritative (or ForwardingResolver)
           └─ Cache          ← shared; consulted at every hop

The DNS server and the dashboard's web server share one asyncio event loop, so a
recursion in flight and a dashboard render never block each other.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .blocklist import Blocklist, BlockingResolver
from .cache import Cache
from .resolver import CachingResolver, ForwardingResolver, RecursiveResolver
from .server import DNSServer
from .stats import Stats
from .webserver import WebServer

STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"


def build_resolver(mode: str, cache: Cache, blocklist: Blocklist, block_mode: str, upstreams):
    if mode == "forward":
        inner = CachingResolver(ForwardingResolver(upstreams=upstreams), cache)
    else:  # "recursive"
        inner = RecursiveResolver(cache)  # self-caching via the shared cache
    return BlockingResolver(inner, blocklist, mode=block_mode)


async def run(args):
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    log = logging.getLogger("dns.main")

    # Shared state.
    cache = Cache()
    blocklist = Blocklist()
    for path in args.blocklist:
        added = blocklist.load_text(Path(path).read_text())
        log.info("loaded %d domains from %s", added, path)

    stats = Stats()
    stats.cache = cache  # let the dashboard report live cache hit-rate

    resolver = build_resolver(args.mode, cache, blocklist, args.block_mode, args.upstream)

    dns = DNSServer(resolver, host=args.host, port=args.port, on_event=stats.on_event)
    web = WebServer(stats, STATIC_DIR, host=args.host, port=args.web_port)

    log.info("DNS  %s:%d  (mode=%s, block=%s, blocked-domains=%d)",
             args.host, args.port, args.mode, args.block_mode, len(blocklist))
    log.info("Dashboard  http://%s:%d", args.host, args.web_port)

    # Run both servers concurrently, forever.
    await asyncio.gather(dns.serve_forever(), web.serve_forever())


def main():
    p = argparse.ArgumentParser(description="A from-scratch DNS server + ad-blocker.")
    p.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 for LAN/Docker)")
    p.add_argument("--port", type=int, default=15353, help="DNS port (53 needs root)")
    p.add_argument("--web-port", type=int, default=8080, help="dashboard HTTP port")
    p.add_argument("--mode", choices=["recursive", "forward"], default="recursive",
                   help="recursive-from-root, or forward to an upstream resolver")
    p.add_argument("--upstream", action="append", default=None,
                   help="upstream resolver IP for --mode forward (repeatable)")
    p.add_argument("--blocklist", action="append", default=[],
                   help="path to a blocklist file (repeatable)")
    p.add_argument("--block-mode", choices=["sinkhole", "nxdomain"], default="sinkhole",
                   help="how to answer blocked names")
    p.add_argument("--log", default="info", help="log level")
    args = p.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
