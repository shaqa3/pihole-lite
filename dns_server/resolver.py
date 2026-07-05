"""
Resolvers — the strategies for turning a question into an answer.

We build these as composable layers, each implementing the same `handle` method
the server expects:

    CachingResolver ── wraps ──▶ ForwardingResolver ──▶ upstream (1.1.1.1)
                                 RecursiveResolver   ──▶ the root servers (M3)

The CachingResolver doesn't care *how* the thing it wraps resolves — it just
checks the cache first and stores what comes back. That's the payoff of giving
every layer the same interface.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Optional

from .cache import Cache
from .records import RecordClass, RecordType, ResponseCode
from .roots import ROOT_HINT_IPS
from .server import Handled
from .wire import AData, Message, Record

log = logging.getLogger("dns.resolver")


# ─────────────────────────────────────────────────────────────────────────────
# Low-level: ask another DNS server a question, over UDP with TCP fallback.
# ─────────────────────────────────────────────────────────────────────────────
async def udp_query(ip: str, port: int, data: bytes, timeout: float) -> bytes:
    """Send one datagram, await one reply. Connected UDP so we only hear back
    from the server we asked (the kernel drops packets from other sources)."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (ip, port))
        await loop.sock_sendall(sock, data)
        return await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout)
    finally:
        sock.close()


async def tcp_query(ip: str, port: int, data: bytes, timeout: float) -> bytes:
    """DNS over TCP: each message is framed with a 2-byte big-endian length."""
    async def _do():
        reader, writer = await asyncio.open_connection(ip, port)
        try:
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()
            length = int.from_bytes(await reader.readexactly(2), "big")
            return await reader.readexactly(length)
        finally:
            writer.close()
    return await asyncio.wait_for(_do(), timeout)


async def ask(ip: str, query: Message, *, port: int = 53, timeout: float = 3.0) -> Message:
    """
    Ask `ip` our `query` and return the parsed response. Automatically retries
    over TCP if the UDP answer comes back truncated (TC flag) — the exact
    UDP→TCP fallback the DNS spec mandates for large responses.
    """
    wire = query.to_bytes()
    raw = await udp_query(ip, port, wire, timeout)
    response = Message.parse(raw)
    if response.header.tc:
        raw = await tcp_query(ip, port, wire, timeout)
        response = Message.parse(raw)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Forwarding resolver: delegate the hard work to a trusted upstream resolver.
# This is the "fine MVP" — 1.1.1.1 does the recursion; we add caching + blocking.
# ─────────────────────────────────────────────────────────────────────────────
class ForwardingResolver:
    def __init__(self, upstreams: Optional[list[str]] = None, timeout: float = 3.0):
        # Cloudflare and Google — try them in order until one answers.
        self.upstreams = upstreams or ["1.1.1.1", "8.8.8.8"]
        self.timeout = timeout

    async def handle(self, query: Message, client_ip: str) -> Handled:
        if not query.questions:
            return Handled(query.make_response(ResponseCode.FORMERR), note="no question")
        q = query.questions[0]

        # Forward a clean single-question query (fresh id keeps upstreams happy).
        upstream_query = Message.make_query(q.name, q.qtype, id=query.header.id, rd=True)

        last_error: Optional[Exception] = None
        for ip in self.upstreams:
            try:
                resp = await ask(ip, upstream_query, timeout=self.timeout)
            except Exception as e:  # timeout, connection refused, parse error...
                last_error = e
                continue
            # Re-stamp the response with the client's original id + question and
            # return it as our own answer.
            resp.header.id = query.header.id
            resp.questions = list(query.questions)
            resp.header.ra = True
            return Handled(resp, upstream=ip, note="forwarded")

        # Every upstream failed → SERVFAIL.
        return Handled(
            query.make_response(ResponseCode.SERVFAIL),
            note=f"all upstreams failed: {last_error!r}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Caching resolver: a transparent cache in front of any other resolver.
# ─────────────────────────────────────────────────────────────────────────────
class CachingResolver:
    def __init__(self, inner, cache: Optional[Cache] = None):
        self.inner = inner
        self.cache = cache or Cache()

    async def handle(self, query: Message, client_ip: str) -> Handled:
        if not query.questions:
            return await self.inner.handle(query, client_ip)
        q = query.questions[0]

        # 1. Cache lookup — the fast path.
        hit = self.cache.get(q.name, int(q.qtype), int(q.qclass))
        if hit is not None:
            response = query.make_response(hit.rcode)
            response.answers = hit.answers
            response.authorities = hit.authorities
            return Handled(response, cache_hit=True, note="cache hit")

        # 2. Miss → delegate to the wrapped resolver.
        handled = await self.inner.handle(query, client_ip)

        # 3. Store cacheable results (positive NOERROR w/ answers, or NXDOMAIN).
        resp = handled.response
        if resp.header.rcode in (ResponseCode.NOERROR, ResponseCode.NXDOMAIN):
            self.cache.put(
                q.name, int(q.qtype), int(q.qclass),
                resp.header.rcode, resp.answers, resp.authorities,
            )
        return handled


# ─────────────────────────────────────────────────────────────────────────────
# Recursive resolver: do the walk ourselves, root → TLD → authoritative.
#
# This is the "impressive core." A query for www.example.com resolves like this:
#
#   1. Ask a ROOT server. It doesn't know www.example.com, but it knows who runs
#      ".com": it returns a REFERRAL — NS records for the com TLD servers, plus
#      "glue" A records giving their IP addresses.
#   2. Ask a .com server. It doesn't know the address either, but it knows who
#      runs "example.com": another referral to example.com's authoritative NS.
#   3. Ask an example.com server. IT owns the zone, so it returns the actual
#      ANSWER (an A record), with the Authoritative Answer (AA) bit set.
#
# Along the way we handle: CNAME chains (an alias that must be re-resolved),
# glueless referrals (an NS whose own address we must go resolve first), NODATA
# vs NXDOMAIN, and loop/depth guards so a hostile zone can't spin us forever.
# ─────────────────────────────────────────────────────────────────────────────
class RecursiveResolver:
    MAX_DEPTH = 16        # nested sub-lookups (CNAME target, glueless NS, ...)
    MAX_DELEGATIONS = 32  # referral hops for a single name before we give up

    def __init__(self, cache: Optional[Cache] = None, timeout: float = 3.0):
        # The cache is consulted at EVERY hop — including internal NS-address
        # lookups — so a warm resolver rarely touches the root at all.
        self.cache = cache or Cache()
        self.timeout = timeout

    async def handle(self, query: Message, client_ip: str) -> Handled:
        if not query.questions:
            return Handled(query.make_response(ResponseCode.FORMERR), note="no question")
        q = query.questions[0]
        try:
            rcode, answers, authorities, from_cache = await self._lookup(q.name, q.qtype, 0)
        except Exception as e:  # anything unexpected → SERVFAIL, never crash
            log.warning("recursion failed for %s: %r", q.name, e)
            return Handled(query.make_response(ResponseCode.SERVFAIL), note=f"recursion error: {e!r}")

        response = query.make_response(rcode)
        response.answers = answers
        response.authorities = authorities
        return Handled(
            response,
            cache_hit=from_cache,
            upstream=None if from_cache else "root-recursion",
            note="cache hit" if from_cache else "recursed",
        )

    async def _lookup(self, qname: str, qtype: RecordType, depth: int):
        """
        Cache-aware resolve of one (name, type).
        Returns (rcode, answers, authorities, from_cache).
        """
        qname = qname.lower()
        hit = self.cache.get(qname, int(qtype), int(RecordClass.IN))
        if hit is not None:
            return hit.rcode, hit.answers, hit.authorities, True

        rcode, answers, authorities = await self._recurse(qname, qtype, depth)

        if rcode in (ResponseCode.NOERROR, ResponseCode.NXDOMAIN):
            self.cache.put(qname, int(qtype), int(RecordClass.IN), rcode, answers, authorities)
        return rcode, answers, authorities, False

    async def _recurse(self, qname: str, qtype: RecordType, depth: int):
        if depth > self.MAX_DEPTH:
            return ResponseCode.SERVFAIL, [], []

        nameservers = list(ROOT_HINT_IPS)  # start at the top of the tree

        for _ in range(self.MAX_DELEGATIONS):
            resp = await self._ask_any(nameservers, qname, qtype)
            if resp is None:
                return ResponseCode.SERVFAIL, [], []

            in_answers = [r for r in resp.answers if r.rclass == RecordClass.IN]

            # (a) A direct answer of the type we wanted → done.
            typed = [r for r in in_answers if r.rtype == qtype]
            if typed:
                return ResponseCode.NOERROR, resp.answers, resp.authorities

            # (b) A CNAME (alias). Re-resolve the target for our original type,
            #     prepending the CNAME so the client sees the full chain.
            cname = next((r for r in in_answers if r.rtype == RecordType.CNAME), None)
            if cname is not None and qtype != RecordType.CNAME:
                target = cname.rdata.target
                rc, sub_answers, sub_auth, _ = await self._lookup(target, qtype, depth + 1)
                return rc, [cname, *sub_answers], sub_auth

            # (c) The name definitively does not exist.
            if resp.header.rcode == ResponseCode.NXDOMAIN:
                return ResponseCode.NXDOMAIN, [], resp.authorities

            # (d) A referral: authority section lists the NS for a lower zone.
            ns_records = [r for r in resp.authorities if r.rtype == RecordType.NS]
            if not ns_records:
                # NOERROR but no answer and no referral = NODATA (name exists,
                # just not this type). Authority carries the SOA for neg-caching.
                return ResponseCode.NOERROR, [], resp.authorities

            next_ips = self._glue_addresses(ns_records, resp.additionals)
            if not next_ips:
                # Glueless referral: we were told the NS *names* but not their
                # addresses. Go resolve one of them ourselves, then continue.
                next_ips = await self._resolve_nameservers(ns_records, depth)
            if not next_ips:
                return ResponseCode.SERVFAIL, [], []

            nameservers = next_ips  # descend one level and loop

        return ResponseCode.SERVFAIL, [], []  # too many delegations

    async def _ask_any(self, nameservers: list[str], qname: str, qtype: RecordType) -> Optional[Message]:
        """Try each server IP in turn until one answers; None if all fail."""
        # rd=False: we are the recursive resolver; authoritative servers neither
        # want nor perform recursion — we drive the walk hop by hop.
        query = Message.make_query(qname, qtype, id=0, rd=False)
        for ip in nameservers:
            try:
                return await ask(ip, query, timeout=self.timeout)
            except Exception as e:
                log.debug("  ns %s failed for %s/%s: %r", ip, qname, qtype.name, e)
                continue
        return None

    @staticmethod
    def _glue_addresses(ns_records: list[Record], additionals: list[Record]) -> list[str]:
        """Match NS names against the A records in the additional (glue) section."""
        ns_names = {r.rdata.target.lower() for r in ns_records}
        return [
            r.rdata.address
            for r in additionals
            if r.rtype == RecordType.A and r.name.lower() in ns_names
        ]

    async def _resolve_nameservers(self, ns_records: list[Record], depth: int) -> list[str]:
        """No glue provided → recursively resolve an NS name's A record."""
        for ns in ns_records:
            name = ns.rdata.target
            rc, answers, _, _ = await self._lookup(name, RecordType.A, depth + 1)
            addrs = [r.rdata.address for r in answers
                     if r.rtype == RecordType.A and isinstance(r.rdata, AData)]
            if addrs:
                return addrs
        return []
