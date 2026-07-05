"""
The network layer: an asyncio DNS server speaking both UDP and TCP on :53.

DNS uses BOTH transports on the same port:
  • UDP is the default — one datagram out, one back. Fast, connectionless, but
    historically capped at 512 bytes. If a response doesn't fit, the server sets
    the TC (truncated) flag and the client is expected to retry over TCP.
  • TCP is used for large responses (and zone transfers). Over TCP each DNS
    message is prefixed with a 2-byte length, because TCP is a byte stream with
    no message boundaries of its own — you need to know where one message ends.

This module knows nothing about *how* names get resolved. It just receives
bytes, parses them into a Message, hands the query to a `resolver` object, and
writes the response bytes back. That separation is what lets us swap a static
map (milestone 1) for a forwarding resolver (2), then a recursive one (3),
without touching a line of socket code.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .records import DNS_PORT, ResponseCode, UDP_MAX_LEGACY
from .wire import Message


@dataclass
class Handled:
    """
    What a resolver returns: the response message plus metadata for the
    dashboard/logging. Keeping the metadata here means the server can emit one
    clean event per query without the resolver reaching into logging itself.
    """

    response: Message
    blocked: bool = False
    cache_hit: bool = False
    upstream: Optional[str] = None
    note: str = ""


class Resolver(Protocol):
    """Anything that can turn a query Message into a Handled response."""

    async def handle(self, query: Message, client_ip: str) -> Handled: ...


class StaticResolver:
    """
    Milestone 1's resolver: answer from an in-memory table, else NXDOMAIN.

    This exists to prove the wire codec + server plumbing end-to-end before we
    add any real resolution. It's also genuinely useful later as the mechanism
    for "custom local records" (be authoritative for your own hostnames).
    """

    def __init__(self, records: dict[tuple[str, int], list]):
        # key: (lowercased name, RecordType int) -> list[Record]
        self._records = records

    async def handle(self, query: Message, client_ip: str) -> Handled:
        response = query.make_response()
        if not query.questions:
            response.header.rcode = ResponseCode.FORMERR
            return Handled(response, note="no question")

        q = query.questions[0]
        key = (q.name.lower(), int(q.qtype))
        answers = self._records.get(key)
        if answers:
            response.answers.extend(answers)
            response.header.rcode = ResponseCode.NOERROR
            return Handled(response, note="static hit")

        response.header.rcode = ResponseCode.NXDOMAIN
        return Handled(response, note="static miss")


# ─────────────────────────────────────────────────────────────────────────────
# UDP: a DatagramProtocol receives each packet as a whole message.
# ─────────────────────────────────────────────────────────────────────────────
class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: "DNSServer"):
        self._server = server
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        # Handle each query as its own task so a slow upstream doesn't stall
        # every other in-flight query.
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr):
        client_ip = addr[0]
        response = await self._server.process(data, client_ip, over_tcp=False)
        if response is not None and self.transport is not None:
            self.transport.sendto(response, addr)


# ─────────────────────────────────────────────────────────────────────────────
# The server: owns both listeners and the resolver.
# ─────────────────────────────────────────────────────────────────────────────
class DNSServer:
    def __init__(
        self,
        resolver: Resolver,
        host: str = "127.0.0.1",
        port: int = DNS_PORT,
        on_event=None,
    ):
        self.resolver = resolver
        self.host = host
        self.port = port
        # on_event(query, handled, client_ip, latency_ms) — hook for stats/logging.
        self._on_event = on_event
        self._udp_transport = None
        self._tcp_server = None

    async def process(self, data: bytes, client_ip: str, *, over_tcp: bool) -> Optional[bytes]:
        """Parse → resolve → serialise. Returns response bytes (or None)."""
        try:
            query = Message.parse(data)
        except Exception:
            # Unparseable garbage: on UDP we simply drop it (a real server may
            # try to reply FORMERR, but we can't trust anything we read).
            return None

        started = time.perf_counter()
        try:
            handled = await self.resolver.handle(query, client_ip)
        except Exception:
            # Any resolver failure becomes SERVFAIL rather than a dropped query,
            # so the client gets a definite (if unhappy) answer.
            handled = Handled(query.make_response(ResponseCode.SERVFAIL), note="exception")
        latency_ms = (time.perf_counter() - started) * 1000

        if self._on_event is not None:
            try:
                self._on_event(query, handled, client_ip, latency_ms)
            except Exception:
                pass  # logging must never take down the resolver

        out = handled.response.to_bytes()

        # UDP truncation: if the answer is too big for legacy UDP, clear the
        # answer sections and set TC so the client retries over TCP.
        if not over_tcp and len(out) > UDP_MAX_LEGACY:
            truncated = query.make_response(handled.response.header.rcode)
            truncated.header.tc = True
            out = truncated.to_bytes()

        return out

    async def start(self):
        loop = asyncio.get_running_loop()

        # UDP listener.
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self),
            local_addr=(self.host, self.port),
        )

        # TCP listener — each connection may carry length-prefixed messages.
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp, self.host, self.port
        )
        return self

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_ip = writer.get_extra_info("peername")[0]
        try:
            while True:
                length_bytes = await reader.readexactly(2)
                (length,) = __import__("struct").unpack("!H", length_bytes)
                data = await reader.readexactly(length)
                response = await self.process(data, client_ip, over_tcp=True)
                if response is None:
                    continue
                writer.write(len(response).to_bytes(2, "big") + response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def serve_forever(self):
        await self.start()
        assert self._tcp_server is not None
        async with self._tcp_server:
            await self._tcp_server.serve_forever()


# ── a tiny milestone-1 demo you can run directly ──────────────────────────────
async def _demo():
    """`python -m dns_server.server` → a static server answering blog.local."""
    from .records import RecordClass, RecordType
    from .wire import AData, Record

    records = {
        ("blog.local", int(RecordType.A)): [
            Record("blog.local", RecordType.A, RecordClass.IN, 60, AData("127.0.0.1"))
        ],
    }
    server = DNSServer(StaticResolver(records), host="127.0.0.1", port=5353)
    print("milestone-1 static DNS server on 127.0.0.1:5353")
    print("try:  dig @127.0.0.1 -p 5353 blog.local")
    await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass
