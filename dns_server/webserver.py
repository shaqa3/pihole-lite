"""
A tiny asyncio HTTP/1.1 + Server-Sent-Events server — zero dependencies.

We already hand-rolled a binary DNS server on asyncio; a small HTTP server for
the dashboard is the same tools again, and keeps the whole project runnable with
nothing but the standard library.

Why SSE and not WebSockets? The dashboard only needs data flowing ONE way
(server → browser). Server-Sent Events is exactly that: a normal HTTP response
with `Content-Type: text/event-stream` that stays open, over which we write
`data: {...}\n\n` frames. The browser's built-in `EventSource` reconnects
automatically. No handshake, no framing, no library — a fraction of WebSocket's
complexity for a live feed.

Routes:
  GET /            → the dashboard HTML
  GET /api/stats   → a JSON snapshot (totals, top domains, recent queries)
  GET /events      → the live SSE stream of every query as it happens
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

log = logging.getLogger("dns.web")


class WebServer:
    def __init__(self, stats, static_dir: Path, host: str = "127.0.0.1", port: int = 8053):
        self.stats = stats
        self.static_dir = Path(static_dir)
        self.host = host
        self.port = port

    async def serve_forever(self):
        server = await asyncio.start_server(self._handle, self.host, self.port)
        async with server:
            await server.serve_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = await reader.readuntil(b"\r\n")
            # Drain the rest of the headers (we don't need them, but must consume).
            await self._drain_headers(reader)
            method, path, _ = request_line.decode("latin1").split(" ", 2)
            path = path.split("?", 1)[0]  # ignore query string

            if method != "GET":
                await self._send(writer, 405, "text/plain", b"method not allowed")
            elif path == "/events":
                await self._stream_events(writer)          # long-lived; returns on disconnect
                return
            elif path == "/api/stats":
                body = json.dumps(self.stats.snapshot()).encode()
                await self._send(writer, 200, "application/json", body)
            else:
                await self._serve_static(writer, path)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as e:  # never let one bad request kill the listener
            log.debug("web request error: %r", e)
        finally:
            writer.close()

    @staticmethod
    async def _drain_headers(reader: asyncio.StreamReader):
        # Read header lines until the blank line that ends the header block.
        while True:
            line = await reader.readuntil(b"\r\n")
            if line == b"\r\n":
                return

    async def _serve_static(self, writer, path: str):
        name = "index.html" if path == "/" else path.lstrip("/")
        # Guard against path traversal: resolve and confirm it stays in static_dir.
        target = (self.static_dir / name).resolve()
        if not str(target).startswith(str(self.static_dir.resolve())) or not target.is_file():
            await self._send(writer, 404, "text/plain", b"not found")
            return
        ctype = {
            ".html": "text/html", ".css": "text/css", ".js": "application/javascript",
            ".svg": "image/svg+xml",
        }.get(target.suffix, "application/octet-stream")
        await self._send(writer, 200, ctype, target.read_bytes())

    async def _stream_events(self, writer):
        """Hold the connection open and push each query event as it arrives."""
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
        )
        writer.write(headers.encode())
        await writer.drain()

        queue = self.stats.subscribe()
        try:
            # Send a hello comment so EventSource fires `onopen` immediately.
            writer.write(b": connected\n\n")
            await writer.drain()
            while True:
                # Time out periodically to send a keep-alive comment; this also
                # lets us notice a dead connection (the drain will raise).
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    frame = f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    frame = ": keep-alive\n\n"
                writer.write(frame.encode())
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self.stats.unsubscribe(queue)

    @staticmethod
    async def _send(writer, status: int, ctype: str, body: bytes):
        reason = {200: "OK", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "OK")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(head.encode() + body)
        await writer.drain()
