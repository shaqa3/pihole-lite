"""
Stats + a live event bus for the dashboard.

Every processed query becomes a `QueryEvent`. This module does two jobs with it:
  1. AGGREGATE — running totals (queries, blocked, cache hits) and top-domain
     counters, so the dashboard can show "23% blocked, 68% cache hit rate".
  2. BROADCAST — push each event to any connected dashboards in real time.

The broadcast uses the classic asyncio fan-out pattern: each subscriber owns a
bounded `asyncio.Queue`; publishing does a non-blocking put to every queue. A
slow/stuck client just drops events (its queue fills) instead of back-pressuring
the DNS server — the resolver must never wait on a dashboard.
"""
from __future__ import annotations

import asyncio
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class QueryEvent:
    ts: float          # wall-clock seconds (epoch) for display
    name: str
    qtype: str
    client: str
    rcode: str
    blocked: bool
    cache_hit: bool
    upstream: Optional[str]
    latency_ms: float


class Stats:
    def __init__(self, ring: int = 500):
        self.recent: deque[QueryEvent] = deque(maxlen=ring)
        self.total = 0
        self.blocked = 0
        self.cache_hits = 0
        self.domain_counts: Counter[str] = Counter()
        self.blocked_counts: Counter[str] = Counter()
        self._subscribers: set[asyncio.Queue] = set()
        # A reference to the Cache so we can report its live hit-rate too.
        self.cache = None

    # ── ingestion: called by the DNS server's on_event hook ───────────────────
    def on_event(self, query, handled, client_ip, latency_ms) -> None:
        q = query.questions[0] if query.questions else None
        name = q.name if q else "?"
        event = QueryEvent(
            ts=time.time(),
            name=name,
            qtype=(q.qtype.name if q else "?"),
            client=client_ip,
            rcode=handled.response.header.rcode.name,
            blocked=handled.blocked,
            cache_hit=handled.cache_hit,
            upstream=handled.upstream,
            latency_ms=round(latency_ms, 2),
        )

        self.total += 1
        if event.blocked:
            self.blocked += 1
            self.blocked_counts[name] += 1
        else:
            self.domain_counts[name] += 1
        if event.cache_hit:
            self.cache_hits += 1
        self.recent.append(event)

        self._publish(event)

    # ── broadcast ─────────────────────────────────────────────────────────────
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def _publish(self, event: QueryEvent) -> None:
        payload = asdict(event)
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass  # a stuck dashboard simply misses events; never block DNS

    # ── snapshot for the REST endpoint / initial page load ────────────────────
    def snapshot(self) -> dict:
        blocked_pct = (self.blocked / self.total * 100) if self.total else 0.0
        cache_pct = (self.cache_hits / self.total * 100) if self.total else 0.0
        cache_stats = self.cache.stats() if self.cache is not None else {}
        return {
            "total": self.total,
            "blocked": self.blocked,
            "blocked_pct": round(blocked_pct, 1),
            "cache_hits": self.cache_hits,
            "cache_hit_pct": round(cache_pct, 1),
            "cache": cache_stats,
            "top_domains": self.domain_counts.most_common(10),
            "top_blocked": self.blocked_counts.most_common(10),
            "recent": [asdict(e) for e in list(self.recent)[-50:]][::-1],
        }
