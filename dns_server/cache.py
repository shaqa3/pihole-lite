"""
A DNS cache that honours TTLs — including *negative* caching.

Why caching is the whole point of a resolver: resolving a name from the root
takes several round-trips across the internet. If every "www.example.com" did
that, DNS would be unusably slow and the root servers would melt. Instead every
record carries a TTL (Time To Live, in seconds) that says "you may reuse this
answer for up to N seconds." A resolver that respects TTLs turns a 100ms
recursion into a sub-millisecond memory lookup.

Two things make a correct cache more than just a dict:

1. TTL COUNTDOWN. A record cached with TTL=300 and served 200 seconds later must
   be handed out with TTL≈100, not 300 — the downstream client is entitled to
   know how much life is left. So we store an absolute expiry and recompute the
   remaining TTL on every read, evicting once it hits zero.

2. NEGATIVE CACHING (RFC 2308). "This name does not exist" (NXDOMAIN) and "this
   name exists but has no record of that type" (NODATA) are answers worth
   caching too — otherwise a typo'd domain in a loop hammers upstream forever.
   The TTL for a negative answer comes from the SOA record in the authority
   section (its MINIMUM field, capped by the SOA's own TTL).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Optional

from .records import RecordType, ResponseCode
from .wire import Record, SOAData


@dataclass
class CacheEntry:
    rcode: ResponseCode          # NOERROR (positive) or NXDOMAIN (negative)
    answers: list[Record]        # the answer records (empty for a negative entry)
    authorities: list[Record]    # e.g. the SOA that justified a negative answer
    stored_at: float             # monotonic timestamp when we cached it
    ttl: int                     # entry lifetime = min TTL of its records

    @property
    def expires_at(self) -> float:
        return self.stored_at + self.ttl

    def remaining(self, now: float) -> int:
        return int(self.expires_at - now)


class Cache:
    """
    Keyed by (name, qtype, qclass). Not size-bounded here for clarity; a
    production cache would add an LRU bound. Uses a monotonic clock so it's
    immune to wall-clock jumps (NTP steps, DST) — TTLs are durations, not dates.
    """

    def __init__(self, *, min_ttl: int = 0, max_ttl: int = 86_400):
        self._store: dict[tuple[str, int, int], CacheEntry] = {}
        self._min_ttl = min_ttl   # floor: avoid re-querying on 0-TTL spam
        self._max_ttl = max_ttl   # ceiling: don't trust absurdly long TTLs
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _key(name: str, qtype: int, qclass: int) -> tuple[str, int, int]:
        return (name.lower(), qtype, qclass)

    def get(self, name: str, qtype: int, qclass: int) -> Optional[CacheEntry]:
        """
        Return a *fresh copy* of the entry with TTLs counted down, or None on
        miss/expiry. Copying matters: we must not mutate the stored record's TTL,
        and the caller is about to serialise these into a response.
        """
        now = time.monotonic()
        key = self._key(name, qtype, qclass)
        entry = self._store.get(key)
        if entry is None:
            self.misses += 1
            return None

        remaining = entry.remaining(now)
        if remaining <= 0:
            # Lazily evict on read — no background sweeper needed.
            del self._store[key]
            self.misses += 1
            return None

        self.hits += 1
        # Hand back copies whose TTL reflects the time already elapsed.
        answers = [replace(r, ttl=remaining) for r in entry.answers]
        authorities = [replace(r, ttl=remaining) for r in entry.authorities]
        return CacheEntry(entry.rcode, answers, authorities, now, remaining)

    def put(self, name: str, qtype: int, qclass: int, rcode: ResponseCode,
            answers: list[Record], authorities: list[Record]) -> None:
        """Cache a response, computing the entry's lifetime from the records."""
        ttl = self._compute_ttl(rcode, answers, authorities)
        if ttl <= 0:
            return  # nothing worth caching (e.g. a SERVFAIL, or TTL floored to 0)
        entry = CacheEntry(
            rcode=rcode,
            answers=list(answers),
            authorities=list(authorities),
            stored_at=time.monotonic(),
            ttl=ttl,
        )
        self._store[self._key(name, qtype, qclass)] = entry

    def _compute_ttl(self, rcode: ResponseCode, answers: list[Record],
                     authorities: list[Record]) -> int:
        if rcode == ResponseCode.NOERROR and answers:
            # Positive answer: live only as long as the shortest-lived record.
            ttl = min(r.ttl for r in answers)
        else:
            # Negative answer (NXDOMAIN or NODATA): use the SOA's MINIMUM, itself
            # capped by that SOA record's TTL, per RFC 2308.
            ttl = 0
            for rec in authorities:
                if rec.rtype == RecordType.SOA and isinstance(rec.rdata, SOAData):
                    ttl = min(rec.ttl, rec.rdata.minimum)
                    break
        return max(self._min_ttl, min(ttl, self._max_ttl))

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "entries": len(self._store),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": (self.hits / total) if total else 0.0,
        }
