"""
Blocklist filtering — the "ad-blocker" product twist.

The insight behind Pi-hole and friends: your browser can't load an ad if it
can't find the ad server's IP address. Ads and trackers live on identifiable
domains (doubleclick.net, google-analytics.com, ...). If our resolver simply
refuses to answer for those domains, the requests die before a single byte of
ad content is fetched — network-wide, for every device pointed at us, with no
per-app extension needed.

HOW BLOCKING IS EXPRESSED. Two common list formats, both supported here:
  • hosts format:  "0.0.0.0 ads.example.com"  (the sinkhole IP is ignored; we
    only care about the domain). This is the format of the big community lists.
  • domain list:   "ads.example.com"          (one domain per line).

MATCHING IS SUFFIX-BASED. Listing "doubleclick.net" must also block
"ad.doubleclick.net" and "stats.g.doubleclick.net" — every subdomain. So for a
query we test the full name and each parent domain against the set.

WHAT WE RETURN. Two philosophies:
  • NXDOMAIN — "this name does not exist." Honest-ish and cache-friendly.
  • 0.0.0.0 / :: (a "sinkhole") — the name resolves to a dead address, so the
    client connects nowhere. Pi-hole's default; some clients retry less than
    with NXDOMAIN. We default to the sinkhole and make it configurable.

LIMITS worth knowing (and writing about): DNS blocking can't stop ads served
from the same domain as content (first-party ads), and it can't see inside an
HTTPS connection to block by URL path. It's a blunt, powerful, domain-level
filter — not a content filter.
"""
from __future__ import annotations

from dataclasses import dataclass

from .records import RecordClass, RecordType, ResponseCode
from .server import Handled
from .wire import AAAAData, AData, Message, Record


class Blocklist:
    """An in-memory set of blocked domains with suffix matching."""

    def __init__(self):
        self._blocked: set[str] = set()

    def __len__(self) -> int:
        return len(self._blocked)

    def add(self, domain: str) -> None:
        domain = domain.strip().rstrip(".").lower()
        if domain:
            self._blocked.add(domain)

    def load_text(self, text: str) -> int:
        """
        Parse a blocklist in either hosts or plain-domain format. Returns the
        number of domains added. Lines are tolerated liberally: comments (# ...),
        blank lines, and inline IPs are all handled.
        """
        before = len(self._blocked)
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()  # drop comments
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and _looks_like_ip(parts[0]):
                # hosts format: "0.0.0.0 ads.example.com" (possibly more domains)
                for token in parts[1:]:
                    self._add_hostname(token)
            else:
                # plain domain list: "ads.example.com"
                self._add_hostname(parts[0])
        return len(self._blocked) - before

    def _add_hostname(self, token: str) -> None:
        token = token.strip().rstrip(".").lower()
        # Skip the localhost noise that litters hosts files.
        if token and token not in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
            self._blocked.add(token)

    def is_blocked(self, name: str) -> bool:
        """True if `name` or any parent domain is on the list (suffix match)."""
        name = name.strip().rstrip(".").lower()
        labels = name.split(".")
        # Test the full name, then progressively broader parent domains:
        #   ad.doubleclick.net → doubleclick.net → net
        for i in range(len(labels)):
            if ".".join(labels[i:]) in self._blocked:
                return True
        return False


def _looks_like_ip(token: str) -> bool:
    # Good enough to distinguish a hosts-file IP column from a domain.
    return token.replace(".", "").isdigit() or ":" in token


# ─────────────────────────────────────────────────────────────────────────────
# BlockingResolver: intercept blocked names before they reach real resolution.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class BlockingResolver:
    """
    Wraps another resolver. If the queried name is blocked we answer immediately
    (no upstream/recursion, no caching needed — matching is already O(labels)).
    Otherwise we pass through untouched.
    """

    inner: object
    blocklist: Blocklist
    mode: str = "sinkhole"  # "sinkhole" (0.0.0.0 / ::) or "nxdomain"
    ttl: int = 60           # short TTL so list edits take effect quickly

    async def handle(self, query: Message, client_ip: str) -> Handled:
        if not query.questions:
            return await self.inner.handle(query, client_ip)
        q = query.questions[0]

        if not self.blocklist.is_blocked(q.name):
            return await self.inner.handle(query, client_ip)

        # Blocked → craft the refusal ourselves.
        if self.mode == "nxdomain":
            response = query.make_response(ResponseCode.NXDOMAIN)
            return Handled(response, blocked=True, note="blocked (nxdomain)")

        # Sinkhole mode: hand back a dead address for A/AAAA, empty NOERROR else.
        response = query.make_response(ResponseCode.NOERROR)
        if q.qtype == RecordType.A:
            response.answers.append(
                Record(q.name, RecordType.A, RecordClass.IN, self.ttl, AData("0.0.0.0"))
            )
        elif q.qtype == RecordType.AAAA:
            response.answers.append(
                Record(q.name, RecordType.AAAA, RecordClass.IN, self.ttl, AAAAData("::"))
            )
        # For other types we return NOERROR with no answer (NODATA) — nothing to
        # sinkhole, but we still refuse to look it up.
        return Handled(response, blocked=True, note="blocked (sinkhole)")
