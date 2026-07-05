"""Offline tests for the cache (TTL countdown, negative caching) and blocklist."""
import time

from dns_server.blocklist import Blocklist
from dns_server.cache import Cache
from dns_server.records import RecordClass, RecordType, ResponseCode
from dns_server.wire import AData, Record, SOAData


def _a(name, ip, ttl):
    return Record(name, RecordType.A, RecordClass.IN, ttl, AData(ip))


def test_cache_hit_and_miss():
    c = Cache()
    assert c.get("example.com", int(RecordType.A), int(RecordClass.IN)) is None  # miss
    c.put("example.com", int(RecordType.A), int(RecordClass.IN),
          ResponseCode.NOERROR, [_a("example.com", "1.2.3.4", 300)], [])
    hit = c.get("example.com", int(RecordType.A), int(RecordClass.IN))
    assert hit is not None and hit.answers[0].rdata.address == "1.2.3.4"
    assert c.stats()["hits"] == 1 and c.stats()["misses"] == 1


def test_ttl_counts_down_and_expires():
    c = Cache()
    # Cache with a 1s TTL, then rewind the stored timestamp to force expiry.
    c.put("x.test", int(RecordType.A), int(RecordClass.IN),
          ResponseCode.NOERROR, [_a("x.test", "9.9.9.9", 1)], [])
    key = ("x.test", int(RecordType.A), int(RecordClass.IN))
    c._store[key].stored_at = time.monotonic() - 5   # pretend 5s elapsed
    assert c.get("x.test", int(RecordType.A), int(RecordClass.IN)) is None  # expired → evicted


def test_negative_caching_uses_soa_minimum():
    c = Cache()
    soa = Record("test", RecordType.SOA, RecordClass.IN, 3600,
                 SOAData("ns.test", "root.test", 1, 60, 60, 60, minimum=120))
    c.put("nope.test", int(RecordType.A), int(RecordClass.IN),
          ResponseCode.NXDOMAIN, [], [soa])
    hit = c.get("nope.test", int(RecordType.A), int(RecordClass.IN))
    assert hit is not None and hit.rcode == ResponseCode.NXDOMAIN
    # TTL should come from the SOA minimum (120), capped by nothing lower here.
    assert 118 <= hit.ttl <= 120


def test_blocklist_suffix_matching():
    bl = Blocklist()
    added = bl.load_text("0.0.0.0 doubleclick.net\ngoogle-analytics.com\n# comment\n\n")
    assert added == 2
    assert bl.is_blocked("doubleclick.net")
    assert bl.is_blocked("ad.stats.doubleclick.net")   # subdomain
    assert bl.is_blocked("google-analytics.com")
    assert not bl.is_blocked("notdoubleclick.net")     # not a real suffix
    assert not bl.is_blocked("example.com")
