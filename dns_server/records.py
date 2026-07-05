"""
DNS constants — the "vocabulary" of the protocol.

A DNS packet is just bytes. Those bytes carry small integers that stand for
things: "this is a query", "this is an A record", "the name doesn't exist".
This module gives those magic numbers human names so the rest of the code reads
like English instead of like a hex dump.

Everything here is defined by RFC 1035 (the original DNS spec) and its
descendants. The numbers are fixed by the standard — you don't get to choose
them; the whole internet agrees on them.
"""
from __future__ import annotations

from enum import IntEnum


class RecordType(IntEnum):
    """
    The TYPE field of a question/record: *what kind of data* are we asking for?

    A question "what is example.com, type A?" means "give me its IPv4 address".
    The same name can hold many types at once (an A record AND an MX record...).
    """
    A = 1        # IPv4 address (4 bytes)
    NS = 2       # Name server — "the authority for this zone is <name>"
    CNAME = 5    # Canonical name — "this name is an alias for <other name>"
    SOA = 6      # Start Of Authority — zone metadata; also used in negative answers
    PTR = 12     # Pointer — reverse DNS (IP -> name)
    MX = 15      # Mail eXchange — "mail for this domain goes to <host>, priority N"
    TXT = 16     # Arbitrary text (SPF, domain verification, etc.)
    AAAA = 28    # IPv6 address (16 bytes) — "quad A"
    SRV = 33     # Service location (host+port for a service)
    OPT = 41     # Not a real record — the EDNS(0) pseudo-record (see extras)

    @classmethod
    def _missing_(cls, value):
        # DNS has ~90 registered types and new ones appear. We only *model* a
        # handful, but we must not crash when we see an unknown one on the wire
        # (we still need to copy its bytes through). Return a synthetic member.
        unknown = int.__new__(cls, value)
        unknown._name_ = f"TYPE{value}"
        unknown._value_ = value
        return unknown


class RecordClass(IntEnum):
    """
    The CLASS field. In practice this is *always* IN (the Internet).
    The others are historical (CHAOS/CH is occasionally used for server
    version strings via `dig CH TXT version.bind`).
    """
    IN = 1    # Internet — the only one you'll ever see
    CH = 3    # Chaos
    ANY = 255 # Query-only: "any class"

    @classmethod
    def _missing_(cls, value):
        # An OPT (EDNS(0)) pseudo-record hijacks the CLASS field to advertise the
        # sender's UDP payload size (e.g. 4096) — NOT a real class. dig sends one
        # by default, so we must accept arbitrary values here instead of raising.
        unknown = int.__new__(cls, value)
        unknown._name_ = f"CLASS{value}"
        unknown._value_ = value
        return unknown


class OpCode(IntEnum):
    """The kind of operation in the header. Standard queries are QUERY (0)."""
    QUERY = 0
    IQUERY = 1   # inverse query, obsolete
    STATUS = 2   # server status, rarely used


class ResponseCode(IntEnum):
    """
    RCODE — how did the query go? Lives in the last 4 bits of the header flags.
    This is the single most important field for an ad-blocker: to "block" a
    domain we hand back NXDOMAIN, i.e. "this name does not exist."
    """
    NOERROR = 0    # success
    FORMERR = 1    # the server couldn't parse our query (format error)
    SERVFAIL = 2   # server failed (upstream broke, recursion failed, ...)
    NXDOMAIN = 3   # Non-eXistent DOMAIN — the name genuinely does not exist
    NOTIMP = 4     # server doesn't support that opcode
    REFUSED = 5    # server refuses for policy reasons (e.g. not allowed to recurse)


# Port 53 is DNS's well-known port for both UDP and TCP. Binding it needs root
# on unix (ports < 1024 are privileged) — we default to a high port in dev.
DNS_PORT = 53

# The classic UDP DNS message size limit from RFC 1035. Anything bigger had to
# fall back to TCP — until EDNS(0) let clients advertise a larger buffer.
UDP_MAX_LEGACY = 512
