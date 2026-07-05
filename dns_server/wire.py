"""
The DNS wire protocol — parsing and serialising DNS messages.

This is the core of the whole project. A DNS "message" (query or response) is a
compact binary blob. There is no JSON, no length-prefixed fields you can skip
blindly — you must walk it byte by byte, in order, because later fields can only
be located once you've parsed the earlier ones. This module turns those bytes
into Python objects and back.

────────────────────────────────────────────────────────────────────────────
THE MESSAGE LAYOUT (RFC 1035 §4)

Every DNS message, query or answer, has the exact same 5-part shape:

    +---------------------+
    |        Header       |  12 bytes, fixed
    +---------------------+
    |       Question      |  what was asked (usually exactly 1)
    +---------------------+
    |        Answer       |  the resource records that answer it
    +---------------------+
    |      Authority      |  which name servers are authoritative
    +---------------------+
    |      Additional     |  extra helpful records (e.g. "glue" IPs)
    +---------------------+

A *query* fills in the Header + Question and leaves the rest empty. The server
copies the Question back and fills in the Answer/Authority/Additional sections.
Same structure both directions — that symmetry is what makes DNS simple.

────────────────────────────────────────────────────────────────────────────
THE HEADER (12 bytes = six 16-bit big-endian integers)

     0  1  2  3  4  5  6  7   8  9 10 11 12 13 14 15   <- bit
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |   a 16-bit request id
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|  Opcode   |AA|TC|RD|RA|  Z  |    RCODE     |   the flags word
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                     |  # of questions
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                     |  # of answers
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                     |  # of authority records
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                     |  # of additional records
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The flags word packs 8 fields into 16 bits:
  QR     1 bit   0 = query, 1 = response
  Opcode 4 bits  usually 0 (standard QUERY)
  AA     1 bit   Authoritative Answer — set by a server that *owns* the zone
  TC     1 bit   TrunCated — answer was too big for UDP; retry over TCP
  RD     1 bit   Recursion Desired — client asking the server to do the work
  RA     1 bit   Recursion Available — server saying "yes I can recurse"
  Z      3 bits  reserved, must be 0
  RCODE  4 bits  result code (0 = ok, 3 = NXDOMAIN, ...)

────────────────────────────────────────────────────────────────────────────
NAMES AND THE COMPRESSION TRICK (RFC 1035 §4.1.4)

A domain name is NOT a null-terminated string. It's a sequence of *labels*, each
prefixed by its length byte, ending with a zero-length label (the root):

    "www.example.com"  ->  3 w w w 7 e x a m p l e 3 c o m 0
                           ^len       ^len          ^len    ^root

Because a single response repeats the same domain over and over (the question
name, then the answer's owner name, then names inside the records...), DNS
compresses names with *pointers*. If a label's length byte has its top two bits
set (0b11xxxxxx), it is not a length at all — it and the next byte form a 14-bit
offset from the START of the message. "Jump there and keep reading labels."

    ...  0xC0 0x0C   ->  "go to byte 12 and continue the name from there"

This is why you cannot parse a DNS record in isolation: a pointer can reference
any earlier byte in the whole packet. The parser therefore always carries the
full message buffer and resolves pointers against absolute offsets. It's also
the classic source of security bugs (a pointer that points to itself = infinite
loop), so we guard against that.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .records import OpCode, RecordClass, RecordType, ResponseCode


# ─────────────────────────────────────────────────────────────────────────────
# Reader: a cursor over the message bytes with DNS-aware helpers.
# ─────────────────────────────────────────────────────────────────────────────
class Reader:
    """
    A stateful cursor. `pos` is where we are in the buffer. Reading advances it.
    Crucially, `read_name` may temporarily *jump* backwards to follow a
    compression pointer, but the cursor only advances past the pointer itself —
    the bytes we jumped to are not "consumed" for the outer record.
    """

    def __init__(self, data: bytes, pos: int = 0):
        self._data = data
        self.pos = pos

    def read_u8(self) -> int:
        (value,) = struct.unpack_from("!B", self._data, self.pos)
        self.pos += 1
        return value

    def read_u16(self) -> int:
        # "!H" = network byte order (big-endian), unsigned 16-bit.
        (value,) = struct.unpack_from("!H", self._data, self.pos)
        self.pos += 2
        return value

    def read_u32(self) -> int:
        (value,) = struct.unpack_from("!I", self._data, self.pos)
        self.pos += 4
        return value

    def read_bytes(self, n: int) -> bytes:
        chunk = self._data[self.pos : self.pos + n]
        if len(chunk) != n:
            raise ValueError("truncated message: ran off the end")
        self.pos += n
        return chunk

    def read_name(self) -> str:
        """
        Read a domain name, transparently following compression pointers.

        Returns a lowercased dotted string ("www.example.com"); the root is the
        empty string "". Lowercasing here gives us one canonical form, since DNS
        names are case-insensitive — handy for cache keys and blocklist matches.
        """
        labels: list[bytes] = []
        pos = self.pos
        jumped = False          # have we followed at least one pointer?
        cursor_after = None     # where the *real* cursor should land afterwards
        guard = 0               # loop protection: a malicious packet can cycle

        while True:
            guard += 1
            if guard > 128:
                raise ValueError("name compression loop (or absurdly long name)")

            length = self._data[pos]
            marker = length & 0xC0  # top two bits

            if marker == 0xC0:
                # Compression pointer: this byte + the next form a 14-bit offset.
                pointer = ((length & 0x3F) << 8) | self._data[pos + 1]
                if not jumped:
                    # The outer record only "spends" the 2 bytes of the pointer.
                    cursor_after = pos + 2
                    jumped = True
                pos = pointer
                continue

            if marker != 0:
                # 0b10 and 0b01 are reserved and must never appear.
                raise ValueError(f"reserved label bits set: {length:#x}")

            if length == 0:
                # Zero-length label = the root = end of the name.
                pos += 1
                if not jumped:
                    cursor_after = pos
                break

            # An ordinary label: length byte followed by that many bytes.
            pos += 1
            labels.append(self._data[pos : pos + length])
            pos += length
            if not jumped:
                cursor_after = pos

        self.pos = cursor_after
        return ".".join(label.decode("ascii", "replace").lower() for label in labels)


# ─────────────────────────────────────────────────────────────────────────────
# Writer: build a message, with domain-name compression on the way out.
# ─────────────────────────────────────────────────────────────────────────────
class Writer:
    """
    Accumulates bytes in `buf`. Tracks where each name suffix was written so we
    can emit compression pointers ourselves — this is the same trick, in
    reverse. Compressing our responses keeps them under the 512-byte UDP limit
    more often, avoiding TCP fallback.
    """

    def __init__(self):
        self.buf = bytearray()
        self._name_offsets: dict[str, int] = {}  # "example.com" -> byte offset

    def write_u8(self, value: int) -> None:
        self.buf += struct.pack("!B", value)

    def write_u16(self, value: int) -> None:
        self.buf += struct.pack("!H", value)

    def write_u32(self, value: int) -> None:
        self.buf += struct.pack("!I", value)

    def write_bytes(self, data: bytes) -> None:
        self.buf += data

    def write_name(self, name: str) -> None:
        """
        Write a domain name, reusing a compression pointer for any suffix we've
        already written. "mail.example.com" and "www.example.com" share the
        "example.com" tail, so the second one can point at the first's tail.
        """
        # Normalise: drop a trailing dot, split into labels; root -> [].
        labels = [lbl for lbl in name.rstrip(".").split(".") if lbl]

        i = 0
        while i < len(labels):
            suffix = ".".join(labels[i:]).lower()
            if suffix in self._name_offsets:
                # We've written this exact tail before — point at it and stop.
                pointer = 0xC000 | self._name_offsets[suffix]
                self.write_u16(pointer)
                return
            # Remember where this suffix begins, so later names can point here.
            # Pointers are only 14 bits, so we can't reference beyond 0x3FFF.
            if len(self.buf) <= 0x3FFF:
                self._name_offsets[suffix] = len(self.buf)
            label = labels[i].encode("ascii")
            if len(label) > 63:
                raise ValueError("label longer than 63 bytes is illegal")
            self.write_u8(len(label))
            self.write_bytes(label)
            i += 1

        self.write_u8(0)  # the root terminator


# ─────────────────────────────────────────────────────────────────────────────
# RDATA — the type-specific payload inside a resource record.
#
# The RDATA of an A record is 4 raw bytes (an IPv4 address). The RDATA of an MX
# record is a 16-bit preference followed by a *domain name* (which may be
# compressed!). So we model each shape we care about, and fall back to raw bytes
# for anything exotic — a resolver still needs to copy those through untouched.
# ─────────────────────────────────────────────────────────────────────────────
class RData:
    """Base class. Subclasses know how to serialise their own body."""

    def write(self, writer: Writer) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


@dataclass
class AData(RData):
    address: str  # dotted IPv4, e.g. "93.184.216.34"

    def write(self, writer: Writer) -> None:
        writer.write_bytes(socket.inet_pton(socket.AF_INET, self.address))


@dataclass
class AAAAData(RData):
    address: str  # IPv6, e.g. "2606:2800:220:1:248:1893:25c8:1946"

    def write(self, writer: Writer) -> None:
        writer.write_bytes(socket.inet_pton(socket.AF_INET6, self.address))


@dataclass
class NameData(RData):
    """A record whose whole payload is one domain name: NS, CNAME, PTR."""

    target: str

    def write(self, writer: Writer) -> None:
        writer.write_name(self.target)


@dataclass
class MXData(RData):
    preference: int
    exchange: str

    def write(self, writer: Writer) -> None:
        writer.write_u16(self.preference)
        writer.write_name(self.exchange)


@dataclass
class SOAData(RData):
    mname: str      # primary name server for the zone
    rname: str      # admin email, with '.' instead of '@'
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int    # ALSO the TTL to use for negative (NXDOMAIN) caching

    def write(self, writer: Writer) -> None:
        writer.write_name(self.mname)
        writer.write_name(self.rname)
        for value in (self.serial, self.refresh, self.retry, self.expire, self.minimum):
            writer.write_u32(value)


@dataclass
class TXTData(RData):
    chunks: list[bytes]  # TXT is one-or-more length-prefixed byte strings

    def write(self, writer: Writer) -> None:
        for chunk in self.chunks:
            writer.write_u8(len(chunk))
            writer.write_bytes(chunk)


@dataclass
class RawData(RData):
    """Anything we don't specifically model — kept as opaque bytes."""

    raw: bytes

    def write(self, writer: Writer) -> None:
        writer.write_bytes(self.raw)


def _parse_rdata(reader: Reader, rtype: RecordType, rdlength: int) -> RData:
    """Parse the RDATA body according to the record type."""
    start = reader.pos
    if rtype == RecordType.A:
        return AData(socket.inet_ntop(socket.AF_INET, reader.read_bytes(4)))
    if rtype == RecordType.AAAA:
        return AAAAData(socket.inet_ntop(socket.AF_INET6, reader.read_bytes(16)))
    if rtype in (RecordType.NS, RecordType.CNAME, RecordType.PTR):
        return NameData(reader.read_name())
    if rtype == RecordType.MX:
        return MXData(reader.read_u16(), reader.read_name())
    if rtype == RecordType.SOA:
        return SOAData(
            mname=reader.read_name(),
            rname=reader.read_name(),
            serial=reader.read_u32(),
            refresh=reader.read_u32(),
            retry=reader.read_u32(),
            expire=reader.read_u32(),
            minimum=reader.read_u32(),
        )
    if rtype == RecordType.TXT:
        chunks = []
        while reader.pos < start + rdlength:
            n = reader.read_u8()
            chunks.append(reader.read_bytes(n))
        return TXTData(chunks)
    # Unknown / unmodelled type: grab the raw bytes so we can copy it verbatim.
    return RawData(reader.read_bytes(rdlength))


# ─────────────────────────────────────────────────────────────────────────────
# The structured message objects.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Header:
    id: int = 0
    qr: bool = False        # False = query, True = response
    opcode: OpCode = OpCode.QUERY
    aa: bool = False        # authoritative answer
    tc: bool = False        # truncated
    rd: bool = True         # recursion desired
    ra: bool = False        # recursion available
    rcode: ResponseCode = ResponseCode.NOERROR
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    @classmethod
    def parse(cls, reader: Reader) -> "Header":
        id_ = reader.read_u16()
        flags = reader.read_u16()
        # Unpack the flags word bit by bit (see the ASCII diagram at the top).
        return cls(
            id=id_,
            qr=bool(flags >> 15 & 1),
            opcode=OpCode(flags >> 11 & 0xF),
            aa=bool(flags >> 10 & 1),
            tc=bool(flags >> 9 & 1),
            rd=bool(flags >> 8 & 1),
            ra=bool(flags >> 7 & 1),
            # bits 6..4 are Z (reserved) — ignored
            rcode=ResponseCode(flags & 0xF),
            qdcount=reader.read_u16(),
            ancount=reader.read_u16(),
            nscount=reader.read_u16(),
            arcount=reader.read_u16(),
        )

    def write(self, writer: Writer) -> None:
        flags = (
            (int(self.qr) << 15)
            | (int(self.opcode) << 11)
            | (int(self.aa) << 10)
            | (int(self.tc) << 9)
            | (int(self.rd) << 8)
            | (int(self.ra) << 7)
            | int(self.rcode)
        )
        writer.write_u16(self.id)
        writer.write_u16(flags)
        writer.write_u16(self.qdcount)
        writer.write_u16(self.ancount)
        writer.write_u16(self.nscount)
        writer.write_u16(self.arcount)


@dataclass
class Question:
    name: str
    qtype: RecordType = RecordType.A
    qclass: RecordClass = RecordClass.IN

    @classmethod
    def parse(cls, reader: Reader) -> "Question":
        name = reader.read_name()
        return cls(name, RecordType(reader.read_u16()), RecordClass(reader.read_u16()))

    def write(self, writer: Writer) -> None:
        writer.write_name(self.name)
        writer.write_u16(int(self.qtype))
        writer.write_u16(int(self.qclass))


@dataclass
class Record:
    """A resource record (RR): the unit of DNS data in answer/authority/extra."""

    name: str
    rtype: RecordType
    rclass: RecordClass
    ttl: int
    rdata: RData

    @classmethod
    def parse(cls, reader: Reader) -> "Record":
        name = reader.read_name()
        rtype = RecordType(reader.read_u16())
        rclass = RecordClass(reader.read_u16())
        ttl = reader.read_u32()
        rdlength = reader.read_u16()
        end = reader.pos + rdlength
        rdata = _parse_rdata(reader, rtype, rdlength)
        # Defensive: some records' rdata parsing (with compression) can leave the
        # cursor in an odd spot; RDLENGTH is authoritative for where the RR ends.
        reader.pos = end
        return cls(name, rtype, rclass, ttl, rdata)

    def write(self, writer: Writer) -> None:
        writer.write_name(self.name)
        writer.write_u16(int(self.rtype))
        writer.write_u16(int(self.rclass))
        writer.write_u32(self.ttl)
        # We don't know RDLENGTH until we've written the body (names compress to
        # variable length). Trick: write a placeholder, remember the spot, write
        # the body, then patch the length in place.
        length_pos = len(writer.buf)
        writer.write_u16(0)  # placeholder
        body_start = len(writer.buf)
        self.rdata.write(writer)
        rdlength = len(writer.buf) - body_start
        struct.pack_into("!H", writer.buf, length_pos, rdlength)


@dataclass
class Message:
    header: Header = field(default_factory=Header)
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)

    # ── parsing ──────────────────────────────────────────────────────────────
    @classmethod
    def parse(cls, data: bytes) -> "Message":
        reader = Reader(data)
        header = Header.parse(reader)
        msg = cls(header=header)
        for _ in range(header.qdcount):
            msg.questions.append(Question.parse(reader))
        for _ in range(header.ancount):
            msg.answers.append(Record.parse(reader))
        for _ in range(header.nscount):
            msg.authorities.append(Record.parse(reader))
        for _ in range(header.arcount):
            msg.additionals.append(Record.parse(reader))
        return msg

    # ── serialising ──────────────────────────────────────────────────────────
    def to_bytes(self) -> bytes:
        # Keep the counts in the header honest with the actual section lengths.
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authorities)
        self.header.arcount = len(self.additionals)

        writer = Writer()
        self.header.write(writer)
        for question in self.questions:
            question.write(writer)
        for record in self.answers:
            record.write(writer)
        for record in self.authorities:
            record.write(writer)
        for record in self.additionals:
            record.write(writer)
        return bytes(writer.buf)

    # ── convenience constructors ───────────────────────────────────────────────
    @classmethod
    def make_query(cls, name: str, qtype: RecordType, *, id: int = 0, rd: bool = True) -> "Message":
        """Build a standard recursive query for `name`/`qtype`."""
        header = Header(id=id, qr=False, rd=rd, qdcount=1)
        return cls(header=header, questions=[Question(name, qtype, RecordClass.IN)])

    def make_response(self, rcode: ResponseCode = ResponseCode.NOERROR) -> "Message":
        """Start a response to this query: copy id + question, flip QR to 1."""
        header = Header(
            id=self.header.id,
            qr=True,
            opcode=self.header.opcode,
            rd=self.header.rd,
            ra=True,          # we offer recursion
            rcode=rcode,
        )
        return Message(header=header, questions=list(self.questions))
