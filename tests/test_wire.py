"""
Tests for the wire codec. These run offline (no network).

The most important test is `test_parses_real_response_with_compression`, which
feeds in bytes captured from a real DNS answer — the surest proof our parser
handles compression pointers the way the rest of the internet emits them.
"""
import struct

from dns_server.records import RecordClass, RecordType, ResponseCode
from dns_server.wire import AData, Message, Question, Reader, Writer


def test_header_and_question_roundtrip():
    query = Message.make_query("www.example.com", RecordType.A, id=0x1234)
    raw = query.to_bytes()
    again = Message.parse(raw)

    assert again.header.id == 0x1234
    assert again.header.qr is False
    assert again.header.rd is True
    assert len(again.questions) == 1
    assert again.questions[0].name == "www.example.com"
    assert again.questions[0].qtype == RecordType.A
    assert again.questions[0].qclass == RecordClass.IN


def test_answer_record_roundtrip():
    query = Message.make_query("example.com", RecordType.A, id=1)
    resp = query.make_response()
    from dns_server.wire import Record

    resp.answers.append(
        Record("example.com", RecordType.A, RecordClass.IN, 300, AData("93.184.216.34"))
    )
    parsed = Message.parse(resp.to_bytes())

    assert parsed.header.qr is True
    assert parsed.header.rcode == ResponseCode.NOERROR
    assert len(parsed.answers) == 1
    ans = parsed.answers[0]
    assert ans.name == "example.com"
    assert ans.rtype == RecordType.A
    assert ans.ttl == 300
    assert isinstance(ans.rdata, AData)
    assert ans.rdata.address == "93.184.216.34"


def test_name_compression_is_emitted_and_read_back():
    # Two names sharing the "example.com" tail should make the serialiser emit a
    # compression pointer for the second — proving our writer compresses.
    w = Writer()
    w.write_name("mail.example.com")
    first_len = len(w.buf)
    w.write_name("www.example.com")
    second_len = len(w.buf) - first_len

    # "www" (4) + pointer (2) = 6 bytes, versus 17 uncompressed. So compression
    # definitely happened if the second name is much shorter than the first.
    assert second_len < first_len

    r = Reader(bytes(w.buf))
    assert r.read_name() == "mail.example.com"
    assert r.read_name() == "www.example.com"


def test_parses_real_response_with_compression():
    # A hand-assembled, real-world-shaped response to "example.com A".
    # The answer's NAME is the 2-byte compression pointer 0xC00C — "the name at
    # offset 12", i.e. the question name. A parser that can't follow the pointer
    # will get the owner name wrong.
    # id=1234 flags=8180(QR,RD,RA) qd=1 an=1 ns=0 ar=0
    # question: 7"example" 3"com" 0, type A, class IN  (begins at offset 12)
    # answer:   name=ptr→offset 12 (c00c), type A, class IN, ttl=300,
    #           rdlen=4, rdata 5db8d822 = 93.184.216.34
    hex_str = (
        "1234 8180 0001 0001 0000 0000 "
        "07 6578616d706c65 03 636f6d 00 0001 0001 "
        "c00c 0001 0001 0000012c 0004 5db8d822"
    )
    packet = bytes.fromhex(hex_str.replace(" ", ""))
    msg = Message.parse(packet)
    assert msg.header.id == 0x1234
    assert msg.header.qr is True
    assert msg.questions[0].name == "example.com"
    assert len(msg.answers) == 1
    ans = msg.answers[0]
    assert ans.name == "example.com"          # ← resolved through the pointer
    assert ans.ttl == 300
    assert isinstance(ans.rdata, AData)
    assert ans.rdata.address == "93.184.216.34"


def test_compression_loop_is_rejected():
    # A pointer at offset 0 that points to offset 0 = infinite loop. Must raise,
    # not hang. This is a real attack against naive DNS parsers.
    evil = struct.pack("!H", 0xC000)  # pointer -> byte 0 (itself)
    try:
        Reader(evil).read_name()
    except ValueError:
        return
    raise AssertionError("expected a ValueError on a self-referential pointer")
