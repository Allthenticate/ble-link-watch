import struct
from datetime import datetime, timedelta, timezone

from linkwatch.snoop import (
    _EPOCH_DELTA_US,
    UNKNOWN_PEER,
    HolderChange,
    connections,
    read_btsnoop,
    windows,
)

X1 = bytes.fromhex("607957577b84")  # 84:7B:57:57:79:60, little-endian on the wire
BASE = datetime(2026, 9, 28, 19, 48, 57, tzinfo=timezone.utc)


def _record(seconds: float, sent: bool, packet: bytes) -> bytes:
    stamp = int((BASE.timestamp() + seconds) * 1e6) + _EPOCH_DELTA_US
    flags = (0 if sent else 1) | (0 if packet[0] == 0x02 else 2)
    return struct.pack(">IIIIq", len(packet), len(packet), flags, 0, stamp) + packet


def _capture(*records: bytes) -> bytes:
    return b"btsnoop\x00" + struct.pack(">II", 1, 1002) + b"".join(records)


def _connected(handle: int) -> bytes:
    params = bytes([0x0A, 0x00]) + struct.pack("<H", handle) + bytes([0x00, 0x00]) + X1 + bytes(18)
    return bytes([0x04, 0x3E, len(params)]) + params


def _disconnected(handle: int, reason: int) -> bytes:
    return bytes([0x04, 0x05, 4, 0x00]) + struct.pack("<H", handle) + bytes([reason])


def _att(handle: int, pdu: bytes, cid: int = 0x0004) -> bytes:
    l2cap = struct.pack("<HH", len(pdu), cid) + pdu
    return bytes([0x02]) + struct.pack("<HH", handle | 0x2000, len(l2cap)) + l2cap


WRITE_0021 = bytes([0x12, 0x21, 0x00, 0x01])
INDICATION_0021 = bytes([0x1D, 0x21, 0x00, 0x02])


def test_timestamps_are_utc_microseconds_from_year_zero_and_direction_comes_from_the_flags():
    capture = _capture(_record(0, True, _att(65, WRITE_0021)), _record(1.5, False, _connected(65)))

    packets = read_btsnoop(capture, timezone.utc)

    assert [(p.at, p.sent) for p in packets] == [
        (datetime(2026, 9, 28, 19, 48, 57), True),
        (datetime(2026, 9, 28, 19, 48, 58, 500000), False),
    ]


def test_a_connection_collects_its_att_pdus_until_it_disconnects():
    packets = read_btsnoop(_capture(
        _record(0, False, _connected(65)),
        _record(1, True, _att(65, WRITE_0021)),
        _record(1.1, False, _att(65, INDICATION_0021)),
        _record(2, False, _disconnected(65, 0x13)),
        _record(3, True, _att(65, WRITE_0021)),
    ), timezone.utc)

    first, second = connections(packets)

    assert (first.peer, first.suffix, first.reason) == ("84:7B:57:57:79:60", "79:60", 0x13)
    assert [(p.sent, p.name) for p in first.pdus] == [
        (True, "Write Request 0x0021"), (False, "Handle Value Indication 0x0021")]
    assert (second.peer, second.suffix, len(second.pdus)) == (UNKNOWN_PEER, None, 1)


def test_a_handle_carrying_no_att_is_not_mistaken_for_an_le_link():
    packets = read_btsnoop(_capture(_record(0, True, _att(11, bytes([0x02, 0x01, 0x00]), cid=0x0041))),
                           timezone.utc)

    assert connections(packets) == []


def test_requests_are_counted_against_the_apps_holding_the_link_when_they_were_sent():
    packets = read_btsnoop(_capture(
        _record(0, False, _connected(65)),
        _record(1, True, _att(65, WRITE_0021)),
        _record(3.1, True, _att(65, WRITE_0021)),
        _record(4, True, _att(65, WRITE_0021)),
        _record(4, False, _disconnected(65, 0x13)),
    ), timezone.utc)

    def at(seconds: float) -> datetime:
        return BASE.replace(tzinfo=None) + timedelta(seconds=seconds)

    changes = [
        HolderChange(at(0.1), "79:60", ("net.example.first",)),
        HolderChange(at(3), "79:60", ("com.example.other", "net.example.first")),
        HolderChange(at(3.05), "79:60", ("net.example.first",)),
        HolderChange(at(2), "D9:B7", ("com.example.other",)),
    ]

    result = [(w.holders, sum(w.sent.values())) for w in windows(connections(packets)[0], changes)]

    assert result == [
        (None, 0),
        (("net.example.first",), 1),
        (("com.example.other", "net.example.first"), 0),
        (("net.example.first",), 2),
    ]
