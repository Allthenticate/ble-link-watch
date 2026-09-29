"""Read an Android HCI snoop log: what the phone sent on each LE link, and which apps held the link then.

Input is either an `adb bugreport` zip or a bare `btsnoop_hci.log`. A bugreport also carries
`dumpsys bluetooth_manager`, whose `stack::gatt` history records who held each link on the phone's own
clock, so a bugreport alone is enough to attribute every ATT PDU to the apps holding the link when it
was sent. For a bare log, pass the `linkwatch phone` log instead.

When several apps hold a link, the stack sends all their requests over the same channel with nothing to
say whose request is whose.
"""

from __future__ import annotations

import json
import re
import struct
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo

from linkwatch import dumpsys

# btsnoop timestamps count microseconds from midnight, 1 January of year 0; this is 1970-01-01 in them.
# https://fte.com/webhelpii/hsu/Content/Technical_Information/BT_Snoop_File_Format.htm
_EPOCH_DELTA_US = 0x00DCDDB30F2F8000
_DATALINK_H4 = 1002
_H4_ACL, _H4_EVENT = 0x02, 0x04
_EVT_DISCONNECTION_COMPLETE, _EVT_LE_META = 0x05, 0x3E
_LE_CONNECTION_COMPLETE = {0x01, 0x0A, 0x29}  # legacy, enhanced v1, enhanced v2: same leading fields
_ATT_CID = 0x0004
_PB_CONTINUATION = 0b01

ATT_OPCODES = {
    0x01: "Error Response", 0x02: "Exchange MTU Request", 0x03: "Exchange MTU Response",
    0x04: "Find Information Request", 0x05: "Find Information Response",
    0x06: "Find By Type Value Request", 0x07: "Find By Type Value Response",
    0x08: "Read By Type Request", 0x09: "Read By Type Response", 0x0A: "Read Request", 0x0B: "Read Response",
    0x0C: "Read Blob Request", 0x0D: "Read Blob Response", 0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response", 0x10: "Read By Group Type Request", 0x11: "Read By Group Type Response",
    0x12: "Write Request", 0x13: "Write Response", 0x16: "Prepare Write Request",
    0x17: "Prepare Write Response", 0x18: "Execute Write Request", 0x19: "Execute Write Response",
    0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication", 0x1E: "Handle Value Confirmation",
    0x20: "Read Multiple Variable Request", 0x21: "Read Multiple Variable Response",
    0x23: "Multiple Handle Value Notification", 0x52: "Write Command", 0xD2: "Signed Write Command",
}
_HANDLE_FIRST = {0x0A, 0x0C, 0x12, 0x16, 0x1B, 0x1D, 0x52, 0xD2}
CLIENT_REQUESTS = {0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x16, 0x18, 0x20, 0x52, 0xD2}

# Core specification Vol 1 Part F, controller error codes.
REASONS = {
    0x08: "Connection Timeout", 0x13: "Remote User Terminated", 0x16: "Terminated by Local Host",
    0x3B: "Unacceptable Connection Parameters", 0x3D: "MIC Failure", 0x3E: "Failed to be Established",
}
_ADDRESS_TYPES = {0: "public", 1: "random", 2: "public identity", 3: "random identity"}
UNKNOWN_PEER = "??:??:??:??:??:??"


@dataclass(frozen=True)
class Packet:
    """One HCI packet; `sent` is host to controller, i.e. from the phone."""

    at: datetime
    sent: bool
    data: bytes


@dataclass(frozen=True)
class Pdu:
    """One ATT PDU on a connection."""

    at: datetime
    sent: bool
    opcode: int
    attribute: int | None = None

    @property
    def name(self) -> str:
        """The opcode's name in the Core specification, with the attribute handle it targets if it has one."""
        name = ATT_OPCODES.get(self.opcode, f"opcode 0x{self.opcode:02x}")
        return name if self.attribute is None else f"{name} 0x{self.attribute:04x}"


@dataclass
class Connection:
    """One LE connection from its Connection Complete event to its Disconnection Complete."""

    handle: int
    peer: str
    peer_type: str
    opened: datetime
    closed: datetime | None = None
    reason: int | None = None
    pdus: list[Pdu] = field(default_factory=list)

    @property
    def suffix(self) -> str | None:
        """The two address bytes dumpsys keeps; None when the peer is unknown."""
        return None if self.peer == UNKNOWN_PEER else dumpsys.normalize_suffix(self.peer)


@dataclass(frozen=True)
class HolderChange:
    """From `at` (naive phone-local time) on, `holders` held the link to the device ending in `suffix`."""

    at: datetime
    suffix: str
    holders: tuple[str, ...]


@dataclass(frozen=True)
class Window:
    """A stretch of one connection during which the same apps held it."""

    start: datetime
    end: datetime
    holders: tuple[str, ...] | None
    sent: Counter
    received: Counter


def read_btsnoop(data: bytes, tz: tzinfo) -> list[Packet]:
    """Decode an H4 btsnoop file into packets stamped with naive local time in `tz`; ValueError if not one."""
    if data[:8] != b"btsnoop\x00":
        raise ValueError("not a btsnoop file")
    _version, datalink = struct.unpack(">II", data[8:16])
    if datalink != _DATALINK_H4:
        raise ValueError(f"btsnoop datalink {datalink} is not H4 ({_DATALINK_H4})")
    packets = []
    offset = 16
    while offset + 24 <= len(data):
        _orig, included, flags, _drops, stamp = struct.unpack(">IIIIq", data[offset:offset + 24])
        offset += 24
        payload = data[offset:offset + included]
        offset += included
        if len(payload) < included:
            break  # the phone was still writing the last record
        utc = datetime.fromtimestamp((stamp - _EPOCH_DELTA_US) / 1e6, timezone.utc)
        packets.append(Packet(utc.astimezone(tz).replace(tzinfo=None), sent=not flags & 1, data=payload))
    return packets


def _address(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in reversed(raw))


def connections(packets: list[Packet]) -> list[Connection]:
    """Rebuild LE connections and their ATT PDUs; a handle may be reused once its connection has closed."""
    open_: dict[int, Connection] = {}
    done: list[Connection] = []
    for p in packets:
        kind, body = p.data[0], p.data[1:]
        if kind == _H4_EVENT and len(body) >= 2:
            code, params = body[0], body[2:]
            if code == _EVT_LE_META and len(params) >= 12 and params[0] in _LE_CONNECTION_COMPLETE:
                status, handle, addr_type = params[1], struct.unpack("<H", params[2:4])[0], params[5]
                if status == 0:
                    if handle in open_:
                        done.append(open_.pop(handle))
                    open_[handle] = Connection(handle, _address(params[6:12]),
                                               _ADDRESS_TYPES.get(addr_type, str(addr_type)), p.at)
            elif code == _EVT_DISCONNECTION_COMPLETE and len(params) >= 4 and params[0] == 0:
                handle = struct.unpack("<H", params[1:3])[0]
                if conn := open_.pop(handle, None):
                    conn.closed, conn.reason = p.at, params[3]
                    done.append(conn)
        elif kind == _H4_ACL and len(body) >= 9:
            header = struct.unpack("<H", body[:2])[0]
            handle, boundary = header & 0x0FFF, (header >> 12) & 0b11
            if boundary == _PB_CONTINUATION or struct.unpack("<H", body[6:8])[0] != _ATT_CID:
                continue
            if (conn := open_.get(handle)) is None:
                conn = open_[handle] = Connection(handle, UNKNOWN_PEER, "opened before the capture", p.at)
            opcode = body[8]
            has_attribute = opcode in _HANDLE_FIRST and len(body) >= 11
            attribute = struct.unpack("<H", body[9:11])[0] if has_attribute else None
            conn.pdus.append(Pdu(p.at, p.sent, opcode, attribute))
    done.extend(open_.values())
    return sorted(done, key=lambda c: c.opened)


def windows(conn: Connection, changes: list[HolderChange]) -> list[Window]:
    """Split a connection at each holder change for its device; holders are None until the first is known."""
    mine = sorted((c for c in changes if c.suffix == conn.suffix), key=lambda c: c.at)
    end = conn.closed or max([conn.opened, *(p.at for p in conn.pdus)])
    current = None
    for c in mine:
        if c.at <= conn.opened:
            current = c.holders
    edges = [(conn.opened, current)] + [(c.at, c.holders) for c in mine if conn.opened < c.at < end]

    merged: list[Window] = []
    for i, (start, holders) in enumerate(edges):
        last = i + 1 == len(edges)
        stop = end if last else edges[i + 1][0]
        pdus = [p for p in conn.pdus if start <= p.at < stop or (last and p.at == stop)]
        sent = Counter(p.name for p in pdus if p.sent and p.opcode in CLIENT_REQUESTS)
        received = Counter(p.name for p in pdus if not p.sent)
        if merged and merged[-1].holders == holders:
            prev = merged.pop()
            start, sent, received = prev.start, prev.sent + sent, prev.received + received
        merged.append(Window(start, stop, holders, sent, received))
    return merged


def holder_changes_from_dumpsys(text: str) -> list[HolderChange]:
    """The `stack::gatt` history in a dumpsys; it keeps only the last 100 transitions, across all devices."""
    transitions = dumpsys.parse(text).transitions
    return [HolderChange(t.at, t.suffix, tuple(h.package for h in t.holders)) for t in transitions]


def holder_changes_from_phone_log(path: Path) -> list[HolderChange]:
    """Holder changes from a `linkwatch phone` log, on its phone-corrected clock."""
    changes = []
    for line in path.read_text().splitlines():
        r = json.loads(line) if line.strip() else {}
        if r.get("event") == "holders_changed":
            at = datetime.fromisoformat(r.get("host_time") or r["ts"]).replace(tzinfo=None)
            changes.append(HolderChange(at, r["suffix"], tuple(r["holders"])))
    return changes


_BTSNOOP_MEMBERS = (
    "FS/data/misc/bluetooth/logs/btsnoop_hci.log.last",
    "FS/data/misc/bluetooth/logs/btsnoop_hci.log",
)
_TIMEZONE = re.compile(rb"^\[persist\.sys\.timezone\]: \[([^\]]+)\]", re.MULTILINE)


def _bugreport_dumpsys(report: bytes) -> str:
    start = report.find(b"DUMP OF SERVICE bluetooth_manager:")
    if start < 0:
        return ""
    end = report.find(b"was the duration of dumpsys bluetooth_manager", start)
    return report[start:end if end > 0 else None].decode("utf-8", "replace")


def _zone(name: str | None) -> tzinfo:
    return ZoneInfo(name) if name else datetime.now().astimezone().tzinfo


def load(path: Path, tz_name: str | None = None) -> tuple[list[Packet], list[HolderChange], tzinfo]:
    """Packets, holder history and the timezone used, which defaults to the phone's, then this machine's."""
    if not zipfile.is_zipfile(path):
        tz = _zone(tz_name)
        return read_btsnoop(path.read_bytes(), tz), [], tz

    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        report_name = next((n for n in names if re.fullmatch(r"bugreport-.*\.txt", n)), None)
        report = z.read(report_name) if report_name else b""
        if not tz_name and (m := _TIMEZONE.search(report)):
            tz_name = m.group(1).decode()
        tz = _zone(tz_name)
        members = [m for m in _BTSNOOP_MEMBERS if m in names]
        packets = [p for member in members for p in read_btsnoop(z.read(member), tz)]
    if not packets:
        raise SystemExit(f"{path} has no btsnoop log: enable the HCI snoop log and restart Bluetooth first")
    return packets, holder_changes_from_dumpsys(_bugreport_dumpsys(report)), tz


def _duration(delta: timedelta) -> str:
    seconds = delta.total_seconds()
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 120:
        return f"{seconds:.1f} s"
    return f"{seconds / 60:.1f} min"


def _counts(counter: Counter) -> str:
    return ", ".join(f"{name} x{n}" for name, n in counter.most_common()) or "nothing"


def _clock(at: datetime) -> str:
    return f"{at:%H:%M:%S.%f}"[:-3]


def render(conns: list[Connection], changes: list[HolderChange]) -> str:
    """One block per connection: how it opened and closed, then each holder window and the ATT in it."""
    lines = []
    for conn in conns:
        if conn.closed:
            reason = REASONS.get(conn.reason, f"0x{conn.reason:02x}")
            ending = f"{_duration(conn.closed - conn.opened)}, closed {_clock(conn.closed)} ({reason})"
        else:
            ending = "still open at the end of the capture"
        lines.append(f"{conn.opened:%Y-%m-%d} {_clock(conn.opened)}  {conn.peer} ({conn.peer_type})"
                     f"  handle {conn.handle}  {ending}")
        for w in windows(conn, changes):
            who = "holders unknown" if w.holders is None else (", ".join(w.holders) or "no app")
            lines.append(f"    {_clock(w.start)} {_duration(w.end - w.start):>9}  {who}")
            lines.append(f"        phone sent: {_counts(w.sent)}")
            if w.received:
                lines.append(f"        received:   {_counts(w.received)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main(source: Path, phone_log: Path | None, peer: str | None, tz_name: str | None) -> None:
    """Print the per-connection report for one capture."""
    packets, changes, tz = load(source, tz_name)
    if phone_log:
        changes += holder_changes_from_phone_log(phone_log)
    conns = connections(packets)
    if peer:
        conns = [c for c in conns if c.suffix == dumpsys.normalize_suffix(peer)]
    span = f"{packets[0].at:%Y-%m-%d %H:%M:%S} to {packets[-1].at:%H:%M:%S} {tz}" if packets else "empty"
    print(f"{len(packets)} packets, {span}; {len(conns)} LE connections, {len(changes)} holder changes\n")
    print(render(conns, changes))
