"""Parse `adb shell dumpsys bluetooth_manager` into who holds which Bluetooth LE link.

Android masks all but the last two bytes of every address in this dump (``xx:xx:xx:xx:73:f0``), so a
device is identified here by that two-byte suffix, upper-cased (``73:F0``). The formats below were
read from Android 17 (Pixel 10, September 2026); older releases lay some sections out differently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

_SUFFIX = r"(?:[0-9A-Fa-f]{2}:){4,5}([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})"
_MASKED = r"[Xx]{2}(?::[Xx]{2}){3}:([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})"

# `  id: 0  address: xx:xx:xx:xx:93:e2  transport: BT_TRANSPORT_LE  ch_state: GATT_CH_OPEN, ACL holders app_id: a (66), b (65), `
_TCB = re.compile(rf"^\s+id: \d+\s+address: {_MASKED}\s+transport: (\S+)\s+ch_state: (\w+), (.*)$")
# `stack::gatt    2026-09-26 22:13:39.987 xx:xx:xx:xx:93:e2, BT_TRANSPORT_LE, state: GATT_CH_OPEN, ACL holders app_id: ... `
_TRANSITION = re.compile(
    rf"^stack::gatt\s+(\d{{4}}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) {_MASKED}, (\S+), state: (\w+), (.*)$"
)
_HOLDER = re.compile(r"([\w.:]+) \((\d+)\)")
# `    XX:XX:XX:XX:93:E2(Public) => XX:XX:XX:XX:XX:XX(Unknown) [ ???? ] [0x001F00] ... [ Encryption status(...) ] LAPTOP-WIN`
_DEVICE = re.compile(rf"^\s{{4}}{_MASKED}\((\w+)\) => \S+ \[\s*([^\]]*?)\s*\] .*\] ?(.*)$")
_PACKAGES = re.compile(r"^\s+\[Packages\s*\]: \[(.*)\]$")
# `      app_if: 65, appName: com.life360.android.safetymapd, transport: LE`
_APP = re.compile(r"^\s+app_if: (\d+), appName: ([^,]+), transport: (\w+)(?:, tag: (\S+))?")
# `        Connection(connId=65, XX:XX:XX:XX:93:E2, LE, appId=65)`
_CONNECTION = re.compile(rf"^\s+Connection\(connId=(\d+), {_MASKED}, (\w+), appId=(\d+)\)")


@dataclass(frozen=True)
class Holder:
    """An app holding an LE link open, with the GATT client interface it holds it through."""

    package: str
    app_id: int


@dataclass(frozen=True)
class Link:
    """An open LE link as the GATT stack reports it at the moment of the dump."""

    suffix: str
    transport: str
    state: str
    holders: tuple[Holder, ...]


@dataclass(frozen=True)
class Transition:
    """One entry of the stack's own history of link-holder changes, stamped with the phone's clock."""

    at: datetime
    suffix: str
    state: str
    holders: tuple[Holder, ...]


@dataclass
class Device:
    """A remote device the phone knows about."""

    suffix: str
    address_type: str
    device_type: str
    name: str
    bonded: bool
    packages: list[str] = field(default_factory=list)


@dataclass
class GattClient:
    """A GATT client interface an app registered, and the devices it is connected to through it."""

    app_if: int
    package: str
    transport: str
    tag: str | None
    connections: list[str] = field(default_factory=list)


@dataclass
class Snapshot:
    """Everything this module reads out of one dump."""

    links: dict[str, Link]
    transitions: list[Transition]
    devices: dict[str, Device]
    clients: list[GattClient]

    def holders(self, suffix: str) -> tuple[Holder, ...]:
        """Apps holding the link to `suffix` right now; empty if no link is open."""
        link = self.links.get(suffix.upper())
        return link.holders if link else ()


def _holders(text: str) -> tuple[Holder, ...]:
    if "No ACL holders" in text:
        return ()
    return tuple(Holder(pkg, int(app_id)) for pkg, app_id in _HOLDER.findall(text.split("app_id:", 1)[-1]))


def parse(dump: str) -> Snapshot:
    """Parse the text of one `dumpsys bluetooth_manager`."""
    links: dict[str, Link] = {}
    transitions: list[Transition] = []
    devices: dict[str, Device] = {}
    clients: list[GattClient] = []

    section = None
    last_device: Device | None = None
    in_gatt_clients = False
    client: GattClient | None = None

    for line in dump.splitlines():
        stripped = line.strip()
        if stripped.startswith("Bonded devices:"):
            section = "bonded"
            continue
        if stripped.startswith("Other devices:"):
            section = "other"
            continue
        if not stripped or stripped.startswith("Connected devices:"):
            section = None
            last_device = None

        if section in ("bonded", "other"):
            if m := _DEVICE.match(line):
                suffix = m.group(1).upper()
                last_device = Device(
                    suffix=suffix,
                    address_type=m.group(2),
                    device_type=m.group(3).strip() or "?",
                    name=m.group(4).strip(),
                    bonded=section == "bonded",
                )
                devices.setdefault(suffix, last_device)
                continue
            if last_device and (m := _PACKAGES.match(line)):
                last_device.packages = [p.strip() for p in m.group(1).split(",") if p.strip()]
                continue

        if stripped == "Client:":
            in_gatt_clients = True
            continue
        if stripped in ("Server:", "GATT Advertiser Map:"):
            in_gatt_clients = False
            client = None
        if in_gatt_clients:
            if m := _APP.match(line):
                client = GattClient(int(m.group(1)), m.group(2).strip(), m.group(3), m.group(4))
                clients.append(client)
                continue
            if client and (m := _CONNECTION.match(line)):
                client.connections.append(m.group(2).upper())
                continue

        if m := _TCB.match(line):
            suffix = m.group(1).upper()
            links[suffix] = Link(suffix, m.group(2), m.group(3), _holders(m.group(4)))
            continue
        if m := _TRANSITION.match(line):
            transitions.append(
                Transition(
                    at=datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f"),
                    suffix=m.group(2).upper(),
                    state=m.group(4),
                    holders=_holders(m.group(5)),
                )
            )

    return Snapshot(links=links, transitions=transitions, devices=devices, clients=clients)


def normalize_suffix(address: str) -> str:
    """The two-byte suffix dumpsys keeps of a full or masked address, e.g. ``84:7B:57:57:79:60`` -> ``79:60``."""
    m = re.search(_SUFFIX, address) or re.search(_MASKED, address)
    if m:
        return m.group(1).upper()
    parts = address.strip().split(":")
    if len(parts) >= 2:
        return ":".join(parts[-2:]).upper()
    raise ValueError(f"not a Bluetooth address: {address!r}")
