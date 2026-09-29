"""A Bluetooth LE peripheral for Linux (BlueZ) that logs everything a phone does to it.

It advertises, exposes a few characteristics that look worth reading, and writes one JSON line per
connection, disconnection, read, write and subscription, with the central's address, the ATT MTU
and the link type. BlueZ answers service discovery itself without calling this process, so
discovery is only visible in a packet capture (`sudo btmon -w peripheral.btsnoop`).
"""

import asyncio
import json
import logging
import os
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dbus_next import BusType, Message, Variant
from dbus_next.aio import MessageBus
from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method

BLUEZ = "org.bluez"
APP_PATH = "/org/linkwatch"

# Random 128-bit UUIDs for the bait service, generated for this tool.
BAIT_SERVICE = "7a1c0000-5b2e-4d7f-9c1a-2f6e8d3b4a10"
BAIT_READ = "7a1c0001-5b2e-4d7f-9c1a-2f6e8d3b4a10"
BAIT_WRITE = "7a1c0002-5b2e-4d7f-9c1a-2f6e8d3b4a10"
BAIT_NOTIFY = "7a1c0003-5b2e-4d7f-9c1a-2f6e8d3b4a10"
BAIT_ENCRYPTED = "7a1c0004-5b2e-4d7f-9c1a-2f6e8d3b4a10"
DEVICE_INFORMATION = "0000180a-0000-1000-8000-00805f9b34fb"
MANUFACTURER_NAME = "00002a29-0000-1000-8000-00805f9b34fb"
MODEL_NUMBER = "00002a24-0000-1000-8000-00805f9b34fb"
SERIAL_NUMBER = "00002a25-0000-1000-8000-00805f9b34fb"
BATTERY = "0000180f-0000-1000-8000-00805f9b34fb"
BATTERY_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"

# Advertising presets. Appearance values are from the Bluetooth Assigned Numbers "Appearance" table.
PROFILES: dict[str, dict[str, Any]] = {
    "plain": {"name": "linkwatch", "appearance": None, "services": [BAIT_SERVICE]},
    "laptop": {"name": "LAPTOP-7Q2K9", "appearance": 0x0083, "services": [BAIT_SERVICE]},
    "no-services": {"name": "LAPTOP-7Q2K9", "appearance": 0x0083, "services": []},
    "anonymous": {"name": None, "appearance": None, "services": [BAIT_SERVICE]},
    # A Windows 11 laptop running a GATT server advertises Device Information alongside its own service,
    # measured on a Surface Laptop in September 2026.
    "windows": {"name": "LAPTOP-7Q2K9", "appearance": None, "services": [DEVICE_INFORMATION]},
    "dis-only": {"name": "linkwatch", "appearance": None, "services": [DEVICE_INFORMATION]},
}


class Log:
    """Appends one JSON object per event to a file and echoes it to stdout."""

    def __init__(self, path: Path) -> None:
        self._file = path.open("a")

    def __call__(self, event: str, **fields: Any) -> None:
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")
        line = json.dumps({"ts": now, "source": "peripheral", "event": event, **fields})
        self._file.write(line + "\n")
        self._file.flush()
        print(line, flush=True)


def _options(options: dict[str, Variant]) -> dict[str, Any]:
    """The request options BlueZ passes to a read or write, as plain values."""
    return {k: (v.value if isinstance(v, Variant) else v) for k, v in options.items()}


class Characteristic(ServiceInterface):
    """An org.bluez.GattCharacteristic1 that logs every access; `value` is what a read returns."""

    def __init__(self, path: str, uuid: str, service: str, flags: list[str], value: bytes, label: str,
                 log: Log, devices: "DeviceNames") -> None:
        super().__init__("org.bluez.GattCharacteristic1")
        self.path, self._uuid, self._service, self._flags = path, uuid, service, flags
        self._value, self.label, self._log, self._devices = value, label, log, devices
        self._notifying = False

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":  # noqa: N802, F821
        opts = _options(options)
        offset = opts.get("offset", 0)
        self._log("read", characteristic=self.label, uuid=self._uuid, offset=offset,
                  **self._devices.describe(opts))
        return self._value[offset:]

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):  # noqa: N802, F821
        opts = _options(options)
        self._log("write", characteristic=self.label, uuid=self._uuid, value_hex=bytes(value).hex(),
                  value_text=bytes(value).decode("utf-8", "replace"), write_type=opts.get("type"),
                  **self._devices.describe(opts))

    @method()
    def StartNotify(self):  # noqa: N802
        self._notifying = True
        self._log("subscribe", characteristic=self.label, uuid=self._uuid)

    @method()
    def StopNotify(self):  # noqa: N802
        self._notifying = False
        self._log("unsubscribe", characteristic=self.label, uuid=self._uuid)

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":  # noqa: N802, F821
        return self._uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":  # noqa: N802, F821
        return self._service

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":  # noqa: N802, F821
        return self._flags

    def managed(self) -> dict[str, Variant]:
        return {"UUID": Variant("s", self._uuid), "Service": Variant("o", self._service),
                "Flags": Variant("as", self._flags)}


class Service(ServiceInterface):
    """An org.bluez.GattService1."""

    def __init__(self, path: str, uuid: str) -> None:
        super().__init__("org.bluez.GattService1")
        self.path, self._uuid = path, uuid
        self.characteristics: list[Characteristic] = []

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":  # noqa: N802, F821
        return self._uuid

    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> "b":  # noqa: N802, F821
        return True

    def managed(self) -> dict[str, Variant]:
        return {"UUID": Variant("s", self._uuid), "Primary": Variant("b", True)}


class Application(ServiceInterface):
    """The org.freedesktop.DBus.ObjectManager BlueZ reads the whole GATT tree from."""

    def __init__(self, services: list[Service]) -> None:
        super().__init__("org.freedesktop.DBus.ObjectManager")
        self._services = services

    @method()
    def GetManagedObjects(self) -> "a{oa{sa{sv}}}":  # noqa: N802, F821
        objects: dict[str, dict[str, dict[str, Variant]]] = {}
        for service in self._services:
            objects[service.path] = {"org.bluez.GattService1": service.managed()}
            for char in service.characteristics:
                objects[char.path] = {"org.bluez.GattCharacteristic1": char.managed()}
        return objects


class Advertisement(ServiceInterface):
    """An org.bluez.LEAdvertisement1 built from a profile."""

    def __init__(self, path: str, name: str | None, appearance: int | None, services: list[str],
                 log: Log) -> None:
        super().__init__("org.bluez.LEAdvertisement1")
        self.path, self._name, self._appearance, self._services, self._log = (
            path, name, appearance, services, log)

    @method()
    def Release(self):  # noqa: N802
        self._log("advertisement_released")

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":  # noqa: N802, F821
        return "peripheral"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":  # noqa: N802, F821
        return self._services

    @dbus_property(access=PropertyAccess.READ)
    def Discoverable(self) -> "b":  # noqa: N802, F821
        return True

    @dbus_property(access=PropertyAccess.READ)
    def Includes(self) -> "as":  # noqa: N802, F821
        # A legacy advertisement holds 31 bytes; TX power would crowd out the name.
        return []

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":  # noqa: N802, F821
        return self._name or ""

    @dbus_property(access=PropertyAccess.READ)
    def Appearance(self) -> "q":  # noqa: N802, F821
        return self._appearance if self._appearance is not None else 0


class DeviceNames:
    """Resolves the `device` object path BlueZ passes with a request to the central's address and name."""

    def __init__(self, bus: MessageBus) -> None:
        self._bus = bus
        self._cache: dict[str, dict[str, Any]] = {}

    def describe(self, opts: dict[str, Any]) -> dict[str, Any]:
        path = opts.get("device")
        out: dict[str, Any] = {"mtu": opts.get("mtu"), "link": opts.get("link")}
        if path:
            out["central"] = self._cache.get(path, {}).get("address") or path.rsplit("dev_", 1)[-1].replace("_", ":")
        return out

    def remember(self, path: str, props: dict[str, Any]) -> None:
        self._cache.setdefault(path, {}).update(props)


async def run(adapter: str, profile: str, name: str | None, log_path: Path) -> None:
    """Advertise and serve the bait GATT database until interrupted."""
    # BlueZ probes optional advertisement properties such as TxPower; the misses are expected.
    logging.getLogger("dbus_next").setLevel(logging.CRITICAL)
    log = Log(log_path)
    preset = dict(PROFILES[profile])
    if name is not None:
        preset["name"] = name

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    devices = DeviceNames(bus)
    adapter_path = f"/org/bluez/{adapter}"
    intro = await bus.introspect(BLUEZ, adapter_path)
    adapter_obj = bus.get_proxy_object(BLUEZ, adapter_path, intro)
    props = adapter_obj.get_interface("org.freedesktop.DBus.Properties")
    address = (await props.call_get("org.bluez.Adapter1", "Address")).value

    services: list[Service] = []

    def add_service(index: int, uuid: str, chars: list[tuple[str, list[str], bytes, str]]) -> None:
        svc = Service(f"{APP_PATH}/service{index}", uuid)
        for i, (cuuid, flags, value, label) in enumerate(chars):
            svc.characteristics.append(
                Characteristic(f"{svc.path}/char{i}", cuuid, svc.path, flags, value, label, log, devices))
        services.append(svc)

    add_service(0, BAIT_SERVICE, [
        (BAIT_READ, ["read"], b"linkwatch canary: if you can read this, an app read it", "bait_read"),
        (BAIT_WRITE, ["write", "write-without-response"], b"", "bait_write"),
        (BAIT_NOTIFY, ["read", "notify", "indicate"], b"\x00", "bait_notify"),
        (BAIT_ENCRYPTED, ["encrypt-read"], b"needs pairing", "bait_encrypted"),
    ])
    add_service(1, DEVICE_INFORMATION, [
        (MANUFACTURER_NAME, ["read"], b"Linkwatch Labs", "manufacturer_name"),
        (MODEL_NUMBER, ["read"], b"LW-1", "model_number"),
        (SERIAL_NUMBER, ["read"], b"LW-000042", "serial_number"),
    ])
    add_service(2, BATTERY, [(BATTERY_LEVEL, ["read", "notify"], bytes([87]), "battery_level")])

    app = Application(services)
    bus.export(APP_PATH, app)
    for svc in services:
        bus.export(svc.path, svc)
        for char in svc.characteristics:
            bus.export(char.path, char)

    adv = Advertisement(f"{APP_PATH}/advertisement0", preset["name"], preset["appearance"], preset["services"], log)
    bus.export(adv.path, adv)

    gatt = adapter_obj.get_interface("org.bluez.GattManager1")
    adv_mgr = adapter_obj.get_interface("org.bluez.LEAdvertisingManager1")

    await gatt.call_register_application(APP_PATH, {})
    await adv_mgr.call_register_advertisement(adv.path, {})
    log("start", adapter=adapter, address=address, profile=profile, name=preset["name"],
        appearance=preset["appearance"], advertised_services=preset["services"], pid=os.getpid())

    # Connections and disconnections arrive as Device1 property changes on the adapter's devices.
    def on_signal(msg) -> None:  # noqa: ANN001
        if msg.member == "PropertiesChanged" and msg.path.startswith(adapter_path + "/dev_"):
            iface, changed = msg.body[0], msg.body[1]
            if iface != "org.bluez.Device1":
                return
            values = _options(changed)
            devices.remember(msg.path, {k.lower(): v for k, v in values.items() if k in ("Address", "Name")})
            if "Connected" in values:
                log("connected" if values["Connected"] else "disconnected",
                    central=msg.path.rsplit("dev_", 1)[-1].replace("_", ":"))
            if "ServicesResolved" in values:
                log("services_resolved", central=msg.path.rsplit("dev_", 1)[-1].replace("_", ":"),
                    resolved=values["ServicesResolved"])

    await bus.call(Message(
        destination="org.freedesktop.DBus", path="/org/freedesktop/DBus", interface="org.freedesktop.DBus",
        member="AddMatch", signature="s",
        body=[f"type='signal',sender='{BLUEZ}',interface='org.freedesktop.DBus.Properties',"
              f"path_namespace='{adapter_path}'"]))
    bus.add_message_handler(on_signal)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()

    try:
        await adv_mgr.call_unregister_advertisement(adv.path)
        await gatt.call_unregister_application(APP_PATH)
    finally:
        log("stop")
        bus.disconnect()
