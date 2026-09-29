"""A Bluetooth LE bait peripheral for Windows 10/11 that logs every read, write and subscription.

Needs Python 3.12 and the WinRT projections:

    pip install winrt-runtime winrt-Windows.Devices.Bluetooth winrt-Windows.Devices.Bluetooth.GenericAttributeProfile \
        winrt-Windows.Devices.Bluetooth.Advertisement winrt-Windows.Foundation winrt-Windows.Storage.Streams

or `--winrt-path DIR` to import them from an existing directory that has a `winrt` package in it.

Windows tells a GATT server which central sent each request (`session.device_id`, which embeds the phone's
address) but, like any peripheral, not which app on that phone sent it.
"""

import argparse
import asyncio
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

BAIT_SERVICE = "7a1c0000-5b2e-4d7f-9c1a-2f6e8d3b4a10"
CHARACTERISTICS = [
    # uuid, label, properties, value returned on read
    ("7a1c0001-5b2e-4d7f-9c1a-2f6e8d3b4a10", "bait_read", ("read",),
     b"linkwatch canary: if you can read this, an app read it"),
    ("7a1c0002-5b2e-4d7f-9c1a-2f6e8d3b4a10", "bait_write", ("write", "write_without_response"), b""),
    ("7a1c0003-5b2e-4d7f-9c1a-2f6e8d3b4a10", "bait_notify", ("read", "notify", "indicate"), b"\x00"),
    ("7a1c0005-5b2e-4d7f-9c1a-2f6e8d3b4a10", "bait_model", ("read",), b"Linkwatch LW-1 serial LW-000042"),
]


class Log:
    """One JSON line per event, to a file and stdout; safe to call from WinRT callback threads."""

    def __init__(self, path: Path) -> None:
        self._file = path.open("a", encoding="utf-8")
        self._lock = threading.Lock()

    def __call__(self, event: str, **fields) -> None:
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")
        line = json.dumps({"ts": now, "source": "windows-peripheral", "event": event, **fields})
        with self._lock:
            self._file.write(line + "\n")
            self._file.flush()
            print(line, flush=True)


def _central(session) -> dict:
    """The requesting central's WinRT device id, the phone address inside it, and the ATT MTU."""
    device_id = session.device_id.id if session and session.device_id else None
    address = device_id.rsplit("-", 1)[-1].upper() if device_id and "-" in device_id else None
    mtu = session.max_pdu_size if session else None
    return {"central": address, "device_id": device_id, "mtu": mtu}


async def _wait(op):
    """Result of a WinRT async operation, polled so no Python wrapper module is needed to await it."""
    while int(op.status) == 0:  # AsyncStatus.Started
        await asyncio.sleep(0.01)
    if int(op.status) != 1:  # AsyncStatus.Completed
        raise OSError(f"WinRT operation ended with status {int(op.status)}: {op.error_code}")
    return op.get_results()


def _stay_awake() -> None:
    """Hold the system and display awake for as long as this process runs; Windows drops it on exit."""
    import ctypes

    es_continuous, es_system_required, es_display_required = 0x80000000, 0x00000001, 0x00000002
    ctypes.windll.kernel32.SetThreadExecutionState(es_continuous | es_system_required | es_display_required)


async def run(log: Log, stop: asyncio.Event) -> None:
    """Publish the bait service and advertise it until `stop` is set."""
    import uuid

    try:
        from winrt.windows.devices.bluetooth.genericattributeprofile import (
            GattLocalCharacteristicParameters,
            GattServiceProvider,
            GattServiceProviderAdvertisingParameters,
        )
        from winrt.windows.storage.streams import DataReader, DataWriter
    except ImportError:
        # A PyInstaller bundle keeps only the compiled projections on disk; the Python wrappers that
        # define the enum classes live inside its executable, so the enums are used by value below.
        from winrt._winrt_windows_devices_bluetooth_genericattributeprofile import (
            GattLocalCharacteristicParameters,
            GattServiceProvider,
            GattServiceProviderAdvertisingParameters,
        )
        from winrt._winrt_windows_storage_streams import DataReader, DataWriter

    # Values of the WinRT enums, fixed by the Windows SDK:
    # https://learn.microsoft.com/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattcharacteristicproperties
    success = 0  # BluetoothError.Success
    plain = 0  # GattProtectionLevel.Plain
    write_with_response = 0  # GattWriteOption.WriteWithResponse
    props = {"read": 0x02, "write_without_response": 0x04, "write": 0x08, "notify": 0x10, "indicate": 0x20}
    statuses = {0: "CREATED", 1: "STOPPED", 2: "STARTED", 3: "ABORTED", 4: "STARTED_WITHOUT_ALL_ADVERTISEMENT_DATA"}

    result = await _wait(GattServiceProvider.create_async(uuid.UUID(BAIT_SERVICE)))
    if int(result.error) != success:
        raise SystemExit(f"could not create the GATT service provider: error {int(result.error)}")
    provider = result.service_provider

    def on_read(label: str, value: bytes):
        def handler(_sender, args) -> None:
            async def respond() -> None:
                deferral = args.get_deferral()
                request = await _wait(args.get_request_async())
                log("read", characteristic=label, offset=request.offset, **_central(args.session))
                writer = DataWriter()
                writer.write_bytes(value[request.offset:])
                request.respond_with_value(writer.detach_buffer())
                deferral.complete()

            asyncio.run(respond())

        return handler

    def on_write(label: str):
        def handler(_sender, args) -> None:
            async def accept() -> None:
                deferral = args.get_deferral()
                request = await _wait(args.get_request_async())
                reader = DataReader.from_buffer(request.value)
                data = bytes(reader.read_buffer(reader.unconsumed_buffer_length)) if request.value else b""
                log("write", characteristic=label, value_hex=data.hex(),
                    value_text=data.decode("utf-8", "replace"),
                    with_response=int(request.option) == write_with_response,
                    **_central(args.session))
                if int(request.option) == write_with_response:
                    request.respond()
                deferral.complete()

            asyncio.run(accept())

        return handler

    def on_subscribers(label: str):
        def handler(sender, _args) -> None:
            clients = [_central(c.session) for c in sender.subscribed_clients]
            log("subscribers_changed", characteristic=label, subscribers=clients)

        return handler

    for cuuid, label, flags, value in CHARACTERISTICS:
        params = GattLocalCharacteristicParameters()
        combined = 0
        for flag in flags:
            combined |= props[flag]
        params.characteristic_properties = combined
        params.read_protection_level = plain
        params.write_protection_level = plain
        created = await _wait(provider.service.create_characteristic_async(uuid.UUID(cuuid), params))
        if int(created.error) != success:
            raise SystemExit(f"could not create {label}: error {int(created.error)}")
        char = created.characteristic
        if "read" in flags:
            char.add_read_requested(on_read(label, value))
        if "write" in flags:
            char.add_write_requested(on_write(label))
        if "notify" in flags:
            char.add_subscribed_clients_changed(on_subscribers(label))

    def on_status(_sender, args) -> None:
        log("advertisement_status", status=statuses.get(int(args.status), int(args.status)), error=int(args.error))

    provider.add_advertisement_status_changed(on_status)
    adv = GattServiceProviderAdvertisingParameters()
    adv.is_discoverable = True
    adv.is_connectable = True
    provider.start_advertising_with_parameters(adv)
    _stay_awake()
    log("start", service=BAIT_SERVICE, characteristics=[c[1] for c in CHARACTERISTICS])

    await stop.wait()
    provider.stop_advertising()
    log("stop")


def _build_shim(winrt_path: Path) -> str:
    """Stand in for the `winrt.windows.*` wrapper modules a PyInstaller bundle keeps inside its executable.

    Each stand-in re-exports the compiled projection on disk, maps an interface name to the compiled
    `_I...` type, and answers any other name, which the compiled code only asks for to wrap enum values,
    with `int`.
    """
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="linkwatch-winrt-"))
    for pyd in (winrt_path / "winrt").glob("_winrt_windows_*.pyd"):
        dotted = pyd.name.split(".")[0].removeprefix("_winrt_").replace("_", ".")
        # "windows.devices.bluetooth.genericattributeprofile" etc.; package dirs need an __init__.py each.
        parts = dotted.split(".")
        for depth in range(1, len(parts) + 1):
            pkg = root / "winrt" / Path(*parts[:depth])
            pkg.mkdir(parents=True, exist_ok=True)
            init = pkg / "__init__.py"
            if not init.exists():
                init.write_text("def __getattr__(name):\n    return int\n")
        module = pyd.name.split(".")[0]
        (root / "winrt" / Path(*parts) / "__init__.py").write_text(
            f"import winrt.{module} as _compiled\n"
            f"from winrt.{module} import *  # noqa: F401,F403\n\n\n"
            "def __getattr__(name):\n"
            "    # Interfaces are compiled under a leading underscore; anything else is an enum.\n"
            "    return getattr(_compiled, name, None) or getattr(_compiled, '_' + name, int)\n"
        )
    return str(root)


def main() -> None:
    """Parse arguments and run until Ctrl-C."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, default=Path("windows-peripheral.jsonl"))
    parser.add_argument("--winrt-path", type=Path, help="directory containing an importable `winrt` package")
    parser.add_argument("--seconds", type=float, help="stop after this long instead of waiting for Ctrl-C")
    args = parser.parse_args()
    if args.winrt_path:
        sys.path.append(str(args.winrt_path))
        try:
            import winrt.windows.foundation  # noqa: F401
        except ImportError:
            sys.path.append(_build_shim(args.winrt_path))

    async def go() -> None:
        stop = asyncio.Event()
        if args.seconds:
            asyncio.get_running_loop().call_later(args.seconds, stop.set)
        try:
            await run(Log(args.log), stop)
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
