"""Watch an Android phone over adb and log every change in which apps hold which Bluetooth LE links."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from linkwatch.dumpsys import Snapshot, parse


def _adb(serial: str | None, *args: str, timeout: float = 30) -> str:
    cmd = ["adb", *(["-s", serial] if serial else []), *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout).stdout


def phone_clock_offset(serial: str | None) -> float:
    """Seconds to add to the phone's clock to get this host's clock, measured around one `date` call."""
    before = time.time()
    phone = float(_adb(serial, "shell", "date", "+%s.%N").strip())
    after = time.time()
    return (before + after) / 2 - phone


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")


def _holders(snap: Snapshot, suffix: str) -> list[str]:
    return sorted({h.package for h in snap.holders(suffix)})


def watch(out: Path, serial: str | None, interval: float, focus: str | None) -> None:
    """Poll the phone every `interval` seconds and append one JSON line per change to `out`."""
    offset = phone_clock_offset(serial)
    seen_transitions: set[tuple] = set()
    previous: dict[str, list[str]] = {}
    with out.open("a") as log:

        def emit(event: str, **fields) -> None:
            record = {"ts": _now(), "source": "phone", "event": event, **fields}
            log.write(json.dumps(record) + "\n")
            log.flush()
            print(json.dumps(record), flush=True)

        emit("start", serial=serial, phone_clock_offset_s=round(offset, 3), interval_s=interval, focus=focus)
        while True:
            try:
                snap = parse(_adb(serial, "shell", "dumpsys", "bluetooth_manager"))
            except (subprocess.SubprocessError, OSError) as e:
                emit("adb_error", error=str(e))
                time.sleep(interval)
                continue

            for t in snap.transitions:
                key = (t.at, t.suffix, t.state, t.holders)
                if key in seen_transitions:
                    continue
                seen_transitions.add(key)
                if focus and t.suffix != focus:
                    continue
                emit(
                    "holders_changed",
                    suffix=t.suffix,
                    name=snap.devices[t.suffix].name if t.suffix in snap.devices else None,
                    state=t.state,
                    holders=sorted({h.package for h in t.holders}),
                    phone_time=t.at.isoformat(timespec="milliseconds"),
                    host_time=datetime.fromtimestamp(t.at.timestamp() + offset).isoformat(timespec="milliseconds"),
                )

            current = {s: _holders(snap, s) for s in snap.links}
            for suffix in sorted(set(current) | set(previous)):
                if focus and suffix != focus:
                    continue
                if current.get(suffix) != previous.get(suffix):
                    dev = snap.devices.get(suffix)
                    emit(
                        "link_state",
                        suffix=suffix,
                        name=dev.name if dev else None,
                        bonded=dev.bonded if dev else None,
                        open=suffix in current,
                        holders=current.get(suffix, []),
                        apps_that_used_device=dev.packages if dev else [],
                    )
            previous = current
            time.sleep(interval)


def snapshot(serial: str | None) -> None:
    """Print the current links, holders and known devices once, as JSON."""
    snap = parse(_adb(serial, "shell", "dumpsys", "bluetooth_manager"))
    json.dump(
        {
            "links": {s: [asdict(h) for h in link.holders] for s, link in snap.links.items()},
            "devices": {s: asdict(d) for s, d in snap.devices.items()},
            "gatt_clients": [asdict(c) for c in snap.clients],
        },
        sys.stdout,
        indent=2,
    )
    print()
