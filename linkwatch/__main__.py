"""Command line: `linkwatch peripheral|phone|snapshot|report`."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path


def main() -> None:
    """Parse arguments and run one subcommand."""
    parser = argparse.ArgumentParser(prog="linkwatch", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("peripheral", help="advertise a bait GATT server and log every access (Linux, BlueZ)")
    p.add_argument("--adapter", default="hci0")
    p.add_argument("--profile", default="plain", help="plain, laptop, no-services, anonymous")
    p.add_argument("--name", help="override the advertised name")
    p.add_argument("--log", type=Path, default=Path("peripheral.jsonl"))

    p = sub.add_parser("phone", help="poll an Android phone over adb and log link-holder changes")
    p.add_argument("--serial", help="adb serial, if more than one device is attached")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between polls")
    p.add_argument("--focus", help="only log this device, by address or its last two bytes")
    p.add_argument("--log", type=Path, default=Path("phone.jsonl"))

    p = sub.add_parser("snapshot", help="print the phone's current links, holders and devices as JSON")
    p.add_argument("--serial")

    p = sub.add_parser("report", help="merge peripheral and phone logs into one attributed timeline")
    p.add_argument("peripheral_log", type=Path)
    p.add_argument("phone_log", type=Path)

    args = parser.parse_args()
    if args.command == "peripheral":
        from linkwatch.peripheral import run

        asyncio.run(run(args.adapter, args.profile, args.name, args.log))
    elif args.command == "phone":
        from linkwatch.dumpsys import normalize_suffix
        from linkwatch.phone import watch

        watch(args.log, args.serial, args.interval, normalize_suffix(args.focus) if args.focus else None)
    elif args.command == "snapshot":
        from linkwatch.phone import snapshot

        snapshot(args.serial)
    elif args.command == "report":
        from linkwatch.report import main as report_main

        report_main(args.peripheral_log, args.phone_log)


if __name__ == "__main__":
    main()
