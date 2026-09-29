"""Merge a peripheral log and a phone log into one timeline, attributing each access to the apps holding the link.

The peripheral sees the phone, not the app: every app on a phone shares one address and one link. So an
access is attributed to whichever apps the phone reported as holding the peripheral's link at that moment.
When only one app holds it, the attribution is exact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from linkwatch.dumpsys import normalize_suffix

ACCESS_EVENTS = {"read", "write", "subscribe", "unsubscribe", "connected", "disconnected", "services_resolved"}


@dataclass
class Row:
    """One line of the merged timeline."""

    at: datetime
    source: str
    event: str
    detail: str
    holders: list[str] | None = None


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _at(record: dict, key: str = "ts") -> datetime:
    return datetime.fromisoformat(record[key]).replace(tzinfo=None)


def merge(peripheral: list[dict], phone: list[dict]) -> list[Row]:
    """Build the timeline; phone holder changes are placed at the phone's own timestamp, clock-corrected."""
    start = next((r for r in peripheral if r["event"] == "start"), None)
    suffix = normalize_suffix(start["address"]) if start else None

    changes: list[tuple[datetime, list[str]]] = []
    rows: list[Row] = []
    for r in phone:
        if r["event"] == "holders_changed" and r.get("suffix") == suffix:
            at = datetime.fromisoformat(r["host_time"]) if r.get("host_time") else _at(r)
            changes.append((at, r["holders"]))
            rows.append(Row(at, "phone", "holders", f"{r.get('name') or suffix}: {', '.join(r['holders']) or 'none'}"))
    changes.sort()

    def holders_at(at: datetime) -> list[str]:
        current: list[str] = []
        for when, holders in changes:
            if when > at:
                break
            current = holders
        return current

    for r in peripheral:
        if r["event"] not in ACCESS_EVENTS and r["event"] not in ("start", "stop"):
            continue
        at = _at(r)
        bits = [r.get("characteristic"), r.get("value_text") and repr(r["value_text"]),
                r.get("central") and f"from {r['central']}", r.get("mtu") and f"mtu {r['mtu']}"]
        detail = " ".join(b for b in bits if b)
        if r["event"] == "start":
            detail = f"advertising as {r.get('name')!r} from {r.get('address')} ({r.get('profile')})"
        rows.append(Row(at, "peripheral", r["event"], detail,
                        holders_at(at) if r["event"] in ACCESS_EVENTS else None))

    rows.sort(key=lambda row: row.at)
    return rows


def render(rows: list[Row]) -> str:
    """The timeline as aligned text, one row per event."""
    lines = []
    for row in rows:
        who = f"  <- held by {', '.join(row.holders) or 'no app'}" if row.holders is not None else ""
        lines.append(f"{row.at:%H:%M:%S.%f}"[:-3] + f"  {row.source:<10} {row.event:<17} {row.detail}{who}")
    return "\n".join(lines)


def main(peripheral_log: Path, phone_log: Path) -> None:
    """Print the merged timeline for one run."""
    print(render(merge(_load(peripheral_log), _load(phone_log))))
