from datetime import datetime

from linkwatch.report import merge, render

START = {"ts": "2026-09-27T22:00:00.000-05:00", "source": "peripheral", "event": "start",
         "address": "84:7B:57:57:79:60", "name": "linkwatch", "profile": "plain"}


def _phone(at: str, holders: list[str]) -> dict:
    return {"ts": at, "source": "phone", "event": "holders_changed", "suffix": "79:60", "name": "SDA",
            "holders": holders, "host_time": at[:23]}


def test_an_access_is_attributed_to_the_apps_holding_the_link_at_that_moment():
    phone = [_phone("2026-09-27T22:00:05.000", ["net.example.first"]),
             _phone("2026-09-27T22:00:10.000", ["com.example.holder"])]
    peripheral = [START,
                  {"ts": "2026-09-27T22:00:07.000-05:00", "source": "peripheral", "event": "read",
                   "characteristic": "bait_read", "central": "5A:4C:73:27:6A:B7", "mtu": 517},
                  {"ts": "2026-09-27T22:00:12.000-05:00", "source": "peripheral", "event": "read",
                   "characteristic": "battery_level", "central": "5A:4C:73:27:6A:B7", "mtu": 517}]

    reads = [r for r in merge(peripheral, phone) if r.event == "read"]

    assert [(r.detail.split()[0], r.holders) for r in reads] == [
        ("bait_read", ["net.example.first"]),
        ("battery_level", ["com.example.holder"]),
    ]


def test_holder_changes_for_other_devices_are_left_out():
    other = {**_phone("2026-09-27T22:00:05.000", ["com.example.holder"]), "suffix": "D9:B7"}

    rows = merge([START], [other])

    assert [r.event for r in rows] == ["start"]


def test_render_marks_accesses_with_no_holder():
    peripheral = [START, {"ts": "2026-09-27T22:00:01.000-05:00", "source": "peripheral", "event": "connected",
                          "central": "5A:4C:73:27:6A:B7"}]

    text = render(merge(peripheral, []))

    assert "held by no app" in text
    assert text.splitlines()[0].startswith(f"{datetime(2026, 9, 27, 22):%H:%M:%S}")
