from datetime import datetime
from pathlib import Path

from linkwatch.dumpsys import Holder, normalize_suffix, parse

DUMP = (Path(__file__).parent / "fixtures" / "dumpsys_held_link.txt").read_text()


def test_open_links_and_their_holders():
    snap = parse(DUMP)

    assert set(snap.links) == {"93:E2", "93:DC", "B5:CE", "79:60"}
    assert snap.holders("93:e2") == (
        Holder("com.life360.android.safetymapd", 66),
        Holder("com.life360.android.safetymapd", 65),
        Holder("net.allthenticate.sda", 58),
    )
    assert snap.holders("AA:BB") == ()


def test_holder_history_keeps_the_phone_timestamps():
    snap = parse(DUMP)

    first_life360 = next(t for t in snap.transitions if any("life360" in h.package for h in t.holders))
    assert first_life360.suffix == "93:E2"
    assert first_life360.at == datetime(2026, 9, 26, 22, 13, 39, 987000)
    assert [t.holders for t in snap.transitions if t.suffix == "79:60"][0] == ()


def test_devices_record_bonding_names_and_the_apps_that_used_them():
    snap = parse(DUMP)

    laptop = snap.devices["93:E2"]
    assert laptop.name == "LAPTOP-WIN"
    assert laptop.bonded is False
    assert laptop.packages == ["com.life360.android.safetymapd"]
    assert snap.devices["B5:CE"].bonded is True


def test_gatt_clients_map_each_app_interface_to_its_connections():
    snap = parse(DUMP)

    life360 = [c for c in snap.clients if c.package == "com.life360.android.safetymapd"]
    assert [(c.app_if, c.connections) for c in life360] == [(65, ["93:E2"]), (66, ["93:E2"])]
    assert all(c.package != "android.uid.bluetooth:1002" for c in snap.clients)


def test_suffixes_from_full_and_masked_addresses():
    assert normalize_suffix("84:7B:57:57:79:60") == "79:60"
    assert normalize_suffix("xx:xx:xx:xx:73:f0") == "73:F0"
