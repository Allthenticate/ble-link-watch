# ble-link-watch

See which apps on an Android phone connect to a Bluetooth LE device, how long they hold the link, and what they
read from it.

A Bluetooth LE connection belongs to two *devices*, not two apps. Every app on a phone that talks to the same
peripheral shares one radio link, and Android keeps that link up for as long as any app still holds it. That
makes two things hard to see from either end:

- The peripheral sees the phone's address, never the app. It cannot tell which app on the phone read it.
- The phone's apps cannot see each other. An app that disconnects has no way to learn that another app is still
  holding the link.

This tool puts the two halves together:

| Command | Runs on | Shows |
|---|---|---|
| `linkwatch phone` | any machine with `adb` and the phone attached | which apps hold each link, from `dumpsys bluetooth_manager` |
| `linkwatch snapshot` | same | the same, once, as JSON |
| `linkwatch peripheral` | Linux with BlueZ 5.50+ | a bait device that logs every read, write and subscription |
| `linkwatch report` | anywhere | both logs merged, each access attributed to the apps holding the link |
| `python windows_bait.py` | Windows 10/11 with Python 3.12 | the same bait on Windows's own GATT server; logs reads, writes and subscriptions with the central's address |

## Setup

```sh
uv venv && uv pip install -e '.[peripheral]'   # or: python -m venv .venv && .venv/bin/pip install -e '.[peripheral]'
```

- The phone needs USB debugging enabled and `adb devices` must list it.
- The peripheral needs a Linux machine with Bluetooth and BlueZ. It does not need root: BlueZ's default D-Bus
  policy lets any user register a GATT application and an advertisement.
- The two can run on the same machine; then both logs share a clock.

## Running an experiment

```sh
linkwatch phone --log run/phone.jsonl &              # poll the phone every 5 s
linkwatch peripheral --profile laptop --log run/peripheral.jsonl
# ... leave the phone near the peripheral, use it normally, Ctrl-C when done
linkwatch report run/peripheral.jsonl run/phone.jsonl
```

The report is one line per event. Every connection, read, write and subscription on the bait is followed by the
apps the phone said were holding the link at that moment:

```
22:14:09.237  peripheral connected         from 5A:4C:73:27:6A:B7  <- held by no app
22:14:11.799  phone      holders           linkwatch: com.example.app
22:14:12.030  peripheral read              manufacturer_name from 5A:4C:73:27:6A:B7 mtu 517  <- held by com.example.app
```

When one app holds the link, the attribution is exact. When several do, the report lists them all.

### Bait profiles

`--profile` sets what the peripheral advertises. The GATT database is the same in all of them, so the bait service can be read even when it is not advertised. A legacy advertisement holds 31 bytes, so a long name and a 128-bit UUID do not fit together.

| Profile | Name | Appearance | Advertised service |
|---|---|---|---|
| `plain` | `linkwatch` | none | bait service |
| `laptop` | `LAPTOP-7Q2K9` | Laptop (0x0083) | bait service |
| `no-services` | `LAPTOP-7Q2K9` | Laptop | none |
| `anonymous` | none | none | bait service |
| `windows` | `LAPTOP-7Q2K9` | none | Device Information (0x180A), as a Windows 11 GATT server advertises it |
| `dis-only` | `linkwatch` | none | Device Information only |

`--name` overrides the advertised name.

### What the bait exposes

| Service | Characteristic | Access | Why it is there |
|---|---|---|---|
| bait (`7a1c0000-…`) | `bait_read` | read | a canary: anything that reads it, logs it |
| | `bait_write` | write | records whatever an app writes |
| | `bait_notify` | read, notify, indicate | records subscriptions |
| | `bait_encrypted` | read, needs pairing | shows whether an app attempts a protected read |
| Device Information (0x180A) | manufacturer, model, serial | read | the fields a device fingerprinter would read |
| Battery (0x180F) | battery level | read, notify | a common passive read |

## Windows bait

A Windows laptop advertises differently from a Linux one: Windows adds the Device Information service
(0x180A) to a GATT server's advertisement, and phones file Windows laptops as dual-mode (Classic and LE)
devices. `windows_bait.py` publishes the bait service through Windows's own Bluetooth stack:

```powershell
pip install winrt-runtime winrt-Windows.Devices.Bluetooth winrt-Windows.Devices.Bluetooth.GenericAttributeProfile `
    winrt-Windows.Devices.Bluetooth.Advertisement winrt-Windows.Foundation winrt-Windows.Storage.Streams
python windows_bait.py --log windows.jsonl --seconds 1800
```

`--winrt-path DIR` imports the WinRT projections from an existing directory instead, including the
compiled-only copy inside a PyInstaller bundle. While it runs, the bait asks Windows to keep the system and
display awake; Windows drops that request when the process exits. The phone monitor and `linkwatch report`
work with its log the same way.

## What it cannot see

- **Service discovery.** BlueZ answers discovery itself without involving this process. An app joining a link
  that is already up often gets Android's cached copy of the device's services with no radio traffic at all.
  Capture packets to see discovery (below).
- **Which app sent a request, when several hold the link.** Nothing on either end records that.
- **iOS.** `dumpsys` is Android only. On iOS, use PacketLogger from Apple's Additional Tools for Xcode for the
  radio side; there is no equivalent of the ACL holder list.
- **Addresses in `dumpsys` are masked** to their last two bytes, so devices are matched on those. Two nearby
  devices sharing them would be confused.

## Packet captures

For radio-level detail, including discovery:

- **Peripheral side:** `sudo btmon -w run/peripheral.btsnoop` while the bait runs.
- **Phone side:** Developer options, "Enable Bluetooth HCI snoop log", set to **Enabled** (not "Filtered", and
  not the separate "socket" option), then turn Bluetooth off and on. After the experiment, `adb bugreport
  run/bugreport.zip`; the log is `FS/data/misc/bluetooth/logs/btsnoop_hci.log` inside it.

Decode either with `btmon -r <file> -T`. In btmon's output, lines starting `<` are packets the capturing device
sent and `>` are packets it received. ATT requests appear as `ATT: Read Request`, `ATT: Write Request`,
`ATT: Read By Type Request` and so on, under `LE-ACL: Handle <n>`. The handle maps to a peer in the
`LE Enhanced Connection Complete` event that opened it.

## Caveats for your own runs

- **Use a machine whose Bluetooth address nothing else is advertising from.** If another BLE service runs on the
  same adapter, the phone sees one device offering both, and cannot be told they are separate.
- **Dual-mode vs LE-only may matter.** Devices the phone also knows over Bluetooth Classic show up in `dumpsys`
  as `DUAL`. BlueZ with `ControllerMode = le` advertises LE only.
- **Turn the snoop log off afterwards.** It records every Bluetooth packet on the phone.
