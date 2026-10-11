# ac6000-ble

**Unofficial** interoperability driver for the **Acetech AC6000-BT** airsoft
chronograph, obtained by reverse engineering its BLE protocol (Bluetooth traffic
observation + clear-text strings from the app). Read shots, read the ammo table
and set the BB weight — from Python (bleak) or directly in Chrome (Web Bluetooth).

> ⚠️ **Not affiliated with Acetech.** Trademarks and firmware belong to their
> respective owners. Built for interoperability with my own hardware (France/EU:
> IP Code art. L122-6-1; Directive 2009/24/EC art. 6). No code or binary from the
> original application is included or redistributed.
>
> ⚠️ **Measuring instrument.** Changing the BB weight changes the displayed energy
> (joules). Do not use these settings to bypass a compliance check (field joule
> limits). **No warranty** — use at your own risk.

Tested with firmware **1.017** (AC6000-BT5580). Other firmware may differ.

## Features

- Fast application-level pairing (token cached, no cold re-pairing)
- Decoding of **live shots** (m/s + fps)
- Reading the **ammo table** (5 slots, BB weight)
- **Writing a slot's weight** + re-selecting the active slot
- **Python** (`ac6000_sniff.py`) and **Web Bluetooth** (`ac6000_web.html`) clients
- PacketLogger capture parser (`tools/pklg_parse.py`)

## Install (Python)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage (Python)

Chrono powered on, Bluetooth enabled, official app **disconnected** (only one BLE
connection at a time).

```bash
# Scan and list devices
python ac6000_sniff.py --scan-only

# Connect and log live shots (m/s + fps)
python ac6000_sniff.py

# Read the ammo table
python ac6000_sniff.py --read-ammo

# Set a slot's weight (grams) + automatic re-selection
python ac6000_sniff.py --set-weight 3:0.25

# Select the active ammo slot
python ac6000_sniff.py --select-slot 3
```

During live capture, type the speed shown on the chrono + Enter to drop a
timestamped marker into `ac6000_capture.jsonl`. Press `q` to quit.

## Usage (Chrome / Web Bluetooth)

`ac6000_web.html` runs in **Chrome or Edge** (desktop or Android). **Not on iOS**
(WebKit has no Web Bluetooth). A secure context is required:

```bash
python3 -m http.server 8000
# then open http://localhost:8000/ac6000_web.html in Chrome
```

Click **Connect**, pick the `AC6000-BT…` device, and use the buttons. The pairing
token is cached in the browser's `localStorage`.

## Protocol

Full write-up in [PROTOCOL.md](PROTOCOL.md). In short:

- Frame `AA | LEN | CMD | payload | CHECKSUM`, `CHECKSUM=(0x8B+sum(LEN..payload))&0xFF`
- Pairing: HELLO `0x4B` ↔ device token; required before any write
- Shot: `0x52` (spontaneous), speed = value16 LE / 100 m/s
- Ammo: read `0x47`, write weight `0x53` (g×100), select active `0x59`

## Tests

Protocol tests (checksums, frame build/parse) with **no hardware**, validated
against real captured frames:

```bash
python test_protocol.py
```

## Parsing a PacketLogger capture

```bash
python tools/pklg_parse.py capture.pklg 0xe 0x12   # filter on the chrono handles
```
Auto-detects endianness (macOS big-endian / iOS little-endian captures).

## License

MIT — see [LICENSE](LICENSE).
