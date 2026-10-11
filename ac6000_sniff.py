#!/usr/bin/env python3
"""
BLE sniffer / client for the Acetech AC6000 chronograph.

Protocol (reconstructed from a PacketLogger capture of the AceSoft app):

  Frame: AA | LEN | CMD | payload... | CHECKSUM
    AA       = sync byte (0xAA)
    LEN      = total frame length (including AA and CHECKSUM)
    CMD      = command byte
    CHECKSUM = (0x8B + sum(LEN..last payload byte)) & 0xFF

  GATT:
    NOTIFY: service 5cde0c3d-... / char 3337e46e-...   (DEV->APP frames)
    WRITE : service 53c47fe1-... / char 9c6aa1ee-...   (write-without-response)

  Known commands:
    0x4B  hello / pairing token      (app sends aa064bdf02dc)
    0x47  read a stored record       (by group, index)
    0x49  serial number             -> ASCII
    0x56  firmware version          -> ASCII
    0x62  battery
    0x52  LIVE SHOT REPORT           (spontaneous): payload 00 00 | <v 16b LE> | 00 00
          The 16-bit value (little-endian) = SPEED in m/s x 100 (cm/s).
          m/s = value / 100 ; fps = m/s * 3.28084. (Validated on 2 captures.)

  Pairing (application-level handshake, NOT OS bonding):
    App -> chrono : aa06 4b 0000 fb   (HELLO, payload 00 00)
    chrono -> App : aa06 4b df02 dc   (reply, df02 = device token)

Usage:
  python ac6000_sniff.py                 # scan + connect + hello + live capture
  python ac6000_sniff.py --scan-only
  python ac6000_sniff.py --no-wake       # do not send the HELLO
"""

import argparse
import asyncio
import datetime
import json
import sys

from bleak import BleakClient, BleakScanner

NOTIFY_UUID = "3337e46e-f79e-4ff5-9a49-77c36d170c62"
WRITE_UUID = "9c6aa1ee-b4b9-44a1-ba45-1558c9109b4c"
KNOWN_UUIDS = {
    "5cde0c3d-7b1d-4352-94bb-02269c9f42b5", "53c47fe1-6c22-4ea6-99c7-7b6325ec75b9",
    NOTIFY_UUID, WRITE_UUID,
}

# Pairing-token cache file, keyed by device address.
TOKEN_FILE = "ac6000_token.json"

CMD_NAMES = {
    0x41: "STATUS", 0x47: "RECORD", 0x49: "SERIAL", 0x4b: "HELLO",
    0x4e: "STATUS2", 0x52: "SHOT", 0x53: "SET", 0x56: "VERSION",
    0x59: "SELECT", 0x5a: "RECORD_META", 0x62: "BATTERY", 0x63: "INFO",
}


def now():
    return datetime.datetime.now().isoformat(timespec="milliseconds")


def checksum(body: bytes) -> int:
    """body = LEN..payload (without AA or checksum)."""
    return (0x8b + sum(body)) & 0xff


def build(cmd: int, payload: bytes = b"") -> bytes:
    length = 3 + len(payload) + 1  # AA + LEN + CMD + payload + CSUM
    body = bytes([length, cmd]) + payload
    return bytes([0xAA]) + body + bytes([checksum(body)])


def verify(frame: bytes) -> bool:
    if len(frame) < 4 or frame[0] != 0xAA:
        return False
    return checksum(frame[1:-1]) == frame[-1] or (sum(frame[:-1]) & 0xff) == frame[-1]


# ---- Ammo table (BB weight) --------------------------------------------
# Record 0x47/0x53 (11 bytes):
#   AA 0B CMD | 00 GG SS | F2(2 LE) | WW(2 LE) | CS
#   GG = group/profile, SS = slot (1..5), F2 = secondary field (600),
#   WW = BB weight in grams x 100.

def parse_ammo_record(frame: bytes):
    """Return (group, slot, field2, grams) for an 11-byte 0x47/0x53 frame."""
    if len(frame) < 11 or frame[2] not in (0x47, 0x53):
        return None
    p = frame[3:-1]  # 7 bytes: 00 GG SS F2lo F2hi Wlo Whi
    group = p[1]
    slot = p[2]
    field2 = int.from_bytes(p[3:5], "little")
    grams = int.from_bytes(p[5:7], "little") / 100.0
    return group, slot, field2, grams


def build_read_ammo(slot: int, group_req: int = 0x01) -> bytes:
    """Request to read an ammo slot (0x47)."""
    return build(0x47, bytes([group_req, slot]))


def build_select_slot(slot: int, group_req: int = 0x01) -> bytes:
    """Select the active ammo slot (0x59). Payload = group, slot."""
    return build(0x59, bytes([group_req, slot]))


def build_hello(token: bytes = b"\x00\x00") -> bytes:
    """HELLO 0x4B. token=00 00 -> request the token ; token=df02 -> authenticate.
    (0x4B uses the checksum variant = sum of all bytes, AA included.)"""
    body = bytes([6, 0x4B]) + token
    frame = bytes([0xAA]) + body
    return frame + bytes([sum(frame) & 0xFF])


def load_token(address: str):
    try:
        with open(TOKEN_FILE) as f:
            return bytes.fromhex(json.load(f).get(str(address), ""))
    except Exception:
        return None


def save_token(address: str, token: bytes):
    data = {}
    try:
        with open(TOKEN_FILE) as f:
            data = json.load(f)
    except Exception:
        pass
    data[str(address)] = token.hex()
    try:
        with open(TOKEN_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def build_set_weight(slot: int, grams: float, group: int = 0x41,
                     field2: int = 600) -> bytes:
    """Build the 0x53 command that sets a slot's BB weight.

    grams : BB weight (e.g. 0.20, 0.25, 0.28, 0.32, 0.40).
    group/field2 : take these from a prior 0x47 read to match the device state
    (defaults are the values observed in the capture).
    """
    w = round(grams * 100)
    payload = bytes([0x00, group, slot]) + int(field2).to_bytes(2, "little") \
        + int(w).to_bytes(2, "little")
    return build(0x53, payload)


class Logger:
    def __init__(self, path):
        self.f = open(path, "a", buffering=1)

    def log(self, kind, **fields):
        rec = {"ts": now(), "kind": kind, **fields}
        self.f.write(json.dumps(rec) + "\n")
        return rec


def decode_frame(frame: bytes, k: float | None):
    """Return a human-readable string for an AA-framed frame."""
    if len(frame) < 4 or frame[0] != 0xAA:
        return f"(unframed) {frame.hex()}"
    length, cmd = frame[1], frame[2]
    payload = frame[3:-1]
    name = CMD_NAMES.get(cmd, f"0x{cmd:02x}")
    ok = "ok" if verify(frame) else "CSUM?"
    extra = ""
    if cmd == 0x52 and len(payload) >= 4:
        raw = int.from_bytes(payload[2:6] if len(payload) >= 6 else payload[2:4], "little")
        mps = raw / 100.0
        extra = f"  *** SHOT: {mps:.2f} m/s  =  {mps*3.28084:.1f} fps  (raw={raw})"
    elif cmd in (0x47, 0x53) and len(frame) >= 11:
        rec = parse_ammo_record(frame)
        if rec:
            g, s, f2, grams = rec
            gi = chr(g) if 32 <= g < 127 else "?"
            verb = "SET" if cmd == 0x53 else "AMMO"
            extra = f"  {verb} group='{gi}' slot={s} weight={grams:.2f} g (f2={f2})"
    elif cmd == 0x59 and len(payload) >= 2:
        extra = f"  SELECT group={payload[0]} slot={payload[1]}"
    elif cmd in (0x49, 0x56) and payload:
        try:
            extra = f"  ascii={payload.decode('ascii', 'replace').strip()!r}"
        except Exception:
            pass
    return f"{name:11} len={length:<3} cmd=0x{cmd:02x} payload={payload.hex():<16} [{ok}]{extra}"


async def do_scan(name_filter, timeout):
    print(f"[{now()}] BLE scan ({timeout}s)...")
    results = await BleakScanner.discover(timeout=timeout, return_adv=True)
    matches = []
    for device, adv in results.values():
        label = device.name or adv.local_name or "?"
        is_match = name_filter.lower() in label.lower() or any(
            str(u).lower() in KNOWN_UUIDS for u in adv.service_uuids
        )
        if is_match:
            print(f"* {device.address}  RSSI={adv.rssi}  name={label!r}")
            matches.append(device)
    return matches


async def run(args):
    logger = Logger(args.log)
    if args.address:
        target = args.address
    else:
        matches = await do_scan(args.name, args.scan_timeout)
        if args.scan_only:
            return
        if not matches:
            print(f"No device matching {args.name!r}. Chrono on + BT enabled + official app disconnected?")
            return
        target = matches[0]

    disconnect_evt = asyncio.Event()

    def on_disconnect(_c):
        print(f"[{now()}] !! Disconnected")
        logger.log("disconnect")
        disconnect_evt.set()

    print(f"[{now()}] Connecting to {getattr(target,'address',target)} ...")
    async with BleakClient(target, disconnected_callback=on_disconnect, timeout=30) as client:
        print(f"[{now()}] Connected.")
        logger.log("connect", address=str(getattr(target, "address", target)))

        ammo_table = {}  # slot -> (group, field2, grams)
        hello_evt = asyncio.Event()
        learned_token = []

        def cb(_sender, data: bytearray):
            data = bytes(data)
            print(f"[{now()}] NOTIF {data.hex()}")
            print(f"            -> {decode_frame(data, args.k)}")
            logger.log("notify", hex=data.hex(), decoded=decode_frame(data, args.k))
            if len(data) >= 4 and data[0] == 0xAA and data[2] == 0x4B:
                learned_token.append(data[3:-1])  # token volunteered by the chrono
                hello_evt.set()
            if len(data) >= 4 and data[0] == 0xAA and data[2] == 0x41:
                hello_evt.set()  # STATUS: fast ack of our authenticated HELLO
            rec = parse_ammo_record(data)
            if rec:
                g, s, f2, grams = rec
                ammo_table[s] = (g, f2, grams)

        async def write(frame, label):
            await client.write_gatt_char(WRITE_UUID, frame, response=False)
            print(f"[{now()}] {label} -> {frame.hex()}")
            logger.log("write", hex=frame.hex())
            await asyncio.sleep(0.25)

        await client.start_notify(NOTIFY_UUID, cb)
        print(f"[{now()}] Subscribed to notifications.")

        addr = str(getattr(target, "address", target))
        if not args.no_wake:
            token = bytes.fromhex(args.token) if args.token else load_token(addr)
            if token:
                # Known token: authenticate directly -> immediate STATUS ack.
                await write(build_hello(token), f"HELLO (token {token.hex()})")
                try:
                    await asyncio.wait_for(hello_evt.wait(), timeout=3.0)
                    print(f"[{now()}] Authenticated with cached token {token.hex()}.")
                except asyncio.TimeoutError:
                    print(f"[{now()}] (token {token.hex()} not acked; re-pairing)")
                    token = None
            if not token:
                # No token: pair (HELLO 00 00), the chrono returns its own.
                for attempt in range(8):
                    await write(build_hello(), f"PAIRING ({attempt+1})")
                    try:
                        await asyncio.wait_for(hello_evt.wait(), timeout=3.0)
                        break
                    except asyncio.TimeoutError:
                        continue
                if learned_token:
                    save_token(addr, learned_token[-1])
                    print(f"[{now()}] Token learned and cached: {learned_token[-1].hex()}")
                else:
                    print(f"[{now()}] (no token received; writes may be ignored)")

        # Read the ammo table (BB weight) if requested or before a set.
        if args.read_ammo or args.set_weight:
            print(f"[{now()}] Reading the ammo table (slots 1..5)...")
            for s in range(1, 6):
                await write(build_read_ammo(s, args.group_req), f"READ ammo {s}")
            await asyncio.sleep(0.4)
            print("  --- Ammo table ---")
            for s in sorted(ammo_table):
                g, f2, grams = ammo_table[s]
                print(f"    slot {s}: {grams:.2f} g  (group={chr(g) if 32<=g<127 else g}, f2={f2})")

        # Set a weight: --set-weight SLOT:GRAMS (e.g. 3:0.25)
        if args.set_weight:
            slot_s, grams_s = args.set_weight.split(":")
            slot, grams = int(slot_s), float(grams_s)
            # take group/field2 from the read to match the device
            if slot in ammo_table:
                group, field2, _ = ammo_table[slot]
            else:
                group, field2 = args.group, args.field2
                print(f"  (slot {slot} not read, using defaults group={group:#x} f2={field2})")
            frame = build_set_weight(slot, grams, group=group, field2=field2)
            print(f"[{now()}] SET slot {slot} -> {grams:.2f} g")
            await write(frame, "SET weight")
            await asyncio.sleep(0.3)

            # Re-selection (command 0x59): the chrono only applies the active slot
            # when it is re-selected. Select ANOTHER slot then return to the
            # target slot.
            if not args.no_reselect:
                other = next((s for s in sorted(ammo_table) if s != slot), None)
                if other is None:
                    other = slot + 1 if slot < 5 else 1
                await write(build_select_slot(other, args.group_req),
                            f"SELECT other slot {other}")
                await asyncio.sleep(0.3)
                await write(build_select_slot(slot, args.group_req),
                            f"SELECT back slot {slot}")
                await asyncio.sleep(0.3)

            await write(build_read_ammo(slot, args.group_req), f"RE-READ ammo {slot}")
            await asyncio.sleep(0.4)
            if slot in ammo_table:
                print(f"  -> slot {slot} is now {ammo_table[slot][2]:.2f} g")
                print("  (check on the chrono screen that the active slot is updated)")

        # Plain selection of an active slot (0x59), without changing the weight.
        if args.select_slot is not None:
            s = args.select_slot
            await write(build_select_slot(s, args.group_req), f"SELECT slot {s}")
            await asyncio.sleep(0.3)
            print(f"  -> slot {s} selected (check the chrono screen)")

        print(
            "\n=== Live capture ===\n"
            "Put the chrono in SPEED mode (fps or m/s), fire, then type the\n"
            "displayed speed + Enter (e.g. '328.5'). 'q' to quit.\n"
        )
        loop = asyncio.get_running_loop()
        while not disconnect_evt.is_set():
            line_task = asyncio.ensure_future(loop.run_in_executor(None, sys.stdin.readline))
            done, _ = await asyncio.wait(
                [line_task, asyncio.ensure_future(disconnect_evt.wait())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            if disconnect_evt.is_set():
                break
            line = line_task.result() if line_task in done else ""
            if not isinstance(line, str):
                continue
            line = line.strip()
            if line.lower() == "q":
                break
            if line:
                rec = logger.log("marker", text=line)
                print(f"[{rec['ts']}] MARKER: {line}")
    print(f"[{now()}] Done. Log: {args.log}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--name", default="AC6")
    p.add_argument("--address")
    p.add_argument("--scan-only", action="store_true")
    p.add_argument("--scan-timeout", type=float, default=8.0)
    p.add_argument("--no-wake", action="store_true", help="do not send the 0x4B HELLO sequence")
    p.add_argument("--token", help="pairing token in hex (e.g. df02); otherwise cache/auto-pair")
    p.add_argument("--read-ammo", action="store_true", help="read the ammo table (BB weights)")
    p.add_argument("--set-weight", metavar="SLOT:GRAMS",
                   help="set a slot's weight, e.g. 3:0.25")
    p.add_argument("--no-reselect", action="store_true",
                   help="skip the re-selection (other slot then back) after a set")
    p.add_argument("--select-slot", type=int, metavar="N",
                   help="select the active ammo slot (0x59), e.g. 3")
    p.add_argument("--group", type=lambda x: int(x, 0), default=0x41,
                   help="default group/profile if the slot wasn't read (default 0x41)")
    p.add_argument("--group-req", type=lambda x: int(x, 0), default=0x01,
                   help="group byte for 0x47 read requests (default 0x01)")
    p.add_argument("--field2", type=int, default=600, help="secondary field (default 600)")
    p.add_argument("--k", type=float, default=None, help="(unused) legacy parameter")
    p.add_argument("--log", default="ac6000_capture.jsonl")
    args = p.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
