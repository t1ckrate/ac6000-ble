#!/usr/bin/env python3
"""PacketLogger (.pklg) parser -> BLE ATT traffic.

Usage: python pklg_parse.py capture.pklg [handle ...]
  e.g. python pklg_parse.py capture.pklg 0xe 0x12   (filter on the chrono handles)

PacketLogger record:
  u32 length (= 9 + len(payload))
  u32 sec, u32 usec
  u8  type (0x00 sent cmd, 0x01 event, 0x02 sent ACL, 0x03 received ACL)
  payload
Endianness is auto-detected (macOS big-endian / iOS little-endian captures).

ACL payload (HCI ACL):
  u16 le handle+flags ; u16 le data_len
  L2CAP: u16 le len ; u16 le cid ; if cid==4 -> ATT PDU
"""
import struct
import sys
import datetime

ATT_OP = {
    0x01: "ERROR_RSP", 0x02: "MTU_REQ", 0x03: "MTU_RSP",
    0x04: "FIND_INFO_REQ", 0x05: "FIND_INFO_RSP",
    0x08: "READ_BY_TYPE_REQ", 0x09: "READ_BY_TYPE_RSP",
    0x0a: "READ_REQ", 0x0b: "READ_RSP",
    0x10: "READ_BY_GRP_REQ", 0x11: "READ_BY_GRP_RSP",
    0x12: "WRITE_REQ", 0x13: "WRITE_RSP",
    0x1b: "NOTIFY", 0x1d: "INDICATE", 0x1e: "CONFIRM",
    0x52: "WRITE_CMD",
}


def _detect_endian(buf):
    (be,) = struct.unpack_from(">I", buf, 0)
    (le,) = struct.unpack_from("<I", buf, 0)
    # plausible length = the smallest consistent one
    if 9 <= be <= len(buf):
        return ">"
    if 9 <= le <= len(buf):
        return "<"
    return ">"


def records(buf):
    e = _detect_endian(buf)
    off = 0
    n = len(buf)
    while off + 4 <= n:
        (length,) = struct.unpack_from(e + "I", buf, off)
        if length < 9 or off + 4 + length > n:
            break
        sec, usec = struct.unpack_from(e + "II", buf, off + 4)
        typ = buf[off + 12]
        payload = buf[off + 13: off + 4 + length]
        yield sec, usec, typ, payload
        off += 4 + length


def parse_att(payload):
    """payload = HCI ACL; returns (acl_handle, pb, att_bytes) or None."""
    if len(payload) < 8:
        return None
    hf, dlen = struct.unpack_from("<HH", payload, 0)
    acl_handle = hf & 0x0FFF
    pb = (hf >> 12) & 0x3
    l2 = payload[4:]
    if len(l2) < 4:
        return None
    l2len, cid = struct.unpack_from("<HH", l2, 0)
    if cid != 0x0004:
        return None
    return acl_handle, pb, l2[4:4 + l2len]


def main():
    path = sys.argv[1]
    want_handles = None
    if len(sys.argv) > 2:
        want_handles = {int(x, 0) for x in sys.argv[2:]}
    with open(path, "rb") as f:
        buf = f.read()

    seen = []
    op_counts = {}
    handle_counts = {}
    for sec, usec, typ, payload in records(buf):
        if typ not in (0x02, 0x03):
            continue
        res = parse_att(payload)
        if not res:
            continue
        acl_handle, pb, att = res
        if not att:
            continue
        op = att[0]
        direction = "APP->DEV" if typ == 0x02 else "DEV->APP"
        handle = None
        value = b""
        if op in (0x1b, 0x1d, 0x12, 0x52, 0x0a, 0x13) and len(att) >= 3:
            handle = struct.unpack_from("<H", att, 1)[0]
            value = att[3:]
        op_counts[ATT_OP.get(op, hex(op))] = op_counts.get(ATT_OP.get(op, hex(op)), 0) + 1
        if handle is not None:
            handle_counts[handle] = handle_counts.get(handle, 0) + 1
        if want_handles is not None and handle not in want_handles:
            continue
        ts = datetime.datetime.fromtimestamp(sec + usec / 1e6).strftime("%H:%M:%S.%f")[:-3]
        seen.append((ts, direction, ATT_OP.get(op, hex(op)), handle, value))

    print(f"# {path}")
    print(f"# ATT PDUs by opcode: {op_counts}")
    print(f"# ATT handles seen (count): { {hex(k):v for k,v in sorted(handle_counts.items())} }")
    print(f"# lines kept: {len(seen)}")
    print("-" * 70)
    for ts, d, op, h, v in seen:
        hs = hex(h) if h is not None else "-"
        print(f"{ts}  {d}  {op:10} h={hs:6} ({len(v):>3}) {v.hex()}")


if __name__ == "__main__":
    main()
