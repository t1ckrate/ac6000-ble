#!/usr/bin/env python3
"""
AC6000 protocol tests, NO hardware required.

Validates frame construction and parsing against real frames captured from an
AC6000-BT5580 (firmware 1.017). No BLE connection needed.

    python test_protocol.py
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ac6000", os.path.join(HERE, "ac6000_sniff.py"))
ac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ac)

PASS = FAIL = 0


def check(label, got, expected):
    global PASS, FAIL
    ok = got == expected
    PASS += ok
    FAIL += not ok
    status = "ok  " if ok else "FAIL"
    print(f"  [{status}] {label}")
    if not ok:
        print(f"         expected: {expected}")
        print(f"         got     : {got}")


def h(frame):
    return frame.hex()


print("== Frame construction (vs real captures) ==")
check("HELLO 00 00",        h(ac.build_hello()),                       "aa064b0000fb")
check("HELLO token df02",   h(ac.build_hello(bytes.fromhex("df02"))),  "aa064bdf02dc")
check("READ ammo slot 1",   h(ac.build_read_ammo(1)),                  "aa06470101da")
check("SELECT slot 3",      h(ac.build_select_slot(3)),                "aa06590103ee")
check("SELECT slot 4",      h(ac.build_select_slot(4)),                "aa06590104ef")
check("SELECT slot 1",      h(ac.build_select_slot(1)),                "aa06590101ec")
check("SET slot 5 = 0.28g", h(ac.build_set_weight(5, 0.28)),           "aa0b5300410558021c00a5")
check("SET slot 4 = 0.24g", h(ac.build_set_weight(4, 0.24)),           "aa0b5300410458021800a0")
check("SET slot 3 = 0.20g", h(ac.build_set_weight(3, 0.20)),           "aa0b53004103580214009b")

print("== Checksum: verify valid frames ==")
for frame in ["aa064bdf02dc", "aa06470101da", "aa0b5300410558021c00a5",
              "aa0a520000cb000000b2", "aa0956312e303137e1"]:
    check(f"verify({frame})", ac.verify(bytes.fromhex(frame)), True)
check("verify(corrupt frame)", ac.verify(bytes.fromhex("aa064bdf0200")), False)

print("== Shot decoding 0x52 (speed = value/100 m/s) ==")
def shot_mps(frame):
    p = bytes.fromhex(frame)[3:-1]
    return int.from_bytes(p[2:6], "little") / 100.0
check("shot 203 -> 2.03 m/s",   round(shot_mps("aa0a520000cb000000b2"), 2), 2.03)
check("shot 177 -> 1.77 m/s",   round(shot_mps("aa0a520000b100000098"), 2), 1.77)
check("shot 9697 -> 96.97 m/s", round(shot_mps("aa0a520000e1250000ed"), 2), 96.97)

print("== Ammo record parsing 0x47/0x53 ==")
rec = ac.parse_ammo_record(bytes.fromhex("aa0b47004101580214008d"))
check("record slot",   rec[1], 1)
check("record group",  rec[0], 0x41)
check("record field2", rec[2], 600)
check("record weight", round(rec[3], 2), 0.20)

print("== Round-trip set_weight -> parse ==")
for slot, grams in [(1, 0.20), (2, 0.25), (3, 0.28), (4, 0.32), (5, 0.40)]:
    frame = ac.build_set_weight(slot, grams)
    g, s, f2, parsed = ac.parse_ammo_record(frame)
    check(f"slot {slot} {grams:.2f}g round-trip", (s, round(parsed, 2)), (slot, grams))

print(f"\n{PASS} tests passed, {FAIL} failure(s).")
sys.exit(1 if FAIL else 0)
