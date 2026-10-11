# BLE protocol — Acetech AC6000 (AC6000-BT)

Reconstructed by reverse engineering the AceSoft app + 2 PacketLogger captures.
No crypto: simple framing, speed sent in clear.

## GATT

| Role | Service UUID | Characteristic UUID | Handle* | Properties |
|------|--------------|---------------------|---------|------------|
| NOTIFY (chrono → app) | `5cde0c3d-7b1d-4352-94bb-02269c9f42b5` | `3337e46e-f79e-4ff5-9a49-77c36d170c62` | 0x0d/0x0e | notify |
| WRITE (app → chrono)  | `53c47fe1-6c22-4ea6-99c7-7b6325ec75b9` | `9c6aa1ee-b4b9-44a1-ba45-1558c9109b4c` | 0x11/0x12 | write-without-response |

\* Handles vary between sessions; rely on the UUIDs.
Advertised name: `AC6000-BT<serial>` (e.g. `AC6000-BT5580`).

## Framing

```
AA | LEN | CMD | payload... | CHECKSUM
```
- `AA`: sync byte (0xAA)
- `LEN`: total frame length (including AA and CHECKSUM)
- `CMD`: command byte
- `CHECKSUM = (0x8B + sum(LEN..last payload byte)) & 0xFF`
  (2 "info" frames — HELLO 0x4B and the serial-number reply 0x49 — use a
  variant `sum(AA..payload) & 0xFF`; irrelevant if you replay captured bytes.)

## Pairing / wake-up (application-level handshake, NOT OS bonding)

```
app    → chrono : AA 06 4B 00 00 FB      HELLO (payload 00 00)
chrono → app    : AA 06 4B DF 02 DC      reply, DF02 = device token
```
Once paired, the app can send the token directly (`AA 06 4B DF 02 DC`).
After the HELLO, the chrono streams shots spontaneously on the NOTIFY characteristic.
Encrypted BLE bonding is not required (notifications work without it).

## Observed commands

| CMD | Dir | Meaning | Example |
|-----|-----|---------|---------|
| 0x4B | ↔ | HELLO / token | `aa064b0000fb` → `aa064bdf02dc` |
| 0x41 | ← | STATUS (ack) | `aa054100d1` |
| 0x62 | ↔ | Battery | `aa056200f2` → `aa06620001f4` |
| 0x56 | ↔ | Firmware version (ASCII) | `aa055600e6` → `aa0956312e303137e1` = "1.017" |
| 0x49 | ↔ | Serial number (ASCII) | `aa0449d8` → `...3030303035353830...` = "00005580" |
| 0x5A | ↔ | Record metadata | `aa055a00ea` → `aa0a5a01035802190066` |
| 0x47 | ↔ | Read a stored record (group, index) | `aa06470101da` → `aa0b47003101580214007d` |
| 0x53 | → | Write an ammo record (weight) | `aa0b5300410358021900a0` |
| 0x59 | → | **Select the active ammo slot** | `aa06590103ee` (slot 3) |
| 0x52 | ← | **SHOT REPORT (spontaneous)** | `aa0a520000cb000000b2` |

## Shot frame 0x52 (the main one)

```
AA 0A 52 | 00 00 | VV VV | 00 00 | CS
          \_____/  \_____/
          reserved  speed (16-bit little-endian)
```
- **speed_m/s = value16 / 100**  (value is in cm/s)
- **speed_fps = speed_m/s × 3.28084**  (conversion done by the app)

### Validation (2 independent captures)

| Frame | value | m/s | fps | displayed |
|-------|-------|-----|-----|-----------|
| `aa0a520000cb000000b2` | 203 | 2.03 | 6.7 | 6.6 fps / 2.03 m/s ✓ |
| `aa0a520000b100000098` | 177 | 1.77 | 5.8 | 5.8 fps / 1.77 m/s ✓ |
| `aa0a520000e5000000cc` | 229 | 2.29 | 7.5 | 7.5 fps / 2.29 m/s ✓ |
| `aa0a520000e1250000ed` | 9697 | 96.97 | 318 | (real shot) |
| `aa0a520000492d00005d` | 11593 | 115.93 | 380 | (real shot) |

## Ammo table / BB weight (caliber)

The chrono stores a table of ammo types (slots 1..5), each with a **BB weight**.
The weight is used for the energy calculation (Joule = ½·m·v²); it does NOT
change the measured speed (0x52 stays in raw m/s).

**Record (11 bytes, commands 0x47 read / 0x53 write):**
```
AA 0B CMD | 00 | GG | SS | F2 F2 | WW WW | CS
                  │    │    └(LE)  └(LE) BB weight = grams × 100
                  │    └ ammo slot (1..5)
                  └ group/profile (ASCII, 'A'=0x41 here; '0'/'1' depending on mode)
          F2 = secondary 16-bit LE field (600 in the capture, unchanged)
```

**Read a slot**: `AA 06 47 | GRP SS | CS`  (e.g. `aa06470101da` = grp 1, slot 1)
→ 11-byte 0x47 reply above.

**Write the weight (change caliber)**: command **0x53**, same structure, confirmed
by a `STATUS 0x41` (`aa054100d1`). Real examples from the capture:

| 0x53 frame | slot | weight |
|---|---|---|
| `aa0b5300410558021c00a5` | 5 | 0.28 g |
| `aa0b5300410458021800a0` | 4 | 0.24 g |
| `aa0b53004103580214009b` | 3 | 0.20 g |

Weight encoding: `grams × 100`, 16-bit little-endian (0.20 g → `14 00`,
0.25 g → `19 00`, 0.28 g → `1c 00`, 0.32 g → `20 00`, 0.40 g → `28 00`).

To edit cleanly, the app does **read → modify → write-back**: it reads the slot
(0x47), keeps `GG` and `F2` from the reply, and changes only the weight field
before sending a 0x53. This project does the same.

**Selecting the active slot (command 0x59)**: writing the weight (0x53) is NOT
enough for the chrono to apply the slot on its screen. You must **re-select** the
active slot with `0x59`: `AA 06 59 | GG SS | CS` (GG=group `01`, SS=slot). Since
the device only refreshes on a *change* of selection, select another slot then
return to the target:
```
aa06590101ec   SELECT slot 1
aa06590103ee   SELECT slot 3   (back to target → weight applied)
```
Each 0x59 is acked by `STATUS 0x41`. The pairing token (df02) must be received
before any 0x53/0x59 write, otherwise the writes are silently ignored.

## The app binary

`/Applications/AceSoft.app` (native Apple-Silicon iOS app). The binary is
FairPlay-encrypted on **a single 4 KB page** (the fps/J conversion routine, not
needed: the speed already arrives decoded). Everything else is in clear: UUIDs,
command names, Swift source paths (`SpeedTestViewController.swift`, etc.),
RxBluetoothKit.
