#!/usr/bin/env python3
"""Debug DFU protocol — tries different hw_version values."""

import serial
import struct
import time
import binascii
import hashlib
import sys

SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD

def slip_enc(data):
    out = bytearray()
    for b in data:
        if b == SLIP_END: out.extend([SLIP_ESC, SLIP_ESC_END])
        elif b == SLIP_ESC: out.extend([SLIP_ESC, SLIP_ESC_ESC])
        else: out.append(b)
    out.append(SLIP_END)
    return bytes(out)

def slip_dec(data):
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == SLIP_ESC and i + 1 < len(data):
            nxt = data[i + 1]
            if nxt == SLIP_ESC_END: out.append(SLIP_END)
            elif nxt == SLIP_ESC_ESC: out.append(SLIP_ESC)
            i += 2
        elif b == SLIP_END:
            i += 1
        else:
            out.append(b)
            i += 1
    return bytes(out)

def recv(ser, timeout=5):
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = ser.read(ser.in_waiting or 1)
        if chunk:
            buf.extend(chunk)
            if SLIP_END in buf:
                idx = buf.index(SLIP_END)
                return slip_dec(bytes(buf[:idx + 1]))
    return None

def varint(v):
    r = bytearray()
    while v > 0x7f:
        r.append((v & 0x7f) | 0x80)
        v >>= 7
    r.append(v & 0x7f)
    return bytes(r)

def fv(fn, v):
    return varint((fn << 3) | 0) + varint(v)

def fb(fn, d):
    return varint((fn << 3) | 2) + varint(len(d)) + d

RESULT_NAMES = {
    0x01: "SUCCESS", 0x02: "INVALID_OBJECT", 0x03: "UNSUPPORTED_TYPE",
    0x04: "NOT_PERMITTED", 0x05: "FAILED", 0x06: "EXTENDED_ERROR",
    0x07: "INVALID_PARAM", 0x08: "WRONG_TYPE", 0x0A: "INSUFFICIENT_RESOURCES",
}

EXT_ERROR_NAMES = {
    0x00: "NO_ERROR", 0x01: "INVALID_ERROR_CODE", 0x02: "WRONG_COMMAND_FORMAT",
    0x03: "UNKNOWN_COMMAND", 0x04: "INIT_COMMAND_INVALID",
    0x05: "FW_VERSION_FAILURE", 0x06: "HW_VERSION_FAILURE",
    0x07: "SD_VERSION_FAILURE", 0x08: "SIGNATURE_MISSING",
    0x09: "WRONG_HASH_TYPE", 0x0A: "HASH_FAILED",
    0x0B: "WRONG_SIGNATURE_TYPE", 0x0C: "VERIFICATION_FAILED",
    0x0D: "INSUFFICIENT_SPACE",
}

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
    bin_path = sys.argv[2] if len(sys.argv) > 2 else "/home/pi/nrf-sniffer-fw/application.bin"

    ser = serial.Serial(port, 115200, rtscts=False, timeout=0.5)
    ser.reset_input_buffer()
    time.sleep(0.1)

    # Ping
    ser.write(slip_enc(bytes([0x09, 0x01])))
    r = recv(ser, 2)
    print(f"Ping: {r.hex() if r else 'no response'}")

    # Protocol version
    ser.write(slip_enc(bytes([0x00])))
    r = recv(ser, 2)
    if r:
        print(f"Protocol version response: {r.hex()}")
        if len(r) >= 4:
            print(f"  Protocol version: {r[3]}")

    # MTU
    ser.write(slip_enc(bytes([0x07])))
    r = recv(ser, 2)
    mtu = 244
    if r and len(r) >= 5:
        mtu = struct.unpack_from("<H", r, 3)[0]
        print(f"MTU: {mtu}")

    # PRN=0
    ser.write(slip_enc(bytes([0x02, 0x00, 0x00])))
    r = recv(ser, 2)
    print(f"Set PRN=0: result={RESULT_NAMES.get(r[2], r[2]) if r and len(r) > 2 else '?'}")

    # Read firmware
    with open(bin_path, "rb") as f:
        fw = f.read()
    fw_hash = hashlib.sha256(fw).digest()
    print(f"\nFirmware: {len(fw)} bytes, SHA256: {fw_hash.hex()[:16]}...")

    # Try different hw_version values
    for hw_ver in [52, 0xFFFF, 0, 1, 0x0034]:
        print(f"\n--- Trying hw_version={hw_ver} (0x{hw_ver:04X}) ---")

        hash_pb = fv(1, 3) + fb(2, fw_hash)
        init_cmd = fv(1, 0) + fv(2, 1) + fv(3, hw_ver) + fv(4, 0) + fb(5, hash_pb)
        command = fv(1, 1) + fb(2, init_cmd)
        packet = fb(1, command)

        # Create command object
        ser.write(slip_enc(bytes([0x01, 0x01]) + struct.pack("<I", len(packet))))
        r = recv(ser, 3)
        if not r or len(r) < 3 or r[2] != 0x01:
            rn = RESULT_NAMES.get(r[2], hex(r[2])) if r and len(r) > 2 else "?"
            print(f"  Create FAILED: {rn}")
            continue
        print(f"  Create OK")

        # Write
        ser.write(slip_enc(bytes([0x08]) + packet))
        time.sleep(0.2)

        # CRC
        ser.write(slip_enc(bytes([0x03])))
        r = recv(ser, 2)
        if r and len(r) >= 11:
            dev_off = struct.unpack_from("<I", r, 3)[0]
            dev_crc = struct.unpack_from("<I", r, 7)[0]
            exp_crc = binascii.crc32(packet) & 0xFFFFFFFF
            ok = dev_crc == exp_crc
            print(f"  CRC: offset={dev_off} dev={dev_crc:#010x} exp={exp_crc:#010x} {'OK' if ok else 'MISMATCH'}")
            if not ok:
                continue

        # Execute
        ser.write(slip_enc(bytes([0x04])))
        r = recv(ser, 10)
        if r:
            result = r[2] if len(r) > 2 else 0xFF
            rn = RESULT_NAMES.get(result, hex(result))
            print(f"  Execute: {rn} (raw: {r.hex()})")
            if result == 0x06 and len(r) > 3:
                ext = r[3]
                en = EXT_ERROR_NAMES.get(ext, hex(ext))
                print(f"  Extended error: {en} (0x{ext:02X})")
            if result == 0x01:
                print(f"\n  *** SUCCESS with hw_version={hw_ver}! ***")
                ser.close()
                return
        else:
            print(f"  No response")

    ser.close()
    print("\nAll hw_version attempts failed.")

if __name__ == "__main__":
    main()
