#!/usr/bin/env python3
"""
Minimal Nordic nRF52840 DFU Serial Flasher
==========================================
Speaks the Nordic Secure DFU serial protocol (SLIP-framed) to flash
firmware onto an nRF52840 dongle in Open DFU Bootloader mode.

Protocol reference:
  nRF5 SDK v17 — lib_dfu_transport_serial
  SLIP framing: 0xC0 delimiters (RFC 1055 variant for DFU)

Usage:
  python3 nrf_dfu_flash.py --port /dev/ttyACM0 --bin application.bin --dat application.dat
"""

import argparse
import struct
import sys
import time

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Run: pip install pyserial")
    sys.exit(1)


# ── SLIP framing (RFC 1055 — standard DFU variant) ──────────────────────────

SLIP_END     = 0xC0
SLIP_ESC     = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD


def slip_encode(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == SLIP_END:
            out.extend([SLIP_ESC, SLIP_ESC_END])
        elif b == SLIP_ESC:
            out.extend([SLIP_ESC, SLIP_ESC_ESC])
        else:
            out.append(b)
    out.append(SLIP_END)
    return bytes(out)


def slip_decode(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == SLIP_ESC and i + 1 < len(data):
            nxt = data[i + 1]
            if nxt == SLIP_ESC_END:
                out.append(SLIP_END)
            elif nxt == SLIP_ESC_ESC:
                out.append(SLIP_ESC)
            else:
                out.append(b)
                out.append(nxt)
            i += 2
        elif b == SLIP_END:
            i += 1
            continue
        else:
            out.append(b)
            i += 1
    return bytes(out)


# ── DFU Protocol opcodes ────────────────────────────────────────────────────

NRF_DFU_OP_PROTOCOL_VERSION  = 0x00
NRF_DFU_OP_OBJECT_CREATE     = 0x01
NRF_DFU_OP_RECEIPT_NOTIF_SET = 0x02
NRF_DFU_OP_CRC_GET           = 0x03
NRF_DFU_OP_OBJECT_EXECUTE    = 0x04
NRF_DFU_OP_OBJECT_SELECT     = 0x06
NRF_DFU_OP_MTU_GET           = 0x07
NRF_DFU_OP_OBJECT_WRITE      = 0x08
NRF_DFU_OP_PING              = 0x09
NRF_DFU_OP_RESPONSE          = 0x60

# Object types
NRF_DFU_OBJ_TYPE_COMMAND = 0x01
NRF_DFU_OBJ_TYPE_DATA    = 0x02

# Result codes
NRF_DFU_RES_SUCCESS             = 0x01
NRF_DFU_RES_INVALID_OBJECT      = 0x02
NRF_DFU_RES_UNSUPPORTED_TYPE    = 0x03
NRF_DFU_RES_OPERATION_NOT_PERM  = 0x04
NRF_DFU_RES_OPERATION_FAILED    = 0x05
NRF_DFU_RES_EXTENDED_ERROR      = 0x06

RESULT_NAMES = {
    0x01: "SUCCESS",
    0x02: "INVALID_OBJECT",
    0x03: "UNSUPPORTED_TYPE",
    0x04: "OPERATION_NOT_PERMITTED",
    0x05: "OPERATION_FAILED",
    0x06: "EXTENDED_ERROR",
    0x07: "INVALID_PARAM",
    0x08: "WRONG_OBJECT_TYPE",
    0x0A: "INSUFFICIENT_RESOURCES",
    0x0B: "INVALID_OBJECT",
}


# ── CRC-32 (same as zlib) ──────────────────────────────────────────────────

import binascii

def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


# ── DFU Serial Transport ───────────────────────────────────────────────────

class NrfDfuSerial:
    def __init__(self, port: str, baud: int = 115200, timeout: float = 5.0):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.ser = None
        self.mtu = 0
        self.ping_id = 0

    def open(self):
        self.ser = serial.Serial(
            port=self.port,
            baudrate=self.baud,
            rtscts=False,
            timeout=0.5,
        )
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        time.sleep(0.1)

        # Ping to sync
        if not self._ping():
            raise RuntimeError("Dongle did not respond to ping — is it in DFU mode?")

        # Get MTU
        self.mtu = self._get_mtu()
        print(f"  MTU: {self.mtu} bytes")

        # Disable receipt notifications (simplifies the protocol)
        self._set_prn(0)

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def _send(self, data: bytes):
        encoded = slip_encode(data)
        self.ser.write(encoded)
        self.ser.flush()

    def _recv(self, timeout: float = None) -> bytes:
        if timeout is None:
            timeout = self.timeout
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            chunk = self.ser.read(self.ser.in_waiting or 1)
            if not chunk:
                continue
            buf.extend(chunk)
            # Look for SLIP_END delimiter
            if SLIP_END in buf:
                # Extract up to the first END
                idx = buf.index(SLIP_END)
                frame = bytes(buf[:idx + 1])
                return slip_decode(frame)
        raise TimeoutError(f"No response within {timeout}s")

    def _ping(self) -> bool:
        self.ping_id = (self.ping_id + 1) & 0xFF
        try:
            self._send(bytes([NRF_DFU_OP_PING, self.ping_id]))
            resp = self._recv(timeout=2.0)
            if len(resp) >= 3 and resp[0] == NRF_DFU_OP_RESPONSE and resp[1] == NRF_DFU_OP_PING:
                return resp[2] == self.ping_id
        except (TimeoutError, Exception):
            pass
        return False

    def _get_mtu(self) -> int:
        self._send(bytes([NRF_DFU_OP_MTU_GET]))
        resp = self._recv()
        if len(resp) >= 5 and resp[0] == NRF_DFU_OP_RESPONSE and resp[2] == NRF_DFU_RES_SUCCESS:
            mtu = struct.unpack_from("<H", resp, 3)[0]
            return mtu
        return 244  # safe default

    def _set_prn(self, prn: int):
        self._send(bytes([NRF_DFU_OP_RECEIPT_NOTIF_SET]) + struct.pack("<H", prn))
        resp = self._recv()
        if resp[0] != NRF_DFU_OP_RESPONSE or resp[2] != NRF_DFU_RES_SUCCESS:
            raise RuntimeError(f"Failed to set PRN: {resp.hex()}")

    def _select_object(self, obj_type: int) -> tuple:
        """Select object type. Returns (max_size, offset, crc32)."""
        self._send(bytes([NRF_DFU_OP_OBJECT_SELECT, obj_type]))
        resp = self._recv()
        if len(resp) < 15 or resp[0] != NRF_DFU_OP_RESPONSE or resp[2] != NRF_DFU_RES_SUCCESS:
            res_name = RESULT_NAMES.get(resp[2], f"0x{resp[2]:02X}") if len(resp) > 2 else "???"
            raise RuntimeError(f"Select object failed: {res_name}")
        max_size = struct.unpack_from("<I", resp, 3)[0]
        offset   = struct.unpack_from("<I", resp, 7)[0]
        crc      = struct.unpack_from("<I", resp, 11)[0]
        return max_size, offset, crc

    def _create_object(self, obj_type: int, size: int):
        self._send(bytes([NRF_DFU_OP_OBJECT_CREATE, obj_type]) + struct.pack("<I", size))
        resp = self._recv()
        if resp[0] != NRF_DFU_OP_RESPONSE or resp[2] != NRF_DFU_RES_SUCCESS:
            res_name = RESULT_NAMES.get(resp[2], f"0x{resp[2]:02X}") if len(resp) > 2 else "???"
            raise RuntimeError(f"Create object failed: {res_name}")

    def _write_data(self, data: bytes):
        """Write data in MTU-sized chunks (no SLIP opcode — raw write)."""
        chunk_size = self.mtu - 1  # leave room for opcode
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + chunk_size]
            self._send(bytes([NRF_DFU_OP_OBJECT_WRITE]) + chunk)
            offset += len(chunk)

    def _get_crc(self) -> tuple:
        """Get current offset and CRC from the bootloader."""
        self._send(bytes([NRF_DFU_OP_CRC_GET]))
        resp = self._recv()
        if len(resp) < 11 or resp[0] != NRF_DFU_OP_RESPONSE or resp[2] != NRF_DFU_RES_SUCCESS:
            raise RuntimeError(f"CRC get failed: {resp.hex()}")
        offset = struct.unpack_from("<I", resp, 3)[0]
        crc    = struct.unpack_from("<I", resp, 7)[0]
        return offset, crc

    def _execute(self):
        self._send(bytes([NRF_DFU_OP_OBJECT_EXECUTE]))
        resp = self._recv(timeout=10.0)  # execute can take time
        if resp[0] != NRF_DFU_OP_RESPONSE or resp[2] != NRF_DFU_RES_SUCCESS:
            res_name = RESULT_NAMES.get(resp[2], f"0x{resp[2]:02X}") if len(resp) > 2 else "???"
            raise RuntimeError(f"Execute failed: {res_name}")

    # ── High-level DFU transfer ────────────────────────────────────────────

    def send_object(self, obj_type: int, data: bytes, label: str = ""):
        """Send a complete DFU object (init packet or firmware data)."""
        max_size, current_offset, current_crc = self._select_object(obj_type)
        print(f"  {label}: max_size={max_size}, offset={current_offset}, crc={current_crc:#010x}")

        # Check if already transferred (resume support)
        if current_offset == len(data) and current_crc == crc32(data):
            print(f"  {label}: Already transferred, executing...")
            self._execute()
            return

        # Transfer in pages (max_size chunks)
        total = len(data)
        offset = 0

        while offset < total:
            page = data[offset:offset + max_size]
            page_size = len(page)

            self._create_object(obj_type, page_size)
            self._write_data(page)

            # Verify CRC
            dev_offset, dev_crc = self._get_crc()
            expected_crc = crc32(data[:offset + page_size])

            if dev_crc != expected_crc:
                raise RuntimeError(
                    f"CRC mismatch at offset {offset + page_size}: "
                    f"device={dev_crc:#010x} expected={expected_crc:#010x}"
                )

            self._execute()
            offset += page_size

            pct = min(100, int(offset / total * 100))
            bar = "#" * (pct // 2) + "-" * (50 - pct // 2)
            print(f"\r  {label}: [{bar}] {pct}%  ({offset}/{total} bytes)", end="", flush=True)

        print()  # newline after progress bar


def flash_firmware(port: str, dat_path: str, bin_path: str, baud: int = 115200):
    """Flash init packet + firmware binary via Nordic DFU serial."""
    with open(dat_path, "rb") as f:
        init_data = f.read()
    with open(bin_path, "rb") as f:
        fw_data = f.read()

    print(f"nRF52840 DFU Flasher")
    print(f"  Port: {port}")
    print(f"  Init packet: {len(init_data)} bytes")
    print(f"  Firmware: {len(fw_data)} bytes")
    print()

    dfu = NrfDfuSerial(port=port, baud=baud)

    print("Opening DFU transport...")
    dfu.open()

    print("Sending init packet...")
    dfu.send_object(NRF_DFU_OBJ_TYPE_COMMAND, init_data, label="Init")

    print("Sending firmware...")
    dfu.send_object(NRF_DFU_OBJ_TYPE_DATA, fw_data, label="Firmware")

    dfu.close()
    print()
    print("Flash complete! Dongle should reboot with new firmware.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="nRF52840 DFU Serial Flasher")
    parser.add_argument("--port", default="/dev/ttyACM0", help="Serial port")
    parser.add_argument("--bin", required=True, help="Firmware binary (.bin)")
    parser.add_argument("--dat", required=True, help="Init packet (.dat)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    args = parser.parse_args()

    try:
        flash_firmware(args.port, args.dat, args.bin, args.baud)
    except Exception as exc:
        print(f"\nERROR: {exc}")
        sys.exit(1)
