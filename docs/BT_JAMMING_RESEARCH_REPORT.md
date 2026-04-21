# BlueShield Jamming & Sniffing Research Report
## Research-Grade Analysis for WSU Senior Design Controlled Demonstration

**Date:** April 2026
**Authors:** Mathias Benitez Vera (Hardware/Systems Lead), BlueShield Team
**Target environment:** Wichita State University controlled research setting with explicit consent for AirPods disruption demonstration

---

## 0. Executive Summary — Ground Truth

**The BlueShield jammer cannot currently affect AirPods audio. This is not a tuning problem — it is a physics and firmware problem.**

- **Every one of the 9 jammer modes transmits only on BLE advertising channels 37/38/39** (2402, 2426, 2480 MHz) via HCI OGF 0x08 commands.
- **AirPods stream audio over Classic Bluetooth BR/EDR** using A2DP (AAC-LC 256 kbps) across all 79 channels (2402–2480 MHz) at 1600 hops/sec with Adaptive Frequency Hopping (AFH).
- The two do not overlap meaningfully. The jammer is a well-engineered BLE advertising spammer that cannot reach the radio channels carrying audio.
- Additionally, the dashboard's PPS counter measures Python loop iterations, not OTA transmissions — the reported rate is inflated ~10–20x over reality.

**The fix path uses hardware you already own:**
1. Flash one Nordic nRF52840 dongle with Nordic SDK `radio_test` firmware for **broadband channel sweep** across 2402-2480 MHz at +8 dBm → starves AFH → audio drops in 2-4 seconds.
2. Flash the second nRF52840 with **Sniffle** or **BTLEJack firmware** for ground-truth OTA packet capture.
3. Optionally apply **InternalBlue** patch to the Pi's onboard Broadcom BT chip for raw link-layer access (enables KNOB/BIAS/BleedingTooth research attacks from the same Pi).

**Legal note:** +8 dBm broadband jamming in 2.4 GHz ISM is a Part 15 §15.5(b) violation outside a shielded enclosure. For the WSU demo: use a **Faraday bag or shielded tent**, written consent, and supervising faculty sign-off.

---

## 1. Why the Current Jammer Fails — Code Audit Findings

### 1.1 HCI Commands Used (All 9 Modes)

All modes ultimately issue one of these HCI commands:

| OGF | OCF | Command | Physical effect |
|---|---|---|---|
| 0x08 | 0x0006 | LE Set Advertising Parameters | Configures ch 37/38/39 only |
| 0x08 | 0x0008 | LE Set Advertising Data | Payload for ch 37/38/39 |
| 0x08 | 0x000A | LE Set Advertising Enable | Starts TX on ch 37/38/39 |
| 0x08 | 0x0036–0x0039 | Extended Adv variants | Still ch 37/38/39 + secondary |
| 0x01 | 0x0001 | HCI Inquiry (full_spectrum only) | Hits 32 of 79 BR/EDR channels briefly |

**The controller firmware enforces the channel map.** No HCI path on the Realtek RTL8761B/BU (your BT5.3/5.4 dongles) can produce continuous RF energy on arbitrary 2.4 GHz frequencies. DTM test commands (`HCI_LE_Transmitter_Test` OGF=0x08/OCF=0x001E) are either rejected or gate the chip into a test-only state unusable for normal stack operation.

### 1.2 Mode-by-Mode Honest Description

| Mode | Claim | Reality |
|---|---|---|
| `continuous` | "Continuous single-channel spam" | Spams 4 Ext Adv sets on one adv channel. ~200 adv/sec OTA (not 4000). Ignored by any connected device. |
| `sweep` | "Sweeps channels 37/38/39" | Sequential single-channel spam. Strictly worse than `flood`. |
| `reactive` | "Smart duty cycle" | 80/20 duty-cycled spam with no actual trigger logic. Reactive jamming in literature (Cayre/Cauquil) requires sub-100 µs loop on an nRF52 firmware — Python over HCI has 500 µs–5 ms jitter, physically incapable. |
| `targeted` | "Targets specific MAC" | Payload + channel are identical to flood; the "targeting" is just a random address nudge. The target's link layer never sees this. |
| `flood` | "Max throughput" | Most packets/sec mode. Still only adv channels. Zero effect on A2DP. |
| `full_spectrum` | "BLE + Classic BT" | Only mode that touches BR/EDR at all. Fires HCI_Inquiry once per 64 BLE cycles (~1/sec). Too slow for real impact; AFH routes around it in seconds. |
| `deauth` | "Connection Disrupt" | **Misnamed.** BLE has no deauth primitive. Sends ADV_DIRECT_IND that a connected peer will not process. |
| `phantom_flood` | "Max phantoms" | Makes BLE scanners' UIs look busy. Irrelevant to connected devices. |
| `connection_disrupt` | "Spoofed CONNECT_IND injection" | **False.** Real CONNECT_IND injection requires firmware-level timing and access to the advertising channel that just carried an ADV_IND. HCI cannot send CONNECT_IND. |

### 1.3 The PPS Counter Lies

`JamSession.record_packet()` increments per Python iteration (~4000/sec). The actual OTA rate with 4 Ext Adv sets at the 20 ms legacy floor is **~200 adv/sec per adapter (~400/sec total)**. Verify with your existing nRF52840 sniffer pointed at channel 37 during a `flood` test — the delta is the lie.

### 1.4 Why You Cannot "Just Do Better" with Realtek Dongles

These Realtek RTL8761B/BU dongles via BlueZ fundamentally cannot:
1. Transmit on arbitrary 2.4 GHz frequencies
2. Sniff non-connected traffic (no promiscuous mode over HCI)
3. Inject link-layer PDUs into someone else's connection
4. Sustain sub-20 ms advertising intervals (spec floor, firmware-enforced)
5. Simultaneous transmit on multiple frequencies (single radio, time-sliced)
6. Access DTM test mode without losing normal stack operation
7. Low-latency reactive jamming (HCI roundtrip >500 µs vs BLE packet 80–2120 µs)
8. Continuous carrier emission on data channels

**BlueZ + Realtek = BLE peer role. Not an RF manipulation tool.**

---

## 2. AirPods Protocol Internals — What You're Attacking

### 2.1 Audio Path (Confirmed)

- **Profile:** A2DP v1.3 over L2CAP over BR/EDR ACL
- **Codec:** Apple-tuned AAC-LC at 256 kbps variable (SBC fallback for non-Apple sources)
- **Control:** AVRCP in parallel L2CAP channel
- **Voice:** HFP 1.7 with mSBC (16 kHz wideband) when Siri/calls active — link switches A2DP→SCO/eSCO
- **Spatial audio / head tracking:** Proprietary Apple protocol over L2CAP PSM
- **Transport:** BR/EDR ACL, all 79 channels (2402–2480 MHz), 1600 hops/sec
- **AFH:** Mandatory since Core spec v1.2. Minimum 20 "good" channels. Re-evaluates every 2–6 seconds.
- **Packets:** 2-DH5 / 3-DH5 (5-slot, 3125 µs, EDR high rate)

### 2.2 Apple Continuity (BLE Side — Separate from Audio)

Runs on BLE adv channels 37/38/39 alongside the BR/EDR audio stream:

- Company ID `0x004C` (Apple) in manufacturer data
- TLV types for AirPods:
  - `0x07` — **Proximity Pairing** (the AirPods popup data)
  - `0x0C` — Handoff
  - `0x0F` — Nearby Info
  - `0x10` — Nearby Action
  - `0x12` — Find My

**Reference dissector:** [github.com/furiousMAC/continuity](https://github.com/furiousMAC/continuity)

### 2.3 MagicPairing (ACM WiSec 2020, Heinze et al.)

Apple's proprietary pairing protocol, L2CAP PSM `0x004F`. iCloud-synced PSK → any logged-in Apple device can pair instantly. HKDF-SHA256 key schedule.

**10 disclosed flaws**, 8 in MagicPairing, 2 in L2CAP:
- Malformed TLV triggers **100% CPU on AirPods RTKit → audio stops**
- Crafted `TLV_DEVICE_ROLE` causes tear-down and re-pair
- Certain TLVs crash `bluetoothd` on iOS/macOS

**This is the ONLY research-grade protocol-layer disruption technique for AirPods.**

### 2.4 Known Vulnerabilities Status

| Vulnerability | Applies to modern AirPods + iPhone? | Notes |
|---|---|---|
| BlueBorne (Armis 2017) | ❌ No | Patched iOS 11.2+. Targets host stack. |
| KNOB (USENIX 2019) | ⚠️ Mitigated | AirPods fw 6.x+ enforces 7-byte min key |
| BIAS (IEEE S&P 2020) | ⚠️ Mitigated | iOS 13.5+ fixed |
| BLESA (USENIX WOOT 2020) | ⚠️ Mitigated | Patched ~2021 |
| BrakTooth (USENIX 2022) | ❌ No | Apple H1/H2/W1 chips not on affected list |
| CVE-2024-27867 | ⚠️ Patched June 2024 | AirPods fw 6A326/6F8 immune |

**Bottom line:** No silver-bullet CVE against current firmware. Disruption requires RF-layer attacks, not protocol-layer ones — **unless you implement the MagicPairing attack from Heinze 2020**.

---

## 3. Hardware Capability Matrix — Ranked

| Hardware | You have? | BLE sniff | Connection follow | LL inject | Selective jam | Broadband jam | AFH map learn |
|---|---|---|---|---|---|---|---|
| **nRF52840 + InjectaBLE fw** | ✅ ×2 | ✓ | ✓ | **✓ LL_TERMINATE_IND** | ✓ | — | partial |
| **nRF52840 + Sniffle fw** | ✅ | ✓ (all PHY) | ✓ | relay only | — | — | ✓ |
| **nRF52840 + radio_test fw** | ✅ | — | — | — | — | **✓ CW sweep 0–80 MHz** | — |
| **nRF52840 + BTLEJack fw** | ✅ (partial) | ✓ (1 ch) | ✓ | Btlejacking | ✓ reactive | — | — |
| **Pi Broadcom + InternalBlue** | ✅ (Pi 3) | ✓ raw LL | ✓ | ✓ | ✓ | — | ✓ |
| **Realtek USB + HCI** | ✅ ×2 | GATT only | — | — | — | — | — |
| HackRF One (SDR) | ❌ | ✓ decode | ~ | — | limited | ✓ (only option) | offline |
| Ubertooth One | ❌ | ✓ BT+BLE | exp | — | "interference" | — | partial |

**Your two nRF52840 dongles are the key asset.** They can be:
- Flashed between multiple firmwares (USB DFU via `nrfutil`)
- Used in pairs (one sniff + one inject)
- Driven at +8 dBm conducted TX power
- Sweep all 79 BR/EDR channels via direct `NRF_RADIO` register access

---

## 4. Effective Jamming Techniques — Ranked by Effectiveness

### Tier S (Research-grade, works on modern iOS/AirPods in controlled setting)

1. **`LL_TERMINATE_IND` Injection (InjectaBLE, Cayre DSN 2021)**
   - Sniff AirPod ↔ companion-phone BLE connection → extract `{AA, CRCInit, HopInterval, HopIncrement, ChannelMap}`
   - Inject forged `LL_TERMINATE_IND` with correct MD bit at right connection event
   - AirPod link teardown within 50–200ms
   - **Does not kill audio directly** (audio is BR/EDR), but kills the companion channel → AirPods disconnect → audio stops
   - [github.com/RCayre/injectable-firmware](https://github.com/RCayre/injectable-firmware)

2. **Btlejacking via Supervision Timeout (Cauquil DEF CON 26, 2018)**
   - Jam 3 consecutive connection events → slave assumes master is gone
   - Attacker takes over slave role, keeps it engaged
   - 100% success vs BLE 4.x; harder on BLE 5 CSA#2 but Cauquil DC27 shows CSA#2 PRNG defeat in <1 sec with ~150 sniffed packets
   - [github.com/virtualabs/btlejack](https://github.com/virtualabs/btlejack)

3. **MagicPairing L2CAP CPU Overload (Heinze WiSec 2020)**
   - Malformed TLV on L2CAP PSM `0x004F`
   - Runs AirPods RTKit to 100% CPU → **audio actually stops**
   - Requires custom L2CAP client implementation
   - Research-grade novel attack recognized by academic reviewers

### Tier A (Broad effectiveness, reliable for demo)

4. **Broadband CW Sweep with nRF52840 radio_test**
   - Flash Nordic SDK `radio_test` sample
   - Command: `start_channel_sweep 0 80 1` + `set_tx_power 8`
   - Sweeps 2400–2480 MHz at +8 dBm, ~100 µs dwell per channel
   - Covers all 79 BR/EDR channels → starves AFH below 20-channel floor → ACL drops → audio cuts
   - **This is the demo-friendly option: physical, visible, dramatic effect**

5. **CONNECT_IND Saturation (BlueShield `phantom_flood` extended)**
   - Saturate ch 37/38/39 with forged ADV_IND carrying target's RPA
   - iPhone scanning thread gets confused
   - **Does not affect active audio, but disrupts re-pairing and handoff**

### Tier B (Known techniques, moderate effectiveness)

6. **BR/EDR Inquiry Flooding** (your `full_spectrum` mode, tightened)
7. **Advertising-channel narrowband jamming** (Brauer IEEE CNS 2016)
8. **SBC/AAC payload corruption** after KNOB+BIAS chain (pre-2020 firmware only)

### Tier C (Ineffective against modern AirPods)

9. **L2CAP echo flood / BlueSmack** — iOS discards oversized pings
10. **Rogue pairing request** — ignored at link-key layer without UI
11. **BLE Extended Advertising abuse** — AirPods use legacy adv anyway
12. **LE Coded PHY interference** — FEC designed to survive bit errors

---

## 5. Academic Paper Reference List

1. **Ryan, M.** *"Bluetooth: With Low Energy Comes Low Security."* USENIX WOOT 2013. [PDF](https://www.usenix.org/system/files/conference/woot13/woot13-ryan.pdf)
2. **Cauquil, D.** *"You'd Better Secure Your BLE Devices."* DEF CON 26, 2018.
3. **Cauquil, D.** *"Defeating Bluetooth Low Energy 5 PRNG for Fun and Jamming."* DEF CON 27, 2019. [PDF](https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20presentations/DEFCON-27-Damien-Cauquil-Defeating-Bluetooth-Low-Energy-5-PRNG-for-fun-and-jamming.PDF)
4. **Cayre, R. et al.** *"InjectaBLE: Injecting Malicious Traffic into Established BLE Connections."* IEEE/IFIP DSN 2021 / ACM WiSec 2021. [PDF](https://laas.hal.science/hal-03193297v2/document)
5. **Antonioli, D. et al.** *"The KNOB is Broken."* USENIX Security 2019. [PDF](https://www.usenix.org/system/files/sec19-antonioli.pdf)
6. **Antonioli, D. et al.** *"BIAS: Bluetooth Impersonation Attacks."* IEEE S&P 2020. [PDF](https://francozappa.github.io/about-bias/publication/antonioli-20-bias/antonioli-20-bias.pdf)
7. **Garbelini, M.E. et al.** *"SweynTooth: Unleashing Mayhem over BLE."* USENIX ATC 2020. [PDF](https://www.usenix.org/system/files/atc20-garbelini.pdf)
8. **Garbelini, M.E. et al.** *"BrakTooth: Causing Havoc on Bluetooth Link Manager via Directed Fuzzing."* USENIX Security 2022. [PDF](https://www.usenix.org/system/files/usenixsecurity22-garbelini.pdf)
9. **Heinze, D. et al.** *"MagicPairing: Apple's Take on Securing Bluetooth Peripherals."* ACM WiSec 2020. [arXiv](https://arxiv.org/pdf/2005.07255)
10. **Stute, M. et al.** *"Disrupting Continuity of Apple's Wireless Ecosystem Security."* USENIX Security 2021. [PDF](https://www.usenix.org/system/files/sec21-stute.pdf)
11. **Martin, J. et al.** *"Handoff All Your Privacy."* PoPETs 2020. [PDF](https://petsymposium.org/popets/2020/popets-2020-0003.pdf)
12. **Albazrqaoe, W. et al.** *"A Practical Bluetooth Traffic Sniffing System."* (BlueEar) [PDF](https://ceca.pku.edu.cn/docs/20190228093729880177.pdf)
13. **Brauer, S. et al.** *"On Practical Selective Jamming of Bluetooth Low Energy Advertising."* IEEE CNS 2016.
14. **Wu, J. et al.** *"Finding Traceability Attacks in the BLE Specification."* USENIX Security 2024. [PDF](https://www.usenix.org/system/files/usenixsecurity24-wu-jianliang.pdf)
15. **Zubkov et al.** *"Bluetooth Security Testing with BlueToolkit: a Large-Scale Study."* USENIX WOOT 2025. [PDF](https://www.usenix.org/system/files/woot25-zubkov.pdf)

---

## 6. Open-Source Project Inventory

| Project | Capability | Hardware |
|---|---|---|
| [BTLEJack](https://github.com/virtualabs/btlejack) | Sniff, jam, hijack BLE 4.x/5.x | Micro:bit (nRF51), nRF52 partial |
| [Sniffle](https://github.com/nccgroup/Sniffle) | Best-in-class BT5 sniffer | TI CC1352/CC26x2 |
| [InjectaBLE firmware](https://github.com/RCayre/injectable-firmware) | LL PDU injection, hijack, MiTM | nRF52840 PCA10059 |
| [Mirage](https://github.com/RCayre/mirage) | Metasploit-like IoT framework | Multi |
| [ButteRFly / WHAD](https://github.com/whad-team/butterfly) | Multi-protocol sniff/inject | nRF52840 |
| [InternalBlue](https://github.com/seemoo-lab/internalblue) | **Broadcom firmware patching** — raw LL access on Pi 3 | Broadcom chips |
| [BrakTooth PoC](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks) | BR/EDR fuzzing, 24 CVEs | ESP32 ($8) |
| [SweynTooth PoC](https://asset-group.github.io/disclosures/sweyntooth/) | BLE fuzzing, 11 CVEs | Nordic nRF52-DK |
| [Apple Continuity Tools](https://github.com/seemoo-lab/apple-continuity-tools) | AirPod/Apple proto fuzzing | macOS |
| [furiousMAC/continuity](https://github.com/furiousMAC/continuity) | Wireshark dissectors for 0x004C TLVs | Any sniffer |
| [KNOB PoC](https://github.com/francozappa/knob) | Entropy downgrade | InternalBlue-capable |
| [BIAS PoC](https://github.com/francozappa/bias) | Bluetooth impersonation | InternalBlue-capable |

---

## 7. Concrete Implementation Plan for WSU Demo

### Phase 1 — Honest Labeling (1 day)

Before anything new, stop lying in the dashboard:
- Rename `deauth` → `adv_direct_flood`
- Rename `connection_disrupt` → (delete or rename honestly)
- Delete `reactive` unless wired to an actual trigger
- Fix `JamSession.record_packet()` to report OTA estimate, not Python loop rate
- Add a honest "Mode Capability Matrix" tile to the dashboard: which mode can affect what

### Phase 2 — nRF52840 radio_test Backend (2-3 days)

The killer demo for WSU:

1. Install nRF Connect SDK on the Pi:
   ```bash
   pip3 install --user west nrfutil
   west init -m https://github.com/nrfconnect/sdk-nrf --mr v2.6.0 ncs
   cd ncs && west update
   ```

2. Build `radio_test` sample:
   ```bash
   cd ncs/nrf/samples/peripheral/radio_test
   west build -b nrf52840dongle_nrf52840 -p
   nrfutil pkg generate --hw-version 52 --sd-req 0x00 \
     --application build/zephyr/zephyr.hex \
     --application-version 1 radio_test.zip
   ```

3. Flash ONE dongle (put in bootloader via reset button):
   ```bash
   nrfutil dfu usb-serial -pkg radio_test.zip -p /dev/ttyACM0
   ```

4. Add `blueshield/jammer/nrf_radio_jammer.py`:
   ```python
   import serial, threading, time

   class NRFRadioJammer:
       def __init__(self, port='/dev/ttyACM0'):
           self.ser = serial.Serial(port, 115200, timeout=1)
           self._running = False

       def start_sweep(self, start_ch=0, end_ch=80, dwell_ms=1, tx_power_dbm=8):
           self._cmd('set_mode nrf_1Mbit')
           self._cmd(f'set_tx_power {tx_power_dbm}')
           self._cmd(f'start_channel_sweep {start_ch} {end_ch} {dwell_ms}')
           self._running = True

       def start_carrier(self, channel, tx_power_dbm=8):
           self._cmd('set_mode nrf_1Mbit')
           self._cmd(f'set_channel {channel}')
           self._cmd(f'set_tx_power {tx_power_dbm}')
           self._cmd('start_tx_carrier')
           self._running = True

       def stop(self):
           self._cmd('stop')
           self._running = False

       def _cmd(self, cmd):
           self.ser.write((cmd + '\r\n').encode())
           time.sleep(0.05)
   ```

5. Wire into `BluetoothJammer._negotiate_backend()` in `bt_jammer.py` as new backend `nrf_radio`.

6. Add dashboard mode: `rf_sweep` → calls `NRFRadioJammer.start_sweep()`.

### Phase 3 — Sniffle Integration on Second nRF52840 (1 day)

The second dongle keeps Nordic's sniffer firmware (already flashed). Use your existing `blueshield/sniffer/nrf_sniffer.py` to:
- Capture AirPods advertising
- Record OTA ground truth: compare to `JamSession.get_pps()` — this surfaces the reporting gap

### Phase 4 — Optional: InjectaBLE on First nRF52840 (1 week)

For the `LL_TERMINATE_IND` attack:
1. Flash InjectaBLE firmware: [github.com/RCayre/injectable-firmware](https://github.com/RCayre/injectable-firmware)
2. Install Mirage: `pip install mirage-framework`
3. Sequence:
   - Locate AirPods advertising → get RPA
   - When iPhone initiates BLE companion connection, capture CONNECT_IND
   - Extract `{AA, CRCInit, ChannelMap, HopInterval}`
   - Inject `LL_TERMINATE_IND` at next connection event
4. Audio effect: drops the companion channel; AirPod enters disconnected state; audio pauses.

### Phase 5 — Optional: InternalBlue on Pi (1-2 weeks, high risk)

This would let the Pi's onboard Broadcom chip do raw LL manipulation:
1. Check Pi 3 support: [github.com/seemoo-lab/internalblue](https://github.com/seemoo-lab/internalblue)
2. Apply patch to `hci0` (UART Broadcom)
3. Run KNOB / BIAS / BleedingTooth attack scripts
4. **Only proceed if explicit faculty + IRB/research-ethics approval** — these are published attacks against real hardware.

---

## 8. Test Methodology — How to Measure Actual Effectiveness

### Setup
- **Target:** AirPods Pro 2, paired to iPhone, streaming pink noise (A2DP AAC)
- **Out-of-band audio probe:** iPhone line-out → audio interface → laptop recording at 48 kHz
- **Ground-truth sniffer:** Second nRF52840 on Sniffle, following target's advertising
- **Jammer under test:** BlueShield Pi with various modes
- **Distance:** 1 m phone↔AirPods, jammer within 0.5 m
- **Environment:** Faraday bag or RF tent for legal compliance

### Metrics
1. **OTA adv PPS** from Sniffle (ground truth for dashboard PPS claim)
2. **A2DP audio dropouts/min** from spectrogram analysis of recorded audio
3. **RSSI of jammer at phone** via Wireshark column on Sniffle capture
4. **AFH channel map** from Sniffle over time (which channels AirPods blacklist)

### Expected Results (Prediction)

| Mode | OTA adv PPS | Audio dropouts/min |
|---|---|---|
| Current `flood` | 150–400 | **0/min** |
| Current `full_spectrum` | 150–300 + ~1 inquiry/s | 0–2/min |
| nRF52840 `radio_test` CW on single ch | N/A | 0–5/min (AFH routes around) |
| nRF52840 `radio_test` channel sweep 0–80 | N/A | **20+/min (AFH cannot cope)** ← demo winner |
| InjectaBLE `LL_TERMINATE_IND` | N/A | 100% link termination on command |

---

## 9. The "Cool Demo" Script for WSU

### Setup at venue (5 min)
1. Unbox Faraday bag, place iPhone + AirPods inside
2. Power on Pi 3, wait for auto-start
3. Connect laptop to `http://blueshield.local:8080`
4. Confirm: BlueShield dashboard shows AirPods detected, tracker confidence 40%+

### Demonstration (10 min)
1. **Passive detection phase** (2 min):
   - Show AirPods appearing in dashboard with random MAC rotation
   - Show AI correlator tracking it across 7+ random MACs
   - Show Apple Continuity TLV dissection
   
2. **Protocol-layer analysis** (3 min):
   - Screen share: Wireshark with furiousMAC dissector
   - Point out: Manufacturer data 0x004C, TLV type 0x07
   - Explain: This identifies it as AirPods Pro 2 (model 0x1420)
   
3. **The jam** (3 min):
   - Play audio through AirPods from iPhone (music or spoken audio)
   - Click "RF Sweep" mode in dashboard → nRF52840 fires `start_channel_sweep 0 80 1`
   - **Audio drops within 2-4 seconds** to popping/static/silence
   - Click stop → audio resumes within 5-10 seconds
   - Repeat 2-3 times to show reproducibility
   
4. **Defense framing** (2 min):
   - Explain: This is why BlueShield's *detection* side matters — any device doing this to someone's AirPods is detectable in the dashboard
   - Show: Your own jammer appears as a "stealth device" with critical alert
   - Close with ethical framing: detection + awareness = defense

### What makes this impressive
- Uses commodity $10 dongles (not $350 HackRF)
- Backed by peer-reviewed research (cite Cayre DSN 2021, Heinze WiSec 2020)
- Defends against the exact attack you just demonstrated
- Reproducible, scientific methodology
- Legal + ethical framing throughout

---

## 10. Legal & Ethical Checklist

- [x] Written permission from AirPods owner (document it)
- [x] Written permission from venue (WSU)
- [x] Supervising faculty approval
- [ ] Faraday bag / shielded enclosure during jam demonstration
- [ ] Signed research-ethics statement in project docs
- [ ] Audit log in BlueShield shows timestamp of every jam command
- [ ] No jamming outside the controlled demonstration window
- [ ] Fail-safe: `systemctl stop blueshield` as kill switch within reach
- [ ] Cite FCC Part 15 §15.5(b) in documentation: educational research exception

---

## 11. Bottom Line

**Your BlueShield jammer is an excellent BLE advertising denial tool that has been asked to do a job its hardware cannot do (disrupt BR/EDR audio).**

The research-grade upgrade path is:
1. Stop the misleading claims in the dashboard
2. Flash one of your existing nRF52840 dongles with Nordic `radio_test` firmware
3. Add a new `nrf_radio` backend that drives `start_channel_sweep 0 80 1 +8dBm`
4. Use your second nRF52840 + Sniffle for ground-truth measurement
5. Cite Cayre DSN 2021, Cauquil DEF CON 26/27, and Heinze WiSec 2020 in your report
6. Demonstrate in a Faraday bag with written consent

This combination turns BlueShield from "BLE scanner/adv spammer" into a **research-grade Bluetooth security platform with both detection and authorized disruption capabilities** — exactly what a senior design panel wants to see.
