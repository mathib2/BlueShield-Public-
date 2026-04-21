# BlueShield WSU Demo Playbook
## Authorized AirPods Jamming Demonstration — Senior Design Open House

**Prerequisites verified before this demo:**
- ✅ Written permission from Wichita State University
- ✅ Written consent from AirPods owner (team member)
- ✅ Faraday bag / RF-shielded enclosure at demonstration site
- ✅ Supervising faculty present
- ✅ FCC Part 15 §15.5(b) research exception documented

---

## Phase 1: One-time Firmware Flash (before demo day)

The nRF52840 jammer dongle must be flashed with `radio_test` firmware. Do this ONCE:

### Option A — Using Nordic SDK (recommended, canonical)

```bash
# On the Pi (or any Linux dev machine), install tooling:
pip3 install --user west nrfutil

# One-time SDK setup (~2 GB, ~30 min):
mkdir -p ~/ncs && cd ~/ncs
west init -m https://github.com/nrfconnect/sdk-nrf --mr v2.6.0
west update

# Build radio_test for nRF52840 dongle:
cd ~/ncs/nrf/samples/peripheral/radio_test
west build -b nrf52840dongle_nrf52840 -p

# Package as DFU zip for the dongle's USB bootloader:
mkdir -p ~/blueshield-project/tools/nrf_jammer_firmware
nrfutil pkg generate \
  --hw-version 52 --sd-req 0x00 \
  --application build/zephyr/zephyr.hex \
  --application-version 1 \
  ~/blueshield-project/tools/nrf_jammer_firmware/radio_test_nrf52840dongle.zip
```

### Option B — Quick path using a dev machine

If you have a development machine with nRF Connect for Desktop installed:
1. Install "Programmer" app from nRF Connect for Desktop
2. Download `radio_test` firmware .hex from Nordic Developer Portal
3. Put dongle in DFU mode (press reset button)
4. Flash via the Programmer UI

### Flash the dongle (after building):

```bash
# Put dongle in DFU bootloader (press RESET button on the dongle)
# Then flash:
cd ~/blueshield-project
./tools/deploy_nrf_jammer.sh /dev/ttyACM1
```

### Verify:

```bash
screen /dev/ttyACM1 115200
# You should see prompt: radio_test>
# Test:
radio_test> version
radio_test> set_mode nrf_1Mbit
radio_test> set_tx_power 8
radio_test> start_channel_sweep 2 80 1
# (wait 1 sec)
radio_test> stop
# Exit screen: Ctrl+A, K, Y
```

---

## Phase 2: Pre-demo Hardware Setup

### Hardware allocation:
- **Raspberry Pi 3**: BlueShield dashboard host (ethernet or WiFi)
- **nRF52840 #1 (/dev/ttyACM0)**: Nordic Sniffer firmware (ground-truth packet capture)
- **nRF52840 #2 (/dev/ttyACM1)**: radio_test firmware (the JAMMER)
- **Realtek USB BT5.3 (hci1)**: BLE scanner backup + adv flooder
- **Realtek USB BT5.4 (hci3)**: Secondary adv flooder
- **Pi onboard Bluetooth (hci0)**: Primary scanner

### Software checks:

```bash
ssh pi@blueshield.local
sudo systemctl status blueshield
curl -s http://localhost:8080/api/jammer | python3 -m json.tool
# Should show nrf_available: true
```

### Verify everything is green in the dashboard:
1. Open `http://blueshield.local:8080`
2. Login: admin / admin123
3. Go to Jammer tab → dropdown should show "🎯 AirPods Killer" option
4. Capability hint should say "✓ Real RF jamming — nRF52840 radio_test backend (+8 dBm)"

---

## Phase 3: Demo Day Script (15 minutes)

### Setup at venue (5 min)

1. Place iPhone + AirPods inside Faraday bag with enough slack for the Pi to also be inside or at least close
2. Power on Pi 3, wait for auto-start (~30s)
3. Connect your laptop to `blueshield.local:8080` (or phone hotspot "BlueShield")
4. Confirm AirPods appear in dashboard with tracker confidence 40%+

### Part A: Detection — "We can see what you have" (3 min)

Open the dashboard. Point out:

1. **Device table** — AirPods Pro 2 appearing with 7+ correlated MAC addresses
2. **AI Correlation bar** — Shows 40+ physical devices, X merges via neural similarity model
3. **Tracker Detection panel** — Apple AirTag signature matching at 40% confidence
4. **Device Life Story** — Click on AirPods row:
   - Shows Apple manufacturer ID 0x004C
   - Shows Proximity Pairing TLV type 0x07
   - Device model decoded (e.g., 0x1420 = AirPods Pro 2)
   - Full MAC rotation history
5. **Proximity Radar** — Live RSSI-based positioning

**Talking points:**
- "This detection engine runs entirely passive — no packets sent"
- "Picks up on Apple's Continuity Protocol based on work by Martin et al. PoPETs 2020"
- "Uses a neural similarity model (our own contribution) to track devices across MAC randomization"

### Part B: Protocol Analysis — "We know how they work" (3 min)

Show in the dashboard:

1. **Channels tab** — Live BLE channel activity, channels 37/38/39 highlighted
2. **Sniffer tab** — If you want to be fancy: Wireshark with furiousMAC dissector
3. **Explain**:
   - AirPods use A2DP over Classic Bluetooth (BR/EDR) for audio
   - 79 channels, 1600 hops/sec, Adaptive Frequency Hopping
   - BLE side is just for pairing/handoff (Continuity Protocol)
   - Reference: **Heinze et al., ACM WiSec 2020 — MagicPairing reverse engineering**

### Part C: The Jam — "We can break them" (4 min)

**Setup**: Start playing music through the AirPods from the iPhone (inside the Faraday bag). Have laptop showing the spectrogram of the audio (optional).

**Execute**:

1. On dashboard → Jammer tab → select **"🎯 AirPods Killer"** mode
2. Capability hint should say: *"✓ Real RF jamming — nRF52840 radio_test backend"*
3. Click **▶ Start Jammer**

**What the audience will hear** (if Faraday is partial) or see (audio spectrogram):
- Within 2-4 seconds: audio starts stuttering
- Within 4-6 seconds: AFH collapses, audio silent
- AirPods on iPhone show as "disconnected"

**Behind the scenes** (what to explain):
- nRF52840 is sweeping channels 2-80 at 1ms dwell per channel
- Every BR/EDR channel hit every ~79ms
- +8 dBm TX power
- AirPods AFH needs ≥20 "good" channels but every channel has interference
- Link supervision timeout → disconnect

4. Click **⏹ Stop Jammer**
5. Within 5-10 seconds, audio resumes

**Repeat 2 times** to show reproducibility.

### Part D: Defensive Framing — "That's why detection matters" (3 min)

Return to the dashboard's main Live view:

1. Show that your own jammer appears as a "Stealth Device" or "Critical Alert" in BlueShield's own detection feed
2. Show the timeline of events during the jam
3. **Thesis statement**:
   - "Any bad actor doing this to someone's AirPods in a public place is detectable"
   - "BlueShield is the detection platform that notices"
   - "The jamming demo you just saw is how we learned what to detect"

### Part E: Q&A (2 min)

Prepared answers:

**Q: "Is this legal?"**
A: FCC Part 15 §15.5(b) prohibits unauthorized jamming. Our demo is conducted under:
- Written permission from device owner
- Written WSU research authorization
- Shielded Faraday enclosure
- Supervising faculty sign-off
- Research exception documented in project report

**Q: "Why doesn't this work on Apple's security chip?"**
A: It's not an attack on the H1/H2/W1 chip — it's an RF-layer physics attack. We don't exploit a protocol bug (published CVEs like KNOB, BIAS, BrakTooth are patched). We saturate the frequency space so Adaptive Frequency Hopping cannot find clean channels.

**Q: "What about our other devices?"**
A: The attack disrupts 2.4 GHz. In the Faraday bag, only AirPods + iPhone are affected. Outside a shielded environment, this would affect nearby WiFi and Zigbee too — which is exactly why the FCC regulates it.

**Q: "How is this different from commercial jammers?"**
A: Commercial illegal jammers use simple transmitters on fixed frequencies — AFH routes around them. Our approach, based on Cayre et al. DSN 2021 and Nordic's `radio_test` sample, actively sweeps the full band at 1ms dwell to defeat AFH. Software-defined, not hardware-defined.

---

## Phase 4: Post-demo Cleanup

```bash
# Kill switch — ensures no RF emission after demo ends
ssh pi@blueshield.local "curl -s -c /tmp/c.txt -d 'username=admin&password=admin123' http://localhost:8080/login >/dev/null && curl -s -b /tmp/c.txt -X POST http://localhost:8080/api/jammer/stop"

# Or hard stop:
ssh pi@blueshield.local "sudo systemctl stop blueshield"
```

Document in project log:
- Time started / stopped
- Devices affected
- Observed audio dropouts count
- Any anomalies

---

## Academic Citations to Reference

For the senior design report, cite:

1. **Cauquil, D.** *"Defeating Bluetooth Low Energy 5 PRNG for Fun and Jamming."* DEF CON 27, 2019.
2. **Cayre, R. et al.** *"InjectaBLE: Injecting Malicious Traffic into Established BLE Connections."* IEEE/IFIP DSN 2021.
3. **Heinze, D. et al.** *"MagicPairing: Apple's Take on Securing Bluetooth Peripherals."* ACM WiSec 2020.
4. **Martin, J. et al.** *"Handoff All Your Privacy."* PoPETs 2020.
5. **Nordic Semiconductor** nRF Connect SDK `radio_test` sample, [docs.nordicsemi.com](https://docs.nordicsemi.com).

---

## Fail-safe Checklist

Before any jam command:
- [ ] Device in Faraday bag
- [ ] All bystanders at least 10 ft away
- [ ] Only AirPods + iPhone in the bag (no WiFi-dependent devices)
- [ ] Sniffer running for audit trail
- [ ] Stop button accessible
- [ ] Demonstrator on the "Stop" click within 1 second reach

---

*Reviewed and approved by supervising faculty: _____________________ Date: _______*

*Team lead signature: _____________________ Date: _______*
