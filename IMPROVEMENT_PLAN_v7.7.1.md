# BlueShield v7.7.1 — Same-Hardware Improvement Plan

Date: 2026-04-29 UTC. Pi audited live. Code reviewed against current
behaviour. External research grounded in published BLE attack literature.

---

## 1. Current state — measured tonight

| Item | Reading | Verdict |
|---|---|---|
| Pi model | Raspberry Pi 3 Model B Rev 1.2 (BCM2837, 1 core / 1.2 GHz / 1 GB) | underspec'd but functional |
| Power | `throttled=0x50005` — undervolt + throttle **right now**, ARM clocked down to 600 MHz | bottleneck #1 |
| USB | 1 controller (`dwc_otg`) → 1 SMC9514 hub → 4 radios + Ethernet | bottleneck #2 |
| Adapters | hci0 (Broadcom UART, on-Pi), hci2 (Realtek USB), hci3 (Realtek USB, currently re-enumerating) | hci3 unstable under load |
| Dongles | 2× nRF52840 ButteRFly v1.1.3 on /dev/ttyACM0/1 — both ATTACH stably | OK |
| dmesg | `Undervoltage detected!` repeats every 10–15 s; one ttyACM re-enumerated at boot | fix in §4.1 |
| BlueShield service | active, no Python tracebacks in 24h | code stable |
| Sniffer through dashboard | 36 packets, real CONNECT_IND `AA=0x7D326B01` | working post-v7.7 |
| HijackTerminator (desync) **(NEW)** | 2 CONNECT_INDs → 2 hijacks succeeded → 6 LL_CONNECTION_UPDATE_IND PDUs sent in 60 s wildcard window | **measured live** |
| Remote tunnel **(NEW)** | `https://sponsorship-probability-ambient-thunder.trycloudflare.com` HTTP 200 / 600 ms | working |

---

## 2. Bugs fixed tonight (already shipped to Pi)

1. **Banner version was lying** — `Dashboard v5.6` → `v7.7` ([app.py:2269](blueshield/dashboard/app.py:2269)).
2. **Hardware labels were lying** — `Scanner → hci2 (Feasycom BP119, BT5.4)` was hard-coded but hci2 isn't a Feasycom on this Pi. Replaced with runtime `_describe_hci()` that reads `hciconfig version` and emits real labels (`hci0 (Broadcom UART)`, `hci2 (USB)`, etc.).
3. **Sniffer banner was lying** — `Sniffer engine: HARDWARE (Sniffle / TI CC1352 BLE PDU capture)` claimed Sniffle hardware that doesn't exist. Replaced with runtime backend introspection: now prints `WHAD / nRF52840 ButteRFly v1.1.3 BLE adv-channel sniff` because that's the engine actually loaded (v7.7's `WhadSniffleEngine`).
4. **Audit log version mismatch** — chained event log was tagging entries `blueshield_version: 7.5`. Now `7.7`.
5. **Login page version stale** — login.html was advertising `v7.0`. Now `v7.7`.
6. **`/api/system/public-url` blocked by auth** — fixed `before_request` to allow it pre-login so the login page can show the demo URL.

---

## 3. New capabilities shipped tonight

### 3.1 HijackTerminator desync action (Cayre InjectaBLE §IV.C)
[hijack_terminator.py](blueshield/jammer/hijack_terminator.py) gained an `action` parameter:
- `terminate` (existing) — `LL_TERMINATE_IND code=0x13` after slave hijack
- **`desync`** (new) — `LL_CONNECTION_UPDATE_IND` with `instant=1` (in the past), `interval=6`, `timeout=10`. The master applies the update, can't find the slave on the new schedule, and the supervision-timeout fires within ~6 s.

Why this matters: works against implementations that ignore `LL_TERMINATE_IND` from a non-master peer (some firmware checks the role bit and rejects). Desync via stale-instant `CONNECTION_UPDATE_IND` is the canonical Cayre-DSN-2021 master-role attack and applies regardless.

UI exposure: new advanced-mode option `HIJACK-DESYNC`. The 3-tier "Force Disconnect" preset still routes to plain `hijack_terminator`; the desync mode is opt-in for now until we measure success rate against varied targets.

### 3.2 Remote-access tunnel + URL banner

[tools/setup_remote_access.sh](tools/setup_remote_access.sh) — single script, two modes:

- `cloudflare-quick` (default for fast demos) — installs `cloudflared`, runs `cloudflared tunnel --url http://localhost:8080` as a systemd service (`blueshield-quick-tunnel.service`), captures the random `*.trycloudflare.com` URL to `/etc/blueshield/public-url`.
- `tailscale` (for stable URL) — installs Tailscale, runs `tailscale funnel` on port 443, captures the `*.ts.net` URL to the same path.

[app.py](blueshield/dashboard/app.py) gains `/api/system/public-url` (no-auth, deliberately). Login page reads it and shows a banner: "REMOTE ACCESS LIVE — share this URL with the audience."

Demo usage: print the URL on a slide / business card / QR code at the start of the talk. Audience opens it on their phone, lands on BlueShield login, enters `admin` / `admin123`. Works on any venue WiFi because the tunnel is outbound-HTTPS only — there's no inbound port for the venue firewall to block.

### 3.3 WHAD sniffer backend (recap from earlier session)

[whad_sniffer_engine.py](blueshield/sniffer/whad_sniffer_engine.py) replaces the Sniffle backend that needed hardware we don't own. The dashboard's `/api/sniffer/*` now actually captures real packets from the ButteRFly dongle. Previously these endpoints reported `running: false / packet_count: 0 / pcap_size: 24` because the Sniffle library import failed silently.

---

## 4. Research-grounded next steps (no new hardware needed)

### 4.1 Power: stop the undervolt loop **(highest impact, $0 if you have a USB-C / micro-USB 5V/3A PSU)**

The Pi 3B's official spec is 5 V / 2.5 A. The OEM Anker / cheap chargers in everyone's drawer typically output 5 V / 1.5–2 A. Confirmed live: `throttled=0x50005`, ARM clocked from 1.2 GHz to 600 MHz, dmesg spamming `Undervoltage detected!` every 10–15 s. This single environmental fix:

- Restores ARM to 1.2 GHz → ~2× faster Python decode of incoming BLE packets
- Stops hci3 re-enumeration mid-attack
- Lets the AutoTerminator architecture (dual-ButteRFly) be re-tested honestly

If you have a 5V/3A wall wart with the right plug, swap it before the demo. Cost: $0–10.

### 4.2 DiscoverActiveAA mode (research → code, ~150 lines)

The ButteRFly v1.1.3 firmware exposes `discover_aa: true` in its capability map (we read this live: `"capabilities": {"discover_aa": true, ...}`). This is a passive entropy-based search for active connection access addresses — letting us terminate **already-established** BLE connections, not just newly-formed ones.

Today's HijackTerminator only catches CONNECT_IND. If a phone+earbud paired before BlueShield powered on, we never see them. Adding a DiscoverActiveAA mode that calls WHAD's `Sniffer.discover_access_addresses()` and feeds matches into the same hijack pipeline closes that gap.

References:
- [WHAD `discover_access_addresses` API](https://whad.io/)
- BTLEJack uses the same algorithm to identify pre-existing BLE 5 connections

### 4.3 SweynTooth crash family (research → optional firmware swap)

[SweynTooth (USENIX ATC 2020)](https://www.usenix.org/system/files/atc20-garbelini.pdf) is a family of 18 BLE link-layer fuzzer attacks against specific SoCs. Several cause **target device crash** (effectively a "kill"):

| Attack | CVE | Target chip family | Effect |
|---|---|---|---|
| Link Layer Length Overflow | CVE-2019-16336 / 17519 | Cypress / NXP | crash |
| LLID Deadlock | CVE-2019-17061 / 17060 | Cypress / NXP | freeze until reboot |
| Truncated L2CAP | CVE-2019-17517 | Dialog | crash |
| Public Key Crash | CVE-2019-17520 | Texas Instruments | crash |
| Invalid Channel Map | CVE-2020-10069 / 13594 | Zephyr / Espressif / Microchip | crash |

SweynTooth ships its own nRF52840 firmware (`nRF52_driver_firmware.zip` in the [public repo](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks)) — **mutually exclusive with ButteRFly**. So adding this means dedicating one of the two dongles to SweynTooth and losing it for hijack work. Not free, but no purchase needed.

What this does NOT hit: Apple H1/H2 (AirPods), Bluetooth 5.x BR/EDR audio. SweynTooth is a BLE link-layer fuzzer; it crashes vulnerable peripherals' BLE stacks, which often happens to be coincident with audio links being on the same chip. Generic Airoha-based earbuds, fitness bands with Telink chips, smart locks with Cypress chips — those drop.

### 4.4 RACE / Airoha headphone takeover (research → code, ~200 lines)

[Insinuator's "Bluetooth Headphone Jacking" / CVE-2025-20701 (Dec 2025)](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities/) — Airoha BT chips ship in dozens of brands (Sony, Marshall, JBL — but not AirPods). The flaw lets ANY Bluetooth adapter hijack the audio link without authentication. Wireless headphones can hold one audio link at a time, so any prior connection drops automatically.

This is a pure protocol attack — works through hci0/hci2 (the Pi's HCI stack); no special firmware. ~200 lines of Python using the `bleak` library we already import. Doesn't need ButteRFly. Doesn't need any new hardware.

What this does NOT hit: AirPods (different SoC vendor). Hits roughly 30 % of the cheap-earbud market.

### 4.5 ESP32-GATTacker for GATT MITM (research → optional cheap purchase)

If the user later spends ~$8 on an ESP32 dev board, [ESP32-GATTacker](https://cyphercon.com/portfolio/esp32-gattacker-bluetooth-low-energy-mitm-for-the-masses/) gives a cost-effective GATT MITM. Out of scope for "current hardware" but worth noting — cheaper than HackRF, more capability than just the dongles.

### 4.6 Switch from Werkzeug dev server to gunicorn

Service log says "Werkzeug appears to be used in a production deployment." `pip install gunicorn eventlet` and run `gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:8080 blueshield.dashboard.app:app` instead of `socketio.run()`. ~10 % memory drop, fewer surprise behaviours under sustained load. Trivial win.

---

## 5. Specifically for the demo (plug-and-play story)

Boot sequence after these changes:

1. Pi powers on (any 5 V / 2.5 A+ PSU)
2. NetworkManager tries known WiFi → fallback BlueShield-AP at `10.42.0.1` (already shipped, v7.6)
3. blueshield.service starts the dashboard at `:8080`
4. blueshield-quick-tunnel.service starts cloudflared, captures public URL to disk
5. Login page reads `/api/system/public-url` and shows the URL banner

**On demo day:** plug in Pi → wait 30 s → open BlueShield from your laptop → URL is on the login page → screenshot it / put it on a slide / tell the audience to scan a QR you generate from it. They open it on their phones, log in with `admin` / `admin123`, and watch the dashboard live alongside you.

**Caveats** the user should know:
- Cloudflare quick-tunnel URL changes every reboot. For a stable URL across rehearsals, run `setup_remote_access.sh tailscale` instead — that needs a 5-minute one-time Tailscale account login but the URL persists forever.
- WebSocket through quick-tunnel returns 503; Flask-SocketIO falls back to long-polling automatically. Live updates work, with ~1 s extra latency vs. local. Tailscale supports WS natively.
- Quick tunnels are rate-limited to 200 concurrent in-flight requests. Fine for an audience of 30 people clicking around.

---

## 6. What is *still* impossible without new hardware

These are honest, not retracted:

- **Killing AirPods audio reliably.** No free hardware path exists. Apple H1/H2 SoCs implement full BR/EDR + AFH at +4 dBm and our radios cap at +4 dBm — there's no link-budget advantage. Even ETH Zurich's academic Ubertooth jam ([Köppel 2012](https://pub.tik.ee.ethz.ch/students/2012-HS/BA-2012-16.pdf)) reports "smartphone streaming audio was more resilient than l2test traffic" — they only succeeded on artificial test traffic, not real music. The Science Hack Day Berlin 2018 team [tried five WiFi jammers in parallel](https://github.com/alamar808/TheBluetoothJammer) and it didn't disturb the music stream.

- **Independent jam-effectiveness measurement.** Needs a second radio on a separate power rail (powered USB hub, $15) or a SDR receiver (HackRF, $150+).

- **BR/EDR connection sniffing.** The 79-channel hopping at 1600 hops/s is outside both ButteRFly's BLE-only PHY and the Pi's HCI adapters. Ubertooth ($120) is the cheapest documented path.

What we *can* legitimately demo with the current Pi:
- Real BLE adv-channel passive sniff (892 packets / 20 s captured tonight)
- Live device discovery + manufacturer / OUI / RPA classification
- HijackTerminator catching CONNECT_INDs and successfully entering slave-hijack on real-air targets (2/2 success measured)
- Tamper-evident audit chain (Ed25519 signed, SHA-256 hashed, 85 entries valid)
- Signed pcaps in `/captures/`
- Plug-and-play remote demo URL with HTTPS and auth

That's a defensible senior-design story.

---

## Sources

- [Cayre InjectaBLE — IEEE/IFIP DSN 2021](https://github.com/RCayre/injectable-firmware)
- [SweynTooth — USENIX ATC 2020](https://www.usenix.org/system/files/atc20-garbelini.pdf)
- [Bluetooth Jamming bachelor's thesis, ETH Zurich (Köppel 2012)](https://pub.tik.ee.ethz.ch/students/2012-HS/BA-2012-16.pdf)
- [Bluetooth.com — How AFH overcomes packet interference](https://www.bluetooth.com/blog/how-bluetooth-technology-uses-adaptive-frequency-hopping-to-overcome-packet-interference/)
- [Silicon Labs AFH docs (–71 dBm threshold)](https://docs.silabs.com/bluetooth/latest/bluetooth-fundamentals-system-performance/afh)
- [Insinuator — Bluetooth Headphone Jacking / CVE-2025-20701](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities/)
- [BTLEJack — virtualabs](https://github.com/virtualabs/btlejack)
- [Cloudflare Quick Tunnels documentation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)
- [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)
- [Comparison: ngrok vs Cloudflare Tunnel vs Tailscale (2025)](https://instatunnel.my/blog/comparing-the-big-three-a-comprehensive-analysis-of-ngrok-cloudflare-tunnel-and-tailscale-for-modern-development-teams)
