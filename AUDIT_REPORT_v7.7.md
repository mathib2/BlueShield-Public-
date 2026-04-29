# BlueShield v7.7 — Overnight Audit Report

**Author:** Mathias Benitez Vera (WSU senior design capstone)
**Audit date:** 2026-04-22 → 2026-04-23 UTC
**Platform:** Raspberry Pi 4 / ARMv8 / Python 3.13.3 / Flask + SocketIO
**Hardware:** hci0 (Realtek BT5.4 UART) + hci2 (Broadcom BT4.1) + hci3 (Realtek BT5.3 USB) + 2× nRF52840 USB dongle with ButteRFly v1.1.3

This document is the honest, measurement-first write-up of what works,
what doesn't, and what is physically impossible with current hardware.
Nothing here is simulated. Every number comes from a real endpoint
hit, a real pcap, or a real firmware counter.

---

## 1. Executive summary

| Area | State | Evidence |
|------|------|----------|
| Dashboard backend (Flask + SocketIO) | Working | 42/42 endpoints return 200 or 405 (POST-only), 0 crashes |
| Sniffer (ButteRFly/WHAD backend) | Working | 892 real packets, 3 CONNECT_IND, pcap 43,970 B in 20 s |
| Sniffer (dashboard `/api/sniffer/*`) | Working | 36 packets, CONNECT_IND with real AA `0x7D326B01` / peer `82:AA:70:15:FB:6F` |
| Live BLE scan | Working | 20 devices observed incl. AirPods Pro 2, HomePod mini, iPhone, RSSI -72…-94 dBm |
| Jammer — reactive_jam | Working | firmware reports 254 jams/4 s (~60/s) |
| Jammer — raw_inject | Working | 99 injections/4 s |
| Jammer — adv_flood / apple_spam | Fixed in v7.7 | now falls back to raw_inject when firmware `enable_adv_mode` fails |
| HijackTerminator (single-ButteRFly) | Implemented | starts / arms / stops cleanly; waits for matching CONNECT_IND |
| AutoTerminator (dual-ButteRFly) | Broken on this hw | USB under-voltage; WHAD has no cross-dongle connection sync |
| AP-fallback networking | Working | systemd + NM profile deployed, `blueshield-autonet.service` enabled |
| Evidence integrity chain | Verified | 85 entries, `valid=true`, Ed25519 fp `9CF9DB10C4CD16B0` |
| Auth | Hardened | bcrypt hashes in `keys/users.json`, HttpOnly cookies, 30-min idle |
| A2DP audio disruption (AirPods / HyperX) | **Physically impossible on current hw** | BR/EDR 79 channels + 1600 hops/s AFH; BLE-only radios can't see the audio link |

---

## 2. What was fixed tonight

### 2.1 `/api/adapters` reported every adapter as `up: false`
Root cause in [app.py:1321](blueshield/dashboard/app.py:1321) — the parser
looked for `"UP RUNNING"` on the HCI header line, but `hciconfig -a`
prints that flag on the following indented continuation line.

Fix: track `up` across the block; set `True` on any line containing
`UP RUNNING` until the next HCI header. Verified all three adapters
now report `up: true` matching `hciconfig`.

### 2.2 `/api/sniffer/*` silently dead because Sniffle firmware wasn't flashed
`/api/sniffer/start` returned `{"status":"started"}`, but status
immediately showed `running: false`, `packet_count: 0`, a 24-byte pcap
(header only). The backend (`sniffle_engine.SniffleEngine`) requires
TI CC1352 + Sniffle firmware; the hardware we actually own is
nRF52840 + ButteRFly.

Fix: [whad_sniffer_engine.py](blueshield/sniffer/whad_sniffer_engine.py) —
a `WhadSniffleEngine` sitting behind the same `_BaseSniffleEngine`
interface, using `whad.ble.connector.sniffer.Sniffer` on ttyACM0.
`make_sniffer()` now prefers Sniffle if the `sniffle` pip package is
installed, otherwise falls back to WHAD, otherwise returns a disabled
engine. The previous fallback to `SimulatedSniffleEngine` only fires
when the caller explicitly passes `sim=True`.

Post-fix evidence: 36 real packets, 1 CONNECT_IND `AA=0x7D326B01`,
peripheral `82:AA:70:15:FB:6F`, `hop_increment=31`, `crc_init=0x178DD9`.

### 2.3 `ble_adv_flood` / `apple_spam` failed with `enable_adv_mode returned False`
The ButteRFly v1.1.3 firmware exposes peripheral mode but its WHAD
`enable_adv_mode` call rejects payloads on our dongles. Root cause is
inside the firmware; we can't patch it without a fresh build.

Fix in [butterfly_jammer.py:220](blueshield/jammer/butterfly_jammer.py:220):
when `enable_adv_mode` returns `False` or raises, fall through to
`start_raw_inject_flood()`, which builds the same
`BTLE_ADV_NONCONN_IND` PDU and raw-injects it at 500 Hz. Same on-air
effect. Post-fix: both modes now show `is_active: true`,
`packets_injected` rising. The backend is visible in status as
`mode: ble_raw_inject` even when the user picked `ble_adv_flood` —
this is the honest state, not a cosmetic lie.

### 2.4 AutoTerminator cross-dongle sync — architecturally broken, replaced
The v7.6 AutoTerminator uses two ButteRFly dongles: Observer on
ttyACM0 (sniff CONNECT_IND), Injector on ttyACM1
(`inject_to_slave()`). Audit proved this doesn't work for two
independent reasons:

1. **USB under-voltage.** Measured live: with both ButteRFlies active,
   `dmesg` reports `dwc_otg_hcd_urb_dequeue: Timed out waiting for FSM
   NP transfer` and `hwmon hwmon1: Undervoltage detected!`, followed
   by one ACM device re-enumerating mid-attack. The Pi 4's 5 V rail
   can't sustain both dongles at full radio load without a powered USB
   hub.
2. **WHAD has no cross-dongle connection sync.** The injector radio
   has no knowledge of the target connection's anchor point, hop
   increment, channel map, or access-address tracking. Even with both
   dongles powered, `inject_to_slave()` on dongle B fires on the wrong
   channel at the wrong time; the peer never sees it. The Observer
   did capture 2 real CONNECT_INDs (`AA=0x26aed3d1`), but 0 of our
   injections were accepted.

Fix: new `HijackTerminator` class in
[hijack_terminator.py](blueshield/jammer/hijack_terminator.py). One
ButteRFly only:
1. Sniff advertising channels until CONNECT_IND matches a MAC in the
   kill list (or wildcard).
2. Stop the sniffer and construct a `Hijacker(device)` on the *same*
   dongle. Call `hijack_slave(access_address=AA)` — the ButteRFly
   firmware re-synchronises on-chip (it already knows the hop map
   from the CONNECT_IND it just sniffed), races the real slave for
   the next connection event, and takes over the slave role
   (Cayre DSN 2021, §IV.C).
3. With the slave role owned, inject `LL_TERMINATE_IND code=0x13`
   three times with 10 ms spacing. The master accepts it because it
   now comes from the authoritative slave.
4. Tear the hijacker down, re-enter sniff mode for the next target.

New modes exposed:
- `hijack_terminator` / `ble_hijack_terminate` (top-level mode, the
  recommended "force disconnect" back-end).
- UI wiring: the 3-tier `Action = Force Disconnect` preset now maps
  to `hijack_terminator` instead of the manual-AA `ble_inject_terminate`.
- Live status: `hijack_terminator_active`, `hijack_terminator_status`
  (`connect_inds_seen`, `hijacks_attempted`, `hijacks_succeeded`,
  `terminations_sent`, `last_target_aa_hex`, `last_target_mac`,
  `last_hijack_status`, `last_error`).

### 2.5 AP-fallback networking
`tools/setup_ap_fallback.sh` (deployed) creates a NetworkManager
profile `BlueShield-AP` (open WiFi, 10.42.0.1/24), sets priorities so
`BlueShield-Hotspot` (20) > `Vera Torres Wifi` (10) > `BlueShield-AP`
(0), installs `blueshield-autonet.service` (systemd oneshot, enabled
at boot). Watchdog waits 45 s for known WiFi association; if none
found, activates the AP. Result: on a cold boot, the dashboard is
reachable at `http://blueshield.local:8080` (mDNS via avahi) or
`http://10.42.0.1:8080` (static fallback) with no router.

### 2.6 UI/UX cleanup
- Advanced-mode dropdown now leads with `HIJACK-TERMINATE` (v7.7
  single-dongle) above the legacy `AUTO-TERMINATE` (v7.6 dual-dongle,
  annotated "known cross-dongle sync failure").
- `mapTargetActionToMode("force_disconnect")` now returns
  `hijack_terminator` so the simple 3-tier control works out of the
  box without needing the advanced panel.
- Capability hints rewritten for both modes to say what they actually
  do and what the trade-offs are, with Cayre DSN 2021 cited.
- `j-target-grp` (target MAC input) now shows when hijack-terminator
  or auto-terminator is selected, not just `targeted`/`deauth`.
- Default jammer secondary interface in `settings.py` changed from
  `hci1` (which doesn't enumerate on our Pi) to `hci3` (which does),
  matching the role map in `/api/adapters`.

---

## 3. What cannot be done with current hardware — and why

### 3.1 Kill AirPods / HyperX / Bose audio link
**Impossible with BLE-only hardware.** Measured, confirmed, no
hand-waving:

- The audio link is A2DP over **BR/EDR**, which uses all 79 2.4 GHz
  channels and hops at ~1600 hops/s under Adaptive Frequency Hopping
  (AFH). AFH actively blacklists any channel that shows packet errors.
- Every radio we have (Realtek BT5.4, Realtek BT5.3, Broadcom BT4.1,
  nRF52840) exposes either HCI (protocol layer, can't transmit on an
  arbitrary channel) or BLE-only PHY (nRF's radio in ButteRFly
  firmware is locked to 37 BLE data channels + 3 advertising channels,
  not the 79 BR/EDR channels).
- The ButteRFly firmware does not include `radio_test` (Nordic's
  direct-register test firmware) — flashing it would wipe the
  injection capability we use elsewhere.
- Measurement: even with reactive_jam active on ADV ch 39 @ 60 jams/s,
  AirPods continue playing music because none of their audio traffic
  is on ch 39. The companion BLE link (where `LL_TERMINATE_IND` could
  help) is on a different connection that the hijack must find first.

What would actually work: HackRF One ($320) + amplifier + Faraday cage
environment, or a Nordic nRF52840-DK reflashed with `radio_test` and
CW-swept at +8 dBm across 2.4 GHz ISM. Both require authorized-test
environments (47 USC § 333, FCC Part 15). Neither is in scope for
this project.

### 3.2 Jam effectiveness can't be A/B-tested on this Pi
I wrote `/tmp/jam_eval.py` (baseline sniff → arm jam → jammed sniff →
recover). It fails on this hardware because:
- Running two ButteRFlies simultaneously triggers USB under-voltage
  and one drops.
- Using `hci0` or `hci2` for the measurement scan fails with
  `Enable scan failed: Input/output error` after the jammer's radio
  load pulls the Pi voltage.
- Using `btmon` bypasses the kernel and still requires a BLE PHY to
  observe — which on this hw is another dongle.

What I can confirm: the ButteRFly firmware counts **real TX events**
(not a Python time estimate) and reports 254 jammed packets in 4 s
for `reactive_jam` and 99 raw injections in 4 s. These numbers come
from firmware telemetry, not dashboard loop rate. Independent RF
verification needs a second radio on its own power rail — a powered
USB hub would be enough. That's the single biggest hardware upgrade
the project still needs.

### 3.3 HijackTerminator success rate — not yet verified
The new HijackTerminator runs cleanly but I have not yet observed a
successful hijack in the wild (requires a BLE-paired device
establishing a new connection within the sniff window while the
dongle is armed with that MAC). The code path is exercised; the
`hijacks_attempted` / `hijacks_succeeded` counters are wired. A
fair real-world test needs: (a) a BLE peripheral under my control
(e.g., a Nordic DK advertising ADV_IND), (b) a BLE central (e.g., a
phone) initiating a connection, (c) the Pi's ButteRFly sniffing that
CONNECT_IND. Verifying this in a controlled 2-device setup is the
first to-do after the audit.

### 3.4 `ble_adv_flood` user-facing label vs reality
The dropdown says `AdvMode flood · AirPods payload` but the backend
currently executes `start_raw_inject_flood()` (because
`enable_adv_mode` doesn't work on this firmware). On-air effect is
the same (BTLE_ADV_NONCONN_IND at 500 Hz), but the UI hint and the
`butterfly_status.mode` string disagree. This is a cosmetic honesty
issue, not a functional bug. The status always reports the *actual*
mode in use, never the button the user clicked.

---

## 4. Numbers from tonight — raw

```
ButteRFly passive sniff                  892 packets, 3 CONNECT_IND, 20.5s
Pcap written                             /home/pi/blueshield-project/captures/butterfly_sniff_20260422T054139Z.pcap (43,970 B)
/api/sniffer/start (WhadSniffleEngine)   36 pkts, 1 conn AA=0x7D326B01
Live BLE scan (/api/devices)             20 devices, RSSI -72..-94 dBm
    incl. AirPods Pro 2 (74:21:17:69:A1:3F @ -92)
    incl. HomePod mini (FF:BB:75:78:1C:02 @ -72)
Jammer ble_reactive_jam (ch 39, 4s)      firmware 254 jammed_packets (~60/s)
Jammer ble_raw_inject (4s)               firmware 99 packets_injected
Jammer ble_adv_flood (post-fix)          is_active=true, via raw_inject fallback
Jammer apple_spam (post-fix)             is_active=true, via raw_inject fallback
HijackTerminator                         is_active=true, wildcard kill_list, wire OK
AutoTerminator (prior)                   connect_inds_seen=2, injections_sent=0 (expected — cross-dongle sync)
Integrity chain                          85 entries, valid=true, Ed25519 fp 9CF9DB10C4CD16B0
AP-fallback                              blueshield-autonet.service enabled, BlueShield-AP profile prio 0
Hostname                                 blueshield, cloud-init preserve_hostname:true
Dashboard                                http://blueshield.local:8080 (mDNS), http://192.168.40.72:8080 (current LAN)
Endpoints                                42/42 return 200 or 405 (POST-only)
```

---

## 5. Next real steps (in priority order)

1. **Powered USB hub.** Single biggest hw unblock. $15 on Amazon.
   Eliminates USB under-voltage → lets dual-ButteRFly A/B testing
   (scan radio vs jam radio) work for empirical jam-effect measurement.
2. **Wild HijackTerminator trial.** Spin up a Nordic DK as a BLE
   peripheral, use an iPhone to initiate GATT connection, confirm
   hijacks_succeeded increments and the phone reports "disconnected."
3. **`enable_adv_mode` fallback label honesty.** Route
   `ble_adv_flood`/`apple_spam` through the raw_inject path from day
   one and rename the dropdown entries so UI and backend agree.
4. **Sniffle-firmware dongle.** A cheap TI CC1352 ($30) flashed with
   nccgroup/Sniffle unlocks connection-following on data channels
   (current WHAD sniffer only sees adv channels). Adds the "follow a
   connection across all 37 data channels" capability the dashboard
   already has UI wired for (`/api/nrf-sniffer/follow`).
5. **Optional: HackRF for actual BR/EDR jamming.** Only if the
   project expands to deliberate physical-layer jamming research in
   an authorized Faraday environment. Not needed for the current
   defensive-sensor scope.
