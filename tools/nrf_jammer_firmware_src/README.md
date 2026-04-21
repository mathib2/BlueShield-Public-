# BlueShield nRF52840 Jammer Firmware

Custom firmware for Nordic nRF52840 USB Dongle (PCA10059) that implements
direct RADIO peripheral control for RF jamming. Communicates with the host
over USB CDC-ACM using a simple text protocol compatible with the BlueShield
`NRFRadioJammer` Python driver.

## Why this firmware?

Nordic's SDK `radio_test` sample is the canonical reference but requires:
- nRF Connect SDK v2.6.0+ (~2 GB download)
- `west` build system (Python 3.8+)
- ~30 min build time on a Raspberry Pi

This BlueShield-specific firmware is a minimal alternative with:
- Single C source file, <500 lines
- No Zephyr RTOS dependency
- Pure Nordic nRF5 SDK (`nrf_drv_radio`) or MDK (`nrf.h`)
- ~5 min build time with `arm-none-eabi-gcc` directly

## Supported commands

All commands are CR/LF terminated ASCII at 115200 baud:

| Command | Effect |
|---|---|
| `set_mode <mode>` | Radio PHY mode: `nrf_1Mbit`, `nrf_2Mbit`, `ble_1Mbit`, `ble_lr125Kbit` |
| `set_tx_power <dBm>` | TX power: -40 to +8 (clamped to chip limits) |
| `set_channel <N>` | Radio channel (0-80 → 2400+N MHz). Covers all BT + WiFi 2.4 GHz. |
| `start_tx_carrier` | Continuous unmodulated carrier on current channel |
| `start_tx_modulated_carrier <count>` | PRBS9 modulated TX (count=0 for infinite) |
| `start_channel_sweep <start> <end> <dwell_ms>` | Sweep across channel range |
| `start_duty_cycle_modulated_tx <pct>` | Duty-cycled modulated TX (0-100%) |
| `stop` | Stop all RF emission |
| `version` | Report firmware version + capabilities |
| `reboot_bootloader` | Enter USB DFU bootloader mode for re-flashing |

## Pre-built firmware

If pre-built `.zip` is available in the repo at:
```
tools/nrf_jammer_firmware/radio_test_nrf52840dongle.zip
```
Use `tools/deploy_nrf_jammer.sh /dev/ttyACM0` to flash it.

## Build from source

Two paths:

### Path A: Nordic SDK radio_test (recommended, canonical)

```bash
# One-time setup (~30 min)
pip3 install --user west nrfutil
mkdir -p ~/ncs && cd ~/ncs
west init -m https://github.com/nrfconnect/sdk-nrf --mr v2.6.0
west update

# Build
cd ~/ncs/nrf/samples/peripheral/radio_test
west build -b nrf52840dongle_nrf52840 -p

# Package as DFU zip
nrfutil pkg generate \
  --hw-version 52 --sd-req 0x00 \
  --application build/zephyr/zephyr.hex \
  --application-version 1 \
  ~/BlueShield/tools/nrf_jammer_firmware/radio_test_nrf52840dongle.zip
```

### Path B: Custom BlueShield firmware

See `main.c` in this directory. Requires:
- `arm-none-eabi-gcc` (from ARM Embedded Toolchain)
- Nordic nRF5 SDK v17.1.0
- `nrfutil` for DFU packaging

```bash
cd tools/nrf_jammer_firmware_src
make                        # Build firmware.hex
make dfu                    # Create firmware.zip
make flash DEVICE=/dev/ttyACM0    # Flash to dongle
```

## Quick test after flashing

```bash
# Open UART
screen /dev/ttyACM0 115200

# Try a 2-second sweep of all BT channels at max power
set_mode nrf_1Mbit
set_tx_power 8
start_channel_sweep 2 80 1
# (wait 2 seconds)
stop

# Exit screen: Ctrl+A, then K, then Y
```

## Legal

+8 dBm broadband emission in the 2.4 GHz ISM band is a Part 15 §15.5(b)
violation without a shielded RF enclosure. Use only with:
- Written consent from device owner
- Institutional review / IRB approval
- Faraday bag or RF-shielded test chamber
- Supervising faculty sign-off
