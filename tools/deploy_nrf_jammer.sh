#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# BlueShield nRF52840 Radio Jammer Firmware Deployment
# ═══════════════════════════════════════════════════════════════════════════
#
# Flashes Nordic SDK `radio_test` firmware to an nRF52840 USB dongle (PCA10059).
# This firmware enables DIRECT RADIO PERIPHERAL CONTROL, bypassing BlueZ/HCI,
# enabling real RF jamming across the entire 2.4 GHz ISM band.
#
# Usage:
#   ./deploy_nrf_jammer.sh [device_port]
#
# Example:
#   ./deploy_nrf_jammer.sh /dev/ttyACM0
#
# After flashing, the dongle responds to UART commands at 115200 baud:
#   radio_test> set_mode nrf_1Mbit
#   radio_test> set_tx_power 8
#   radio_test> start_channel_sweep 2 80 1    # Sweep all BR/EDR channels
#   radio_test> stop
#
# Legal: +8 dBm broadband emission requires written consent + Faraday enclosure
# under FCC Part 15 §15.5(b). Use only in authorized research settings.
# ═══════════════════════════════════════════════════════════════════════════

set -e

DEVICE="${1:-/dev/ttyACM0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FW_DIR="$SCRIPT_DIR/nrf_jammer_firmware"
FW_ZIP="$FW_DIR/radio_test_nrf52840dongle.zip"
FW_HEX="$FW_DIR/radio_test_nrf52840dongle.hex"

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║  BlueShield nRF52840 Jammer Firmware Deployment                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Target device: $DEVICE"
echo "Firmware dir:  $FW_DIR"
echo ""

# ─── 1. Check prerequisites ────────────────────────────────────────────────
echo "[1/4] Checking prerequisites..."

# Check nrfutil
if ! command -v nrfutil &>/dev/null; then
    echo "  ✗ nrfutil not found. Install with:"
    echo "    pip3 install --user nrfutil"
    echo "    (or download from https://www.nordicsemi.com/Products/Development-tools/nrf-util)"
    exit 1
fi
echo "  ✓ nrfutil: $(nrfutil version 2>/dev/null | head -1)"

# Check device
if [ ! -e "$DEVICE" ]; then
    echo "  ✗ Device $DEVICE not found. Is the dongle plugged in?"
    echo "    Available devices:"
    ls -la /dev/ttyACM* 2>/dev/null || echo "    (none)"
    exit 1
fi
echo "  ✓ Device present: $DEVICE"

# ─── 2. Get or build firmware ──────────────────────────────────────────────
echo ""
echo "[2/4] Preparing firmware..."
mkdir -p "$FW_DIR"

if [ -f "$FW_ZIP" ]; then
    echo "  ✓ Pre-built firmware found: $FW_ZIP"
else
    echo "  ✗ Pre-built firmware not found."
    echo ""
    echo "  You have two options to obtain the firmware:"
    echo ""
    echo "  ━━━ OPTION A: Build from Nordic SDK (one-time, ~30 min) ━━━"
    echo "  1. Install nRF Connect SDK:"
    echo "       pip3 install --user west"
    echo "       mkdir -p ~/ncs && cd ~/ncs"
    echo "       west init -m https://github.com/nrfconnect/sdk-nrf --mr v2.6.0"
    echo "       west update"
    echo ""
    echo "  2. Build radio_test for the dongle:"
    echo "       cd ~/ncs/nrf/samples/peripheral/radio_test"
    echo "       west build -b nrf52840dongle_nrf52840 -p"
    echo ""
    echo "  3. Package as DFU zip:"
    echo "       nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\"
    echo "         --application build/zephyr/zephyr.hex \\"
    echo "         --application-version 1 \\"
    echo "         $FW_ZIP"
    echo ""
    echo "  ━━━ OPTION B: Download pre-built (if available in repo releases) ━━━"
    echo "  1. Download from project release page to:"
    echo "       $FW_ZIP"
    echo ""
    echo "  ━━━ OPTION C: Use BlueShield custom simple firmware ━━━"
    echo "  See: $SCRIPT_DIR/nrf_jammer_firmware_src/README.md"
    echo ""
    exit 1
fi

# ─── 3. Put device into DFU bootloader mode ────────────────────────────────
echo ""
echo "[3/4] Entering DFU bootloader mode..."
echo "      (If this fails, press the RESET button on the dongle to enter bootloader)"
echo ""

# Try automatic bootloader entry via the firmware's reboot command
if timeout 2 bash -c "echo 'reboot_bootloader' > $DEVICE" 2>/dev/null; then
    echo "  → Sent reboot_bootloader command"
    sleep 2
fi

# Wait for the bootloader device to enumerate (it may change port)
echo "  Waiting up to 10s for bootloader to enumerate..."
for i in {1..10}; do
    if [ -e "$DEVICE" ]; then
        break
    fi
    sleep 1
done

# ─── 4. Flash firmware ─────────────────────────────────────────────────────
echo ""
echo "[4/4] Flashing firmware..."
nrfutil dfu usb-serial -pkg "$FW_ZIP" -p "$DEVICE"

echo ""
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║  ✓ Firmware deployed successfully                                   ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Quick test:"
echo "  screen $DEVICE 115200"
echo "  > set_mode nrf_1Mbit"
echo "  > set_tx_power 8"
echo "  > start_channel_sweep 2 80 1"
echo "  > stop"
echo ""
echo "Or use BlueShield dashboard: select 'airpods_killer' mode"
