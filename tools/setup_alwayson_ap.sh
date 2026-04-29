#!/bin/bash
# BlueShield always-on AP (v7.7.2 — demo-day bulletproof)
#
# Boot directly to AP mode. The Pi advertises an open WiFi network
# named "BlueShield" at 10.42.0.1/24. Audience joins → opens
# http://10.42.0.1:8080 → dashboard. No venue WiFi, no DNS, no
# firewall, no captive portal.
#
# Side-effect: the Pi has no internet while in pure-AP mode, so
# Cloudflare/Tailscale tunnels won't work concurrently. This is
# the trade-off for guaranteed reachability. If you want a tunnel,
# run setup_remote_access.sh and use a phone hotspot to give the
# Pi internet — the AP can stay up only if your radio/firmware
# supports concurrent AP+STA, otherwise pick one.
#
# Idempotent. Safe to re-run.

set -euo pipefail

echo "=== BlueShield always-on AP setup (demo-day bulletproof) ==="

# 1. Profile (re-create with autoconnect=yes priority=99 so it wins boot)
echo "[1/3] Configuring BlueShield-AP NetworkManager profile (autoconnect=yes, prio=99)..."
sudo nmcli connection delete BlueShield-AP 2>/dev/null || true
sudo nmcli connection add \
    type wifi ifname wlan0 con-name BlueShield-AP \
    autoconnect yes \
    connection.autoconnect-priority 99 \
    wifi.mode ap \
    wifi.ssid "BlueShield" \
    wifi.band bg \
    ipv4.method shared \
    ipv4.addresses 10.42.0.1/24 \
    wifi-sec.key-mgmt none

# 2. Demote known WiFi profiles so they NEVER beat the AP at boot
echo "[2/3] Demoting all client WiFi profiles (priority -1)..."
nmcli -t -f NAME,TYPE connection show | awk -F: '$2=="802-11-wireless" && $1!="BlueShield-AP" {print $1}' | while read PROF; do
    sudo nmcli connection modify "$PROF" connection.autoconnect-priority -1 2>/dev/null || true
    sudo nmcli connection modify "$PROF" connection.autoconnect no 2>/dev/null || true
    echo "    demoted: $PROF"
done

# 3. Activate immediately
echo "[3/3] Activating BlueShield-AP now..."
sudo nmcli connection up BlueShield-AP || true

echo
echo "═══════════════════════════════════════════════════════════════════════════"
echo " DEMO-DAY ACCESS"
echo "═══════════════════════════════════════════════════════════════════════════"
echo "   Audience: join WiFi 'BlueShield' (open) → http://10.42.0.1:8080"
echo "   You:      same."
echo "   Login:    admin / admin123"
echo "   QR codes are rendered on the login page automatically."
echo
echo " To go back to client-WiFi behavior:"
echo "   sudo nmcli connection modify BlueShield-AP autoconnect no"
echo "   sudo nmcli connection modify BlueShield-AP connection.autoconnect-priority 0"
echo "   nmcli -t -f NAME,TYPE connection show | awk -F: '\$2==\"802-11-wireless\" && \$1!=\"BlueShield-AP\" {print \$1}' | xargs -I{} sudo nmcli connection modify {} autoconnect yes"
echo "═══════════════════════════════════════════════════════════════════════════"
