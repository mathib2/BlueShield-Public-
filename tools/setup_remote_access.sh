#!/bin/bash
# BlueShield remote-access bootstrap (v7.7)
#
# Goal: make the dashboard reachable from any laptop or phone on any
# network — even one that blocks inbound ports — using only outbound
# HTTPS. The audience opens a stable URL on their device and lands on
# the BlueShield login page. Password gate is the existing Flask auth.
#
# Primary path: Tailscale Funnel
#   - Stable URL like https://blueshield.<your-tailnet>.ts.net
#   - Free (Personal plan: 3 users / 100 devices)
#   - Works on any venue WiFi (outbound TCP/UDP only)
#   - Full WebSocket support (Flask-SocketIO works)
#
# Fallback path: Cloudflare quick tunnel
#   - Random https://<random>.trycloudflare.com URL per session
#   - No account, no domain needed
#   - WebSocket OK, but Quick Tunnels don't support SSE — fine for our app
#
# Usage:
#   bash tools/setup_remote_access.sh tailscale [--auth-key tskey-...]
#   bash tools/setup_remote_access.sh cloudflare-quick
#
# After "tailscale" mode: open the URL printed in /etc/blueshield/public-url

set -euo pipefail

MODE="${1:-tailscale}"
AUTHKEY=""
shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --auth-key) AUTHKEY="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

echo "=== BlueShield remote-access setup (mode=$MODE) ==="
sudo mkdir -p /etc/blueshield
sudo touch /etc/blueshield/public-url
sudo chmod 644 /etc/blueshield/public-url

case "$MODE" in
tailscale)
    if ! command -v tailscale >/dev/null; then
        echo "[1/4] Installing Tailscale (mainline package)..."
        curl -fsSL https://tailscale.com/install.sh | sh
    else
        echo "[1/4] Tailscale already installed: $(tailscale version | head -1)"
    fi

    echo "[2/4] Bringing tailnet up..."
    if [ -n "$AUTHKEY" ]; then
        sudo tailscale up --authkey "$AUTHKEY" --hostname blueshield --reset
    else
        echo "    No auth-key supplied. You will see a one-time login URL."
        echo "    Open it on a laptop, sign in (free), and re-run this script."
        sudo tailscale up --hostname blueshield --reset
    fi

    echo "[3/4] Enabling Funnel (public ingress) on port 8080..."
    sudo tailscale serve reset || true
    sudo tailscale funnel reset || true
    sudo tailscale serve --bg --https=443 http://localhost:8080
    sudo tailscale funnel --bg 443

    URL="https://$(tailscale status --json | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["Self"]["DNSName"].rstrip("."))')"
    echo "$URL" | sudo tee /etc/blueshield/public-url >/dev/null

    echo "[4/4] Done. Public URL:"
    echo "      $URL"
    echo
    echo "    Login: admin / admin123  (change via /api/auth/change-password)"
    echo "    URL persists across reboots. Add the systemd unit below"
    echo "    so the funnel auto-starts after the Pi boots:"
    echo
    cat <<UNIT
[Unit]
Description=BlueShield Tailscale Funnel
After=tailscaled.service
Wants=tailscaled.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/tailscale funnel --bg 443
ExecStartPre=/usr/bin/tailscale serve --bg --https=443 http://localhost:8080

[Install]
WantedBy=multi-user.target
UNIT
    ;;

cloudflare-quick)
    echo "[1/3] Installing cloudflared..."
    if ! command -v cloudflared >/dev/null; then
        ARCH="$(uname -m)"
        case "$ARCH" in
            armv7l|armv6l) BIN="cloudflared-linux-arm" ;;
            aarch64)       BIN="cloudflared-linux-arm64" ;;
            x86_64)        BIN="cloudflared-linux-amd64" ;;
            *) echo "unknown arch $ARCH"; exit 1 ;;
        esac
        TMP=$(mktemp)
        curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/$BIN" -o "$TMP"
        sudo install -m 755 "$TMP" /usr/local/bin/cloudflared
        rm -f "$TMP"
    else
        echo "    cloudflared already installed: $(cloudflared --version | head -1)"
    fi

    echo "[2/3] Installing systemd unit (auto-runs quick tunnel; URL captured to /etc/blueshield/public-url)"
    sudo tee /usr/local/bin/blueshield-quick-tunnel.sh >/dev/null <<'WRAPPER'
#!/bin/bash
# Capture the trycloudflare.com URL on first emit, write it to disk so
# the dashboard can show it. Then keep the tunnel alive in the foreground.
URL_FILE=/etc/blueshield/public-url
LOG=/var/log/blueshield-quick-tunnel.log
: > "$LOG"
echo "starting cloudflared quick tunnel..." | tee -a "$LOG"
cloudflared tunnel --no-autoupdate --url http://localhost:8080 2>&1 \
    | while IFS= read -r line; do
        echo "$line" >> "$LOG"
        if echo "$line" | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' >/dev/null; then
            URL=$(echo "$line" | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | head -1)
            echo "$URL" > "$URL_FILE"
            echo "captured URL: $URL" | tee -a "$LOG"
        fi
    done
WRAPPER
    sudo chmod +x /usr/local/bin/blueshield-quick-tunnel.sh

    sudo tee /etc/systemd/system/blueshield-quick-tunnel.service >/dev/null <<'UNIT'
[Unit]
Description=BlueShield Cloudflare Quick Tunnel
After=blueshield.service network-online.target
Wants=blueshield.service network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/blueshield-quick-tunnel.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
    sudo systemctl daemon-reload
    sudo systemctl enable --now blueshield-quick-tunnel.service

    echo "[3/3] Quick tunnel started. Wait ~5s, then read the URL:"
    sleep 6
    cat /etc/blueshield/public-url || echo "(URL not captured yet — see /var/log/blueshield-quick-tunnel.log)"
    ;;

*)
    echo "unknown mode: $MODE (use 'tailscale' or 'cloudflare-quick')"
    exit 1
    ;;
esac

echo
echo "═══════════════════════════════════════════════════════════════════════════"
echo "Public URL is in /etc/blueshield/public-url"
echo "Dashboard reads it via /api/system/public-url and shows it on the status bar"
echo "═══════════════════════════════════════════════════════════════════════════"
