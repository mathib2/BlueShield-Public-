#!/usr/bin/env bash
# BlueShield one-shot installer for Raspberry Pi (3B+ / 4 / 5).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mathib2/BlueShield-Public-/master/scripts/install.sh | sudo bash
#
# Or, if you have the repo cloned locally:
#   sudo bash scripts/install.sh
#
# This is idempotent — re-running upgrades the install in place.
#
# What it does (in order):
#   1.  Sanity checks the host (Pi 3+/4/5, Debian Bookworm or later, Python 3.10+).
#   2.  apt-installs system deps (BlueZ, build tools, libcap, etc.).
#   3.  Clones (or updates) the repo into /opt/blueshield.
#   4.  Creates a venv at /opt/blueshield/venv and pip-installs requirements.
#   5.  Installs udev rules for nRF52 dongles + adds the operator user to dialout.
#   6.  setcap CAP_NET_RAW + CAP_NET_ADMIN on the venv Python so Bleak can scan
#       without root (the scanner half of BlueShield runs as `pi`).
#   7.  Installs the systemd unit + enables it on boot.
#   8.  Prints LAN URLs, mDNS URL, and an admin/admin123 password warning.
#
set -euo pipefail

# ── Pretty output ─────────────────────────────────────────────────────────────
YELLOW=$'\033[33m'; GREEN=$'\033[32m'; RED=$'\033[31m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
log()  { echo "${CYAN}[blueshield]${RESET} $*"; }
ok()   { echo "${GREEN}  ✓${RESET} $*"; }
warn() { echo "${YELLOW}  !${RESET} $*"; }
die()  { echo "${RED}✗ $*${RESET}" >&2; exit 1; }

# ── Defaults (override via env) ───────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/blueshield}"
REPO_URL="${REPO_URL:-https://github.com/mathib2/BlueShield-Public-.git}"
REPO_BRANCH="${REPO_BRANCH:-master}"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-pi}}"
PORT="${PORT:-8080}"

# ── 0. Root check ─────────────────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
    die "Please run as root (or via sudo)."
fi

# ── 1. Sanity checks ──────────────────────────────────────────────────────────
log "Step 1/8: host sanity check"

if [[ -r /proc/device-tree/model ]]; then
    PI_MODEL=$(tr -d '\0' < /proc/device-tree/model)
    case "$PI_MODEL" in
        *"Raspberry Pi 5"*)   ok "detected: $PI_MODEL" ;;
        *"Raspberry Pi 4"*)   ok "detected: $PI_MODEL" ;;
        *"Raspberry Pi 3"*)   ok "detected: $PI_MODEL — works, but consider Pi 4 for sniffer/jammer headroom" ;;
        *"Raspberry Pi"*)     warn "older Pi detected ($PI_MODEL) — proceed at your own risk" ;;
        *)                    warn "non-Pi ARM device ($PI_MODEL) — installer continues but is untested" ;;
    esac
else
    warn "not a Raspberry Pi — installer will run, but driver paths are Pi-tuned"
fi

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${VERSION_CODENAME:-}" in
        bookworm) ok "Debian 12 (Bookworm) — supported" ;;
        bullseye) ok "Debian 11 (Bullseye) — supported (Python 3.9 path)" ;;
        trixie)   ok "Debian 13 (Trixie) — supported" ;;
        *)        warn "OS = ${ID:-?} ${VERSION_ID:-?} ${VERSION_CODENAME:-?} — only Debian 11/12/13 are tested" ;;
    esac
fi

PY_VER=$(python3 -c 'import sys; print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")
PY_MAJ="${PY_VER%%.*}"; PY_MIN="${PY_VER##*.}"
if [[ "$PY_MAJ" -lt 3 ]] || [[ "$PY_MAJ" -eq 3 && "$PY_MIN" -lt 10 ]]; then
    die "Python 3.10+ required, found ${PY_VER}. (Pi 4 with Bookworm ships Python 3.11.)"
fi
ok "Python ${PY_VER}"

# ── 2. System packages ────────────────────────────────────────────────────────
log "Step 2/8: apt — installing system dependencies"

# DEBIAN_FRONTEND avoids interactive prompts on a fresh-imaged Pi.
export DEBIAN_FRONTEND=noninteractive

# All packages are idempotent — apt skips already-installed.
apt-get update -qq
apt-get install -y --no-install-recommends \
    git \
    bluez \
    bluetooth \
    libbluetooth-dev \
    libcap2-bin \
    libdbus-1-dev \
    libgirepository1.0-dev \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    pkg-config \
    iproute2 \
    rfkill \
    ca-certificates \
    curl \
    >/dev/null 2>&1 && ok "apt packages installed" || die "apt install failed"

# Cloudflare tunnel (optional but enables remote access). Pi 4 ARMv8 binary.
if ! command -v cloudflared >/dev/null 2>&1; then
    log "Step 2a: cloudflared (for public tunnel access)"
    ARCH=$(uname -m)
    case "$ARCH" in
        aarch64|arm64) CLOUDFLARED_ARCH="arm64" ;;
        armv7l|armv6l) CLOUDFLARED_ARCH="arm" ;;
        x86_64)        CLOUDFLARED_ARCH="amd64" ;;
        *)             warn "unknown CPU arch ($ARCH) — skipping cloudflared install"; CLOUDFLARED_ARCH="" ;;
    esac
    if [[ -n "$CLOUDFLARED_ARCH" ]]; then
        curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDFLARED_ARCH}.deb" \
            -o /tmp/cloudflared.deb
        dpkg -i /tmp/cloudflared.deb >/dev/null 2>&1 || apt-get install -fy >/dev/null 2>&1
        rm -f /tmp/cloudflared.deb
        ok "cloudflared installed"
    fi
else
    ok "cloudflared already installed"
fi

# ── 3. Clone or update the repo ───────────────────────────────────────────────
log "Step 3/8: code at ${INSTALL_DIR}"

# If the script is being executed from a local checkout (the common case
# when someone has already cloned the repo), re-use that checkout instead
# of doing a fresh `git clone` — that lets `sudo bash scripts/install.sh`
# work from a private repo without needing SSH keys or HTTPS auth.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOCAL_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    if git -C "${INSTALL_DIR}" remote get-url origin 2>/dev/null | grep -q "github.com"; then
        git -C "${INSTALL_DIR}" fetch --quiet origin "${REPO_BRANCH}" 2>/dev/null \
            && git -C "${INSTALL_DIR}" reset --hard "origin/${REPO_BRANCH}" --quiet 2>/dev/null \
            && ok "updated ${INSTALL_DIR} from origin/${REPO_BRANCH}" \
            || warn "could not refresh from GitHub (private repo or offline) — keeping existing checkout"
    else
        ok "${INSTALL_DIR} is a checkout but origin isn't GitHub — keeping as-is"
    fi
elif [[ -d "${INSTALL_DIR}" && -f "${INSTALL_DIR}/requirements.txt" ]]; then
    # Existing local copy WITHOUT a git remote. If install.sh was invoked
    # from a NEWER checkout (LOCAL_ROOT), refresh the install in place by
    # syncing only the files that exist in the source — that catches the
    # case of upgrading from a pre-v8.0 install that doesn't have udev/,
    # systemd/, or scripts/ yet.
    if [[ -f "${LOCAL_ROOT}/requirements.txt" && "${LOCAL_ROOT}" != "${INSTALL_DIR}" ]]; then
        log "  refreshing ${INSTALL_DIR} from local checkout ${LOCAL_ROOT}"
        if command -v rsync >/dev/null 2>&1; then
            rsync -a --update \
                --exclude '.git' --exclude '__pycache__' --exclude 'venv' \
                --exclude 'captures' --exclude 'keys' \
                --exclude 'blueshield/logs/*.json' \
                --exclude 'blueshield/scanner/heatmap.json*' \
                "${LOCAL_ROOT}/" "${INSTALL_DIR}/"
        fi
        ok "merged newer files from ${LOCAL_ROOT} → ${INSTALL_DIR}"
    else
        ok "using existing ${INSTALL_DIR} (no git remote — local copy)"
    fi
elif [[ -f "${LOCAL_ROOT}/requirements.txt" && "${LOCAL_ROOT}" != "${INSTALL_DIR}" ]]; then
    # Run from a local checkout; copy it to INSTALL_DIR so installs are atomic.
    log "  copying local checkout ${LOCAL_ROOT} → ${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}"
    # Use rsync for fast incremental copies; tar fallback if rsync absent.
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude '.git' --exclude '__pycache__' --exclude 'venv' \
            --exclude 'captures' --exclude 'keys' \
            --exclude 'blueshield/logs/*.json' \
            --exclude 'blueshield/scanner/heatmap.json*' \
            "${LOCAL_ROOT}/" "${INSTALL_DIR}/"
    else
        (cd "${LOCAL_ROOT}" && tar --exclude='.git' --exclude='__pycache__' --exclude='venv' \
            --exclude='captures' --exclude='keys' --exclude='blueshield/logs/*.json' \
            --exclude='blueshield/scanner/heatmap.json*' \
            -cf - .) | (cd "${INSTALL_DIR}" && tar -xf -)
    fi
    ok "copied ${LOCAL_ROOT} → ${INSTALL_DIR}"
else
    log "  cloning ${REPO_URL} (branch ${REPO_BRANCH})"
    git clone --quiet --branch "${REPO_BRANCH}" "${REPO_URL}" "${INSTALL_DIR}" \
        && ok "cloned to ${INSTALL_DIR}" \
        || die "git clone failed — ${REPO_URL} unreachable or private. Run install.sh from a local checkout instead."
fi

# Owner: the operator user, not root. install.sh ran as root for system steps.
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

# ── 4. Python venv + deps ─────────────────────────────────────────────────────
log "Step 4/8: python venv + pip install"

if [[ ! -d "${INSTALL_DIR}/venv" ]]; then
    sudo -u "${SERVICE_USER}" python3 -m venv "${INSTALL_DIR}/venv"
    ok "venv created"
fi

# Always upgrade pip + reinstall requirements (idempotent, refreshes for
# the latest patch versions, fast on no-op).
sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip wheel setuptools
sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade -r "${INSTALL_DIR}/requirements.txt"
ok "Python deps installed"

# ── 5. udev rules + dialout group ─────────────────────────────────────────────
log "Step 5/8: udev rules for nRF52 dongles"

install -m 0644 "${INSTALL_DIR}/udev/99-blueshield.rules" /etc/udev/rules.d/99-blueshield.rules
udevadm control --reload-rules
udevadm trigger
ok "udev rules installed + reloaded"

if ! id -nG "${SERVICE_USER}" | grep -qw dialout; then
    usermod -aG dialout "${SERVICE_USER}"
    ok "added ${SERVICE_USER} to dialout group (re-login to take effect)"
else
    ok "${SERVICE_USER} already in dialout group"
fi

# ── 6. BLE raw-HCI capabilities (so non-root scan works) ──────────────────────
log "Step 6/8: setcap on venv Python (raw HCI access without sudo)"

# Bleak/bluez talks via D-Bus and doesn't strictly need raw HCI; but our
# jammer + classic-BT inquiry path uses hcitool which needs CAP_NET_RAW +
# CAP_NET_ADMIN. Granting on the venv Python keeps it scoped.
PYBIN=$(readlink -f "${INSTALL_DIR}/venv/bin/python3")
setcap cap_net_raw,cap_net_admin+eip "$PYBIN" 2>/dev/null \
    && ok "setcap on $PYBIN" \
    || warn "setcap failed (filesystem may not support xattr) — running as root via systemd will still work"

# ── 7. systemd unit ───────────────────────────────────────────────────────────
log "Step 7/8: systemd service"

# Substitute the WorkingDirectory placeholder if INSTALL_DIR isn't /opt/blueshield.
sed "s|/opt/blueshield|${INSTALL_DIR}|g" "${INSTALL_DIR}/systemd/blueshield.service" \
    > /etc/systemd/system/blueshield.service

# Patch the port if non-default.
if [[ "${PORT}" != "8080" ]]; then
    sed -i "s|--port 8080|--port ${PORT}|" /etc/systemd/system/blueshield.service
fi

systemctl daemon-reload
systemctl enable blueshield.service >/dev/null 2>&1
systemctl restart blueshield.service
ok "blueshield.service enabled and started"

# Wait briefly so we can show the operator if it boots cleanly.
sleep 3
if systemctl is-active --quiet blueshield.service; then
    ok "service is active"
else
    warn "service didn't start cleanly — check: journalctl -u blueshield -n 80 --no-pager"
fi

# ── 8. Final summary ──────────────────────────────────────────────────────────
log "Step 8/8: ready"

LAN_IP=$(ip -4 addr show scope global | awk '/inet/{print $2}' | head -1 | cut -d/ -f1)
HOSTNAME=$(hostname)
echo
echo "${BOLD}${GREEN}========================================================================${RESET}"
echo "${BOLD}  BlueShield is running.${RESET}"
echo "${BOLD}${GREEN}========================================================================${RESET}"
echo
echo "  Open in a browser on the same network:"
echo "    ${CYAN}http://${LAN_IP}:${PORT}${RESET}"
echo "    ${CYAN}http://${HOSTNAME}.local:${PORT}${RESET}    (if mDNS works on your client)"
echo
echo "  Default credentials: ${BOLD}admin / admin123${RESET}"
echo "  ${YELLOW}Change the password${RESET} (Config → Operators) before exposing to the internet."
echo
echo "  Service control:"
echo "    sudo systemctl status blueshield"
echo "    sudo journalctl -u blueshield -f"
echo "    sudo systemctl restart blueshield"
echo
if command -v cloudflared >/dev/null 2>&1; then
    echo "  Public access:  the dashboard's login page can spin up a Cloudflare"
    echo "  quick-tunnel automatically (the URL appears as a third QR code on the"
    echo "  login page) — useful for sharing with people not on your LAN."
fi
echo
