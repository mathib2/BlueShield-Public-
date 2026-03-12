"""
BlueShield Terminal Dashboard

Rich terminal-based dashboard for monitoring Bluetooth activity.
Bash-style CLI interface with real-time updates using curses.

Run: python -m blueshield.dashboard.terminal_ui [--sim]
"""

import os
import sys
import time
import asyncio
import argparse
import curses
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from blueshield.config.settings import load_config
from blueshield.scanner.bt_scanner import BluetoothScanner, SimulatedScanner
from blueshield.jammer.bt_jammer import BluetoothJammer, SimulatedJammer
from blueshield.logs.logger import BlueShieldLogger


# ── Color pairs ──────────────────────────────────────────────────────────────
C_HEADER = 1
C_OK = 2
C_WARN = 3
C_CRIT = 4
C_INFO = 5
C_DIM = 6
C_ACCENT = 7
C_BORDER = 8


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_CRIT, curses.COLOR_RED, -1)
    curses.init_pair(C_INFO, curses.COLOR_CYAN, -1)
    curses.init_pair(C_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(C_ACCENT, curses.COLOR_MAGENTA, -1)
    curses.init_pair(C_BORDER, curses.COLOR_BLUE, -1)


def safe_addstr(win, y, x, text, attr=0):
    """Write string to window, truncating to fit."""
    max_y, max_x = win.getmaxyx()
    if y >= max_y or x >= max_x:
        return
    available = max_x - x - 1
    if available <= 0:
        return
    win.addnstr(y, x, text, available, attr)


def draw_box(win, y, x, h, w, title="", color=0):
    """Draw a bordered box with optional title."""
    max_y, max_x = win.getmaxyx()
    if y + h > max_y or x + w > max_x:
        h = min(h, max_y - y)
        w = min(w, max_x - x)
    if h < 3 or w < 3:
        return

    # Draw borders
    for i in range(1, w - 1):
        safe_addstr(win, y, x + i, "─", curses.color_pair(C_BORDER))
        safe_addstr(win, y + h - 1, x + i, "─", curses.color_pair(C_BORDER))
    for i in range(1, h - 1):
        safe_addstr(win, y + i, x, "│", curses.color_pair(C_BORDER))
        safe_addstr(win, y + i, x + w - 1, "│", curses.color_pair(C_BORDER))
    safe_addstr(win, y, x, "┌", curses.color_pair(C_BORDER))
    safe_addstr(win, y, x + w - 1, "┐", curses.color_pair(C_BORDER))
    safe_addstr(win, y + h - 1, x, "└", curses.color_pair(C_BORDER))
    safe_addstr(win, y + h - 1, x + w - 1, "┘", curses.color_pair(C_BORDER))

    if title:
        safe_addstr(win, y, x + 2, f" {title} ", curses.color_pair(C_ACCENT) | curses.A_BOLD)


def draw_header(win, width, scanner, jammer):
    """Draw the top header bar."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"  BLUESHIELD v0.1.0  |  Bluetooth Security Monitor  |  {now}  "
    safe_addstr(win, 0, 0, " " * width, curses.color_pair(C_HEADER))
    safe_addstr(win, 0, 0, header.ljust(width), curses.color_pair(C_HEADER) | curses.A_BOLD)

    # Status line
    scan_status = "SCANNING" if scanner.is_scanning else "IDLE"
    scan_color = C_OK if scanner.is_scanning else C_DIM
    jam_status = "JAMMING" if jammer.is_jamming else "OFF"
    jam_color = C_CRIT if jammer.is_jamming else C_DIM

    safe_addstr(win, 1, 2, "Scanner: ", curses.A_BOLD)
    safe_addstr(win, 1, 11, scan_status, curses.color_pair(scan_color) | curses.A_BOLD)
    safe_addstr(win, 1, 22, "Jammer: ", curses.A_BOLD)
    safe_addstr(win, 1, 30, jam_status, curses.color_pair(jam_color) | curses.A_BOLD)
    safe_addstr(win, 1, 42, f"Scans: {scanner.total_scans}", curses.color_pair(C_INFO))
    safe_addstr(win, 1, 58, f"Interface: {scanner.interface}", curses.color_pair(C_DIM))


def draw_summary_panel(win, y, x, w, summary):
    """Draw the device summary panel."""
    h = 8
    draw_box(win, y, x, h, w, "DEVICE SUMMARY")

    safe_addstr(win, y + 1, x + 2, f"Total Devices:    ", curses.A_BOLD)
    safe_addstr(win, y + 1, x + 20, str(summary["total_devices"]), curses.color_pair(C_INFO) | curses.A_BOLD)

    safe_addstr(win, y + 2, x + 2, f"Known (Trusted):  ", curses.A_BOLD)
    safe_addstr(win, y + 2, x + 20, str(summary["known_devices"]), curses.color_pair(C_OK))

    safe_addstr(win, y + 3, x + 2, f"Unknown:          ", curses.A_BOLD)
    unk = summary["unknown_devices"]
    unk_color = C_WARN if unk > 0 else C_OK
    safe_addstr(win, y + 3, x + 20, str(unk), curses.color_pair(unk_color) | curses.A_BOLD)

    safe_addstr(win, y + 4, x + 2, f"Critical Alerts:  ", curses.A_BOLD)
    crit = summary["critical_alerts"]
    crit_color = C_CRIT if crit > 0 else C_OK
    safe_addstr(win, y + 4, x + 20, str(crit), curses.color_pair(crit_color) | curses.A_BOLD)

    safe_addstr(win, y + 5, x + 2, f"Warning Alerts:   ", curses.A_BOLD)
    warn = summary["warning_alerts"]
    warn_color = C_WARN if warn > 0 else C_OK
    safe_addstr(win, y + 5, x + 20, str(warn), curses.color_pair(warn_color))

    safe_addstr(win, y + 6, x + 2, f"Total Scans:      ", curses.A_BOLD)
    safe_addstr(win, y + 6, x + 20, str(summary["total_scans"]), curses.color_pair(C_INFO))


def draw_device_table(win, y, x, w, h, devices, scroll_offset=0):
    """Draw the device table."""
    draw_box(win, y, x, h, w, "DISCOVERED DEVICES")

    # Table header
    col_addr = x + 2
    col_name = x + 22
    col_type = x + 42
    col_rssi = x + 52
    col_alert = x + 62
    col_seen = x + 74

    safe_addstr(win, y + 1, col_addr, "ADDRESS", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    safe_addstr(win, y + 1, col_name, "NAME", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    safe_addstr(win, y + 1, col_type, "TYPE", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    safe_addstr(win, y + 1, col_rssi, "RSSI", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    safe_addstr(win, y + 1, col_alert, "ALERT", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    safe_addstr(win, y + 1, col_seen, "SEEN", curses.color_pair(C_ACCENT) | curses.A_BOLD)

    # Draw separator
    safe_addstr(win, y + 2, x + 1, "─" * (w - 2), curses.color_pair(C_BORDER))

    # Device rows
    max_rows = h - 4
    visible_devices = devices[scroll_offset:scroll_offset + max_rows]

    for i, dev in enumerate(visible_devices):
        row = y + 3 + i
        if row >= y + h - 1:
            break

        # Color based on alert level
        alert = dev.get("alert_level", "none")
        if alert == "critical":
            row_color = C_CRIT
        elif alert == "warning":
            row_color = C_WARN
        elif dev.get("is_known"):
            row_color = C_OK
        else:
            row_color = C_DIM

        safe_addstr(win, row, col_addr, dev.get("address", "")[:17], curses.color_pair(row_color))
        safe_addstr(win, row, col_name, dev.get("name", "Unknown")[:18], curses.color_pair(row_color))
        safe_addstr(win, row, col_type, dev.get("device_type", "?")[:8], curses.color_pair(C_INFO))

        rssi = dev.get("rssi", 0)
        rssi_str = f"{rssi} dBm" if rssi else "N/A"
        safe_addstr(win, row, col_rssi, rssi_str, curses.color_pair(C_DIM))

        alert_display = alert.upper() if alert != "none" else "OK"
        alert_color = C_CRIT if alert == "critical" else C_WARN if alert == "warning" else C_OK
        safe_addstr(win, row, col_alert, alert_display, curses.color_pair(alert_color) | curses.A_BOLD)

        seen = dev.get("seen_count", 0)
        safe_addstr(win, row, col_seen, str(seen), curses.color_pair(C_DIM))

    # Scroll indicator
    if len(devices) > max_rows:
        safe_addstr(win, y + h - 1, x + 2,
                    f" [{scroll_offset + 1}-{min(scroll_offset + max_rows, len(devices))}/{len(devices)}] ",
                    curses.color_pair(C_DIM))


def draw_jammer_panel(win, y, x, w, jammer_status):
    """Draw jammer status panel."""
    h = 7
    draw_box(win, y, x, h, w, "JAMMER STATUS")

    enabled = jammer_status.get("jam_enabled", False)
    active = jammer_status.get("is_jamming", False)
    sessions = jammer_status.get("total_sessions", 0)

    safe_addstr(win, y + 1, x + 2, "Enabled: ", curses.A_BOLD)
    safe_addstr(win, y + 1, x + 11, "YES" if enabled else "NO",
                curses.color_pair(C_WARN if enabled else C_DIM))

    safe_addstr(win, y + 2, x + 2, "Active:  ", curses.A_BOLD)
    safe_addstr(win, y + 2, x + 11, "JAMMING" if active else "IDLE",
                curses.color_pair(C_CRIT if active else C_OK) | curses.A_BOLD)

    safe_addstr(win, y + 3, x + 2, f"Sessions: {sessions}", curses.color_pair(C_DIM))

    session = jammer_status.get("active_session")
    if session:
        safe_addstr(win, y + 4, x + 2, f"Mode: {session['mode']}  Ch: {session['channel']}",
                    curses.color_pair(C_WARN))
        safe_addstr(win, y + 5, x + 2, f"Packets: {session['packets_sent']}",
                    curses.color_pair(C_CRIT))


def draw_alert_log(win, y, x, w, h, alerts):
    """Draw the alert log panel."""
    draw_box(win, y, x, h, w, "RECENT ALERTS")

    if not alerts:
        safe_addstr(win, y + 1, x + 2, "No alerts. System clean.", curses.color_pair(C_OK))
        return

    max_rows = h - 2
    recent = alerts[-max_rows:]
    for i, alert in enumerate(recent):
        row = y + 1 + i
        if row >= y + h - 1:
            break

        data = alert.get("data", {})
        level = data.get("level", "info")
        msg = data.get("message", "")[:w - 6]
        ts = alert.get("timestamp", "")[:19]

        color = C_CRIT if level == "critical" else C_WARN if level == "warning" else C_INFO
        safe_addstr(win, row, x + 2, f"[{ts}] ", curses.color_pair(C_DIM))
        safe_addstr(win, row, x + 23, msg, curses.color_pair(color))


def draw_help_bar(win, y, width):
    """Draw the bottom help bar."""
    help_text = " [S]can  [J]am On/Off  [W]hitelist  [E]xport  [R]eset  [Q]uit  [↑↓]Scroll "
    safe_addstr(win, y, 0, help_text.center(width), curses.color_pair(C_HEADER))


def draw_rssi_bars(win, y, x, w, devices):
    """Draw RSSI signal strength visualization."""
    h = min(len(devices) + 2, 8)
    draw_box(win, y, x, h, w, "SIGNAL STRENGTH")

    for i, dev in enumerate(devices[:h - 2]):
        row = y + 1 + i
        name = dev.get("name", "?")[:10]
        rssi = dev.get("rssi", -100)
        # Normalize RSSI: -30 (strong) to -100 (weak) => 0-20 bar width
        bar_len = max(0, min(20, int((rssi + 100) / 3.5)))
        bar = "█" * bar_len + "░" * (20 - bar_len)

        color = C_OK if rssi > -50 else C_WARN if rssi > -70 else C_CRIT
        safe_addstr(win, row, x + 2, f"{name:>10} ", curses.color_pair(C_DIM))
        safe_addstr(win, row, x + 13, bar, curses.color_pair(color))
        safe_addstr(win, row, x + 34, f" {rssi}dBm", curses.color_pair(C_DIM))


async def dashboard_main(stdscr, use_sim=False):
    """Main dashboard loop."""
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)
    init_colors()

    config = load_config()

    if use_sim:
        scanner = SimulatedScanner(config)
        jammer = SimulatedJammer(config)
    else:
        scanner = BluetoothScanner(config)
        jammer = BluetoothJammer(config)

    logger = BlueShieldLogger(config)
    scroll_offset = 0
    auto_scan = True
    last_scan_time = 0
    scan_interval = config.get("scan_interval", 5)

    while True:
        try:
            height, width = stdscr.getmaxyx()
            if height < 20 or width < 80:
                stdscr.clear()
                safe_addstr(stdscr, 0, 0, "Terminal too small. Need 80x20 minimum.", curses.color_pair(C_CRIT))
                stdscr.refresh()
                time.sleep(0.5)
                continue

            stdscr.erase()

            # ── Auto-scan ──
            now = time.time()
            if auto_scan and (now - last_scan_time) >= scan_interval:
                scan_result = await scanner.run_scan()
                logger.log_scan(scan_result)
                last_scan_time = now

                # Log alerts for unknown devices
                if scan_result.get("unknown_devices", 0) > 0:
                    logger.log_alert(
                        scan_result["alert_status"],
                        f"{scan_result['unknown_devices']} unknown device(s) detected",
                        [d for d in scan_result["devices_found"] if not d.get("is_known")]
                    )

            # ── Layout ──
            summary = scanner.get_device_summary()
            devices = scanner.get_all_devices()
            jammer_status = jammer.get_status()
            alerts = logger.get_alerts(count=10)

            # Header (rows 0-1)
            draw_header(stdscr, width, scanner, jammer)

            # Left column: Summary + Devices
            left_w = max(width * 2 // 3, 60)
            draw_summary_panel(stdscr, 3, 0, left_w, summary)

            device_table_h = max(height - 22, 8)
            draw_device_table(stdscr, 11, 0, left_w, device_table_h, devices, scroll_offset)

            # Right column: Jammer + RSSI
            right_x = left_w + 1
            right_w = width - right_x - 1
            if right_w > 20:
                draw_jammer_panel(stdscr, 3, right_x, right_w, jammer_status)
                if devices:
                    draw_rssi_bars(stdscr, 10, right_x, right_w, devices[:5])

            # Alert log at bottom
            alert_h = min(6, height - device_table_h - 14)
            if alert_h > 2:
                draw_alert_log(stdscr, 11 + device_table_h, 0, width - 1, alert_h, alerts)

            # Help bar
            draw_help_bar(stdscr, height - 1, width)

            stdscr.refresh()

            # ── Input ──
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                break
            elif key == ord('s') or key == ord('S'):
                scan_result = await scanner.run_scan()
                logger.log_scan(scan_result)
                last_scan_time = time.time()
            elif key == ord('j') or key == ord('J'):
                if jammer.is_jamming:
                    session = jammer.stop_jam()
                    if session:
                        logger.log_jam_session({
                            "session_id": session.session_id,
                            "mode": session.mode,
                            "packets_sent": session.packets_sent,
                        })
                else:
                    try:
                        config["jam_enabled"] = True
                        jammer.config = config
                        jammer.start_jam(mode="sweep")
                    except RuntimeError:
                        pass
            elif key == ord('w') or key == ord('W'):
                # Whitelist the most recent unknown device
                for dev in devices:
                    if not dev.get("is_known") and dev.get("alert_level") != "none":
                        scanner.add_known_device(dev["address"])
                        logger.log_event("whitelist", {"address": dev["address"], "name": dev.get("name")})
                        break
            elif key == ord('e') or key == ord('E'):
                filepath = logger.export_report()
                logger.log_event("export", {"file": filepath})
            elif key == ord('r') or key == ord('R'):
                scanner.devices.clear()
                scanner.scan_history.clear()
                scanner.total_scans = 0
                scroll_offset = 0
            elif key == curses.KEY_UP:
                scroll_offset = max(0, scroll_offset - 1)
            elif key == curses.KEY_DOWN:
                scroll_offset = min(max(0, len(devices) - 5), scroll_offset + 1)

            await asyncio.sleep(0.1)

        except KeyboardInterrupt:
            break

    # Cleanup
    if jammer.is_jamming:
        jammer.stop_jam()


def main():
    parser = argparse.ArgumentParser(description="BlueShield Terminal Dashboard")
    parser.add_argument("--sim", action="store_true", help="Use simulated scanner (no hardware needed)")
    args = parser.parse_args()

    def run(stdscr):
        asyncio.run(dashboard_main(stdscr, use_sim=args.sim))

    curses.wrapper(run)


if __name__ == "__main__":
    main()
