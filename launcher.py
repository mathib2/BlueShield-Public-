"""
BlueShield Desktop Launcher
Double-click to start BlueShield and open the dashboard in your browser.
Works on Windows — runs in simulated mode (no hardware needed).
"""

import sys
import os
import threading
import webbrowser
import time
import tkinter as tk
from tkinter import font as tkfont

# ── Config ────────────────────────────────────────────────────
PORT = 8080
HOST = "127.0.0.1"
URL = f"http://{HOST}:{PORT}"

# ── Ensure project root is on path ───────────────────────────
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)


class BlueShieldLauncher:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BlueShield")
        self.root.configure(bg="#0d1117")
        self.root.resizable(False, False)

        # Window size and center
        w, h = 420, 520
        sx = (self.root.winfo_screenwidth() - w) // 2
        sy = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{sx}+{sy}")

        # Remove default titlebar look — dark theme
        self.root.overrideredirect(False)

        self.server_thread = None
        self.server_running = False
        self._build_ui()

    def _build_ui(self):
        bg = "#0d1117"
        fg = "#e6edf3"
        accent = "#58a6ff"
        green = "#3fb950"
        red = "#f85149"
        dim = "#484f58"
        card_bg = "#161b22"

        # ── Logo Area ──
        logo_frame = tk.Frame(self.root, bg=bg)
        logo_frame.pack(pady=(30, 10))

        # Draw Bluetooth-like logo on canvas
        canvas = tk.Canvas(logo_frame, width=80, height=80, bg=bg, highlightthickness=0)
        canvas.pack()
        # Shield shape
        cx, cy = 40, 40
        canvas.create_oval(8, 8, 72, 72, outline=accent, width=3)
        canvas.create_oval(18, 18, 62, 62, outline=accent, width=1, dash=(3, 3))
        # Bluetooth symbol
        canvas.create_line(40, 16, 40, 64, fill=accent, width=2.5)
        canvas.create_line(40, 16, 54, 30, fill=accent, width=2.5)
        canvas.create_line(54, 30, 26, 50, fill=accent, width=2.5)
        canvas.create_line(40, 64, 54, 50, fill=accent, width=2.5)
        canvas.create_line(54, 50, 26, 30, fill=accent, width=2.5)

        # ── Title ──
        title_font = tkfont.Font(family="Segoe UI", size=22, weight="bold")
        tk.Label(self.root, text="BlueShield", font=title_font, fg=fg, bg=bg).pack(pady=(5, 0))

        ver_font = tkfont.Font(family="Consolas", size=9)
        tk.Label(self.root, text="v5.2 — Bluetooth Intelligence Platform", font=ver_font, fg=dim, bg=bg).pack(pady=(0, 20))

        # ── Status Card ──
        card = tk.Frame(self.root, bg=card_bg, padx=20, pady=15, highlightbackground="#21262d", highlightthickness=1)
        card.pack(padx=30, fill="x")

        status_font = tkfont.Font(family="Consolas", size=10)
        self.status_dot = tk.Label(card, text="●", font=("Consolas", 14), fg=dim, bg=card_bg)
        self.status_dot.grid(row=0, column=0, padx=(0, 8))
        self.status_label = tk.Label(card, text="Server Stopped", font=status_font, fg=dim, bg=card_bg, anchor="w")
        self.status_label.grid(row=0, column=1, sticky="w")

        self.url_label = tk.Label(card, text=URL, font=("Consolas", 9), fg=accent, bg=card_bg, cursor="hand2")
        self.url_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.url_label.bind("<Button-1>", lambda e: webbrowser.open(URL) if self.server_running else None)

        mode_label = tk.Label(card, text="Mode: Simulated (no hardware)", font=("Consolas", 8), fg=dim, bg=card_bg)
        mode_label.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self.port_label = tk.Label(card, text=f"Port: {PORT}  •  Host: {HOST}", font=("Consolas", 8), fg=dim, bg=card_bg)
        self.port_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(2, 0))

        # ── Buttons ──
        btn_frame = tk.Frame(self.root, bg=bg)
        btn_frame.pack(pady=25)

        btn_font = tkfont.Font(family="Segoe UI", size=11, weight="bold")

        self.start_btn = tk.Button(
            btn_frame, text="▶  Start Server", font=btn_font,
            fg="#ffffff", bg=accent, activebackground="#4090e0",
            relief="flat", padx=25, pady=10, cursor="hand2",
            command=self._start_server
        )
        self.start_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = tk.Button(
            btn_frame, text="■  Stop", font=btn_font,
            fg="#ffffff", bg=red, activebackground="#d04040",
            relief="flat", padx=25, pady=10, cursor="hand2",
            command=self._stop_server, state="disabled"
        )
        self.stop_btn.grid(row=0, column=1, padx=5)

        # Open browser button
        open_font = tkfont.Font(family="Segoe UI", size=10)
        self.open_btn = tk.Button(
            self.root, text="🌐  Open Dashboard in Browser", font=open_font,
            fg=accent, bg=card_bg, activebackground="#1c2333",
            relief="flat", padx=15, pady=8, cursor="hand2",
            command=lambda: webbrowser.open(URL),
            state="disabled",
            highlightbackground="#21262d", highlightthickness=1
        )
        self.open_btn.pack(padx=30, fill="x")

        # ── Footer ──
        footer_font = tkfont.Font(family="Consolas", size=8)
        tk.Label(
            self.root, text="Senior Project • Cybersecurity Research",
            font=footer_font, fg=dim, bg=bg
        ).pack(side="bottom", pady=(0, 12))

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_status(self, text, color):
        self.status_dot.configure(fg=color)
        self.status_label.configure(text=text, fg=color)

    def _start_server(self):
        self._set_status("Starting...", "#d29922")
        self.start_btn.configure(state="disabled")
        self.root.update()

        def run():
            try:
                os.environ["FLASK_ENV"] = "production"
                from blueshield.dashboard.app import main as app_main, app, socketio, config
                from blueshield.config.settings import load_config

                # Override sys.argv for the argparse in main()
                sys.argv = ["blueshield", "--sim", "--port", str(PORT), "--host", HOST]

                # Initialize everything via main() logic but run server ourselves
                import argparse
                from blueshield.config.settings import load_config, LOG_DIR
                from blueshield.scanner.bt_scanner import SimulatedScanner
                from blueshield.scanner.fingerprint import BLEFingerprintEngine
                from blueshield.scanner.tracker_detector import TrackerDetector
                from blueshield.scanner.ai_classifier import AIDeviceClassifier
                from blueshield.scanner.advanced_analysis import (
                    FollowingDetector, ShadowDeviceDetector, EnvironmentFingerprint,
                    DeviceLifeStory, ConversationGraph, MovementTrailTracker,
                )
                from blueshield.jammer.bt_jammer import SimulatedJammer
                from blueshield.logs.logger import BlueShieldLogger
                import blueshield.dashboard.app as app_module

                cfg = load_config()
                app_module.config = cfg
                app_module.scan_interval = cfg.get("scan_interval", 15)
                app_module.platform_info = app_module.detect_platform()
                app_module.scanner = SimulatedScanner(cfg)
                app_module.jammer = SimulatedJammer(cfg)
                app_module.logger = BlueShieldLogger(cfg)
                app_module.fingerprint_engine = BLEFingerprintEngine()
                app_module.tracker_detector = TrackerDetector()
                app_module.ai_classifier = AIDeviceClassifier()
                app_module.following_detector = FollowingDetector()
                app_module.shadow_detector = ShadowDeviceDetector()
                app_module.env_fingerprint = EnvironmentFingerprint()
                app_module.life_story = DeviceLifeStory()
                app_module.conversation_graph = ConversationGraph()
                app_module.trail_tracker = MovementTrailTracker()

                self.server_running = True
                self.root.after(0, self._on_server_started)

                # Start background scan loop
                scan_thread = threading.Thread(target=app_module.background_scan_loop, daemon=True)
                scan_thread.start()

                # Run Flask-SocketIO server (this blocks)
                socketio.run(app, host=HOST, port=PORT, debug=False, use_reloader=False, log_output=False)
            except Exception as e:
                self.root.after(0, lambda: self._set_status(f"Error: {e}", "#f85149"))
                self.root.after(0, lambda: self.start_btn.configure(state="normal"))

        self.server_thread = threading.Thread(target=run, daemon=True)
        self.server_thread.start()

    def _on_server_started(self):
        self._set_status("Running", "#3fb950")
        self.stop_btn.configure(state="normal")
        self.open_btn.configure(state="normal")
        # Auto-open browser after short delay
        self.root.after(1500, lambda: webbrowser.open(URL))

    def _stop_server(self):
        self._set_status("Stopped", "#484f58")
        self.server_running = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled")
        # Force kill the server thread (it's daemon so it'll die with the process)
        # For clean shutdown we'd need socketio.stop() but daemon threads work fine

    def _on_close(self):
        self.server_running = False
        self.root.destroy()
        os._exit(0)  # Force exit to kill daemon threads

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = BlueShieldLauncher()
    app.run()
