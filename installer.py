#!/usr/bin/env python3
"""
BlueShield Installer — Cross-platform GUI installer
Supports: Windows, Linux, macOS, Raspberry Pi

Usage:
    python installer.py
"""

import os
import sys
import subprocess
import threading
import platform
import shutil
import webbrowser
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:
    print("tkinter not found. Install it with: sudo apt install python3-tk")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
APP_NAME    = "BlueShield"
APP_VERSION = "5.4"
REPO_URL    = "https://github.com/mathib2/BlueShield"
SCRIPT_DIR  = Path(__file__).parent.resolve()
SYSTEM      = platform.system()   # "Windows", "Linux", "Darwin"
IS_PI       = (SYSTEM == "Linux" and
               Path("/proc/device-tree/model").exists() and
               "Raspberry Pi" in Path("/proc/device-tree/model").read_text(errors="ignore"))

ACCENT  = "#58a6ff"
RED     = "#f85149"
GREEN   = "#3fb950"
ORANGE  = "#d29922"
BG      = "#0d1117"
BG2     = "#161b22"
BG3     = "#1c2333"
FG      = "#e6edf3"
FG2     = "#8b949e"
BORDER  = "#21262d"

REQUIRED_PACKAGES = [
    "bleak>=0.21.0",
    "bluetooth-numbers>=1.0.0",
    "flask>=3.0.0",
    "flask-socketio>=5.3.0",
]
if SYSTEM == "Windows":
    REQUIRED_PACKAGES.append("windows-curses>=2.3.1")


# ── Helper ────────────────────────────────────────────────────────────────────
def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def python_exe():
    return sys.executable


# ── Main Installer Window ─────────────────────────────────────────────────────
class InstallerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION} — Installer")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.geometry("620x560")
        self._center()

        self._install_path = tk.StringVar(value=str(self._default_install_path()))
        self._create_shortcut = tk.BooleanVar(value=True)
        self._add_to_path = tk.BooleanVar(value=(SYSTEM == "Linux"))
        self._install_service = tk.BooleanVar(value=IS_PI)
        self._open_after = tk.BooleanVar(value=True)

        self._build_ui()
        self._detect_environment()

    def _center(self):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - 620) // 2
        y  = (sh - 560) // 2
        self.geometry(f"620x560+{x}+{y}")

    def _default_install_path(self):
        if SYSTEM == "Windows":
            return Path(os.environ.get("LOCALAPPDATA", "C:/Users")) / "BlueShield"
        elif SYSTEM == "Darwin":
            return Path.home() / "Applications" / "BlueShield"
        else:
            return Path.home() / "BlueShield"

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._style_ttk()

        # Header
        hdr = tk.Frame(self, bg=BG2, height=72)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🛡  BlueShield", font=("Segoe UI", 18, "bold"),
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20)
        tk.Label(hdr, text=f"v{APP_VERSION}", font=("Segoe UI", 9),
                 bg=BG2, fg=FG2).pack(side="left", padx=0, pady=24)
        tk.Label(hdr, text=f"{SYSTEM}  •  Python {sys.version.split()[0]}",
                 font=("Courier New", 9), bg=BG2, fg=FG2).pack(side="right", padx=20)

        # Environment badges
        self._env_frame = tk.Frame(self, bg=BG3, pady=6)
        self._env_frame.pack(fill="x")
        self._env_label = tk.Label(self._env_frame, text="Checking environment…",
                                   font=("Segoe UI", 9), bg=BG3, fg=FG2)
        self._env_label.pack(padx=16)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

        # Options
        opts = tk.Frame(self, bg=BG, pady=10)
        opts.pack(fill="x", padx=20)

        # Install path
        tk.Label(opts, text="Install directory", font=("Segoe UI", 9, "bold"),
                 bg=BG, fg=FG2).pack(anchor="w", pady=(8,2))
        path_row = tk.Frame(opts, bg=BG)
        path_row.pack(fill="x")
        tk.Entry(path_row, textvariable=self._install_path, bg=BG3, fg=FG,
                 insertbackground=FG, relief="flat", font=("Courier New", 9),
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(side="left", fill="x", expand=True, padx=(0,6))
        tk.Button(path_row, text="Browse…", command=self._browse,
                  bg=BG3, fg=FG2, relief="flat", activebackground=BG2,
                  font=("Segoe UI", 9), cursor="hand2").pack(side="left")

        # Checkboxes
        ck_frame = tk.Frame(opts, bg=BG, pady=6)
        ck_frame.pack(fill="x")

        self._cb(ck_frame, "Create desktop shortcut", self._create_shortcut)
        self._cb(ck_frame, "Add BlueShield to PATH" if SYSTEM != "Windows" else
                 "Add to Start Menu", self._add_to_path)
        if SYSTEM == "Linux":
            self._cb(ck_frame, "Install as systemd service (auto-start on boot)",
                     self._install_service)
        self._cb(ck_frame, "Open BlueShield after install", self._open_after)

        # Packages list
        tk.Label(opts, text="Python packages to install", font=("Segoe UI", 9, "bold"),
                 bg=BG, fg=FG2).pack(anchor="w", pady=(10,4))
        self._pkg_frame = tk.Frame(opts, bg=BG)
        self._pkg_frame.pack(fill="x")
        self._pkg_labels = {}
        for pkg in REQUIRED_PACKAGES:
            row = tk.Frame(self._pkg_frame, bg=BG)
            row.pack(fill="x", pady=1)
            tk.Label(row, text="•", bg=BG, fg=FG2, font=("Courier New", 9)).pack(side="left")
            lbl = tk.Label(row, text=pkg, bg=BG, fg=FG2, font=("Courier New", 9))
            lbl.pack(side="left", padx=4)
            self._pkg_labels[pkg] = lbl

        sep2 = tk.Frame(self, bg=BORDER, height=1)
        sep2.pack(fill="x")

        # Log area
        log_frame = tk.Frame(self, bg=BG, pady=6)
        log_frame.pack(fill="both", expand=True, padx=12)
        self._log = tk.Text(log_frame, height=6, bg=BG3, fg=FG2,
                            font=("Courier New", 8), relief="flat",
                            state="disabled", wrap="word",
                            highlightthickness=1, highlightbackground=BORDER)
        self._log.pack(fill="both", expand=True)
        self._log.tag_config("ok",  foreground=GREEN)
        self._log.tag_config("err", foreground=RED)
        self._log.tag_config("hdr", foreground=ACCENT)
        self._log.tag_config("warn",foreground=ORANGE)

        # Progress
        self._progress = ttk.Progressbar(self, mode="indeterminate",
                                          style="Accent.Horizontal.TProgressbar")
        self._progress.pack(fill="x", padx=12, pady=(0,4))

        # Bottom buttons
        btn_row = tk.Frame(self, bg=BG2, pady=10)
        btn_row.pack(fill="x", side="bottom")
        tk.Button(btn_row, text="Cancel", command=self.destroy,
                  bg=BG3, fg=FG2, relief="flat", font=("Segoe UI", 9),
                  activebackground=BG, cursor="hand2", padx=12, pady=6
                  ).pack(side="right", padx=(4,16))
        self._install_btn = tk.Button(btn_row, text="Install", command=self._start_install,
                                      bg=ACCENT, fg="#fff", relief="flat",
                                      font=("Segoe UI", 10, "bold"),
                                      activebackground="#4090df", cursor="hand2",
                                      padx=20, pady=6)
        self._install_btn.pack(side="right", padx=4)

    def _cb(self, parent, text, var):
        tk.Checkbutton(parent, text=text, variable=var, bg=BG, fg=FG,
                       selectcolor=BG3, activebackground=BG, activeforeground=FG,
                       font=("Segoe UI", 9), anchor="w", cursor="hand2"
                       ).pack(fill="x", pady=1)

    def _style_ttk(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("Accent.Horizontal.TProgressbar", troughcolor=BG3,
                     background=ACCENT, thickness=4)

    def _browse(self):
        path = filedialog.askdirectory(title="Choose install directory",
                                       initialdir=self._install_path.get())
        if path:
            self._install_path.set(path)

    # ── Environment detection ─────────────────────────────────────────────────
    def _detect_environment(self):
        parts = []
        py_ok = sys.version_info >= (3, 9)
        parts.append(("✓" if py_ok else "✗") + f" Python {sys.version.split()[0]}")
        pip_ok = shutil.which("pip3") or shutil.which("pip")
        parts.append(("✓" if pip_ok else "✗") + " pip")
        if SYSTEM == "Linux":
            bt_ok = shutil.which("hciconfig") is not None
            parts.append(("✓" if bt_ok else "⚠") + " BlueZ")
        if IS_PI:
            parts.append("✓ Raspberry Pi detected")
        self._env_label.config(text="   ".join(parts), fg=GREEN if py_ok else ORANGE)

    # ── Install ───────────────────────────────────────────────────────────────
    def _start_install(self):
        self._install_btn.config(state="disabled", text="Installing…")
        self._progress.start(10)
        threading.Thread(target=self._run_install, daemon=True).start()

    def _run_install(self):
        try:
            self._log_write(f"BlueShield v{APP_VERSION} Installer\n", "hdr")
            self._log_write(f"Platform: {SYSTEM} | Python: {sys.version.split()[0]}\n")
            self._log_write(f"Source:   {SCRIPT_DIR}\n")

            # 1. Copy files
            dst = Path(self._install_path.get())
            self._log_write(f"\n→ Installing to {dst}\n")
            if dst != SCRIPT_DIR:
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(SCRIPT_DIR, dst, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("__pycache__","*.pyc",
                                                              ".git","venv",".venv"))
            self._log_write("✓ Files copied\n", "ok")

            # 2. Install pip packages
            self._log_write("\n→ Installing Python packages\n")
            for pkg in REQUIRED_PACKAGES:
                self._log_write(f"  pip install {pkg} … ")
                r = run([python_exe(), "-m", "pip", "install", pkg, "--quiet"])
                if r.returncode == 0:
                    self._log_write("OK\n", "ok")
                    self.after(0, lambda p=pkg: self._pkg_labels[p].config(fg=GREEN))
                else:
                    self._log_write(f"FAILED\n{r.stderr.strip()}\n", "err")
                    self.after(0, lambda p=pkg: self._pkg_labels[p].config(fg=RED))

            # 3. Desktop shortcut
            if self._create_shortcut.get():
                self._log_write("\n→ Creating desktop shortcut\n")
                self._make_shortcut(dst)

            # 4. Systemd service (Linux)
            if SYSTEM == "Linux" and self._install_service.get():
                self._log_write("\n→ Installing systemd service\n")
                self._install_systemd(dst)

            self._log_write("\n✓ Installation complete!\n", "ok")
            self._log_write(f"Run: python -m blueshield --sim\n", "hdr")

            # Done
            self.after(0, self._on_done)

        except Exception as ex:
            self._log_write(f"\n✗ Error: {ex}\n", "err")
            self.after(0, lambda: self._install_btn.config(state="normal", text="Retry"))
            self.after(0, self._progress.stop)

    def _make_shortcut(self, install_dir):
        if SYSTEM == "Windows":
            desktop = Path.home() / "Desktop"
            bat = desktop / "BlueShield.bat"
            bat.write_text(
                f'@echo off\n'
                f'cd /d "{install_dir}"\n'
                f'start "" "http://localhost:5000"\n'
                f'"{python_exe()}" -m blueshield --port 5000\n'
                f'pause\n'
            )
            self._log_write(f"  Created: {bat}\n", "ok")

        elif SYSTEM == "Darwin":
            desktop = Path.home() / "Desktop"
            app_path = desktop / "BlueShield.command"
            app_path.write_text(
                f'#!/bin/bash\n'
                f'cd "{install_dir}"\n'
                f'"{python_exe()}" -m blueshield --port 5000 &\n'
                f'sleep 1 && open "http://localhost:5000"\n'
            )
            app_path.chmod(0o755)
            self._log_write(f"  Created: {app_path}\n", "ok")

        elif SYSTEM == "Linux":
            desktop = Path.home() / "Desktop"
            desktop.mkdir(exist_ok=True)
            shortcut = desktop / "blueshield.desktop"
            shortcut.write_text(
                f'[Desktop Entry]\n'
                f'Name=BlueShield\n'
                f'Comment=Bluetooth Security Monitor\n'
                f'Exec={python_exe()} -m blueshield --port 5000\n'
                f'Path={install_dir}\n'
                f'Icon={install_dir}/assets/icon.png\n'
                f'Terminal=true\n'
                f'Type=Application\n'
                f'Categories=Network;Security;\n'
            )
            shortcut.chmod(0o755)
            self._log_write(f"  Created: {shortcut}\n", "ok")

    def _install_systemd(self, install_dir):
        service_content = (
            "[Unit]\n"
            "Description=BlueShield Bluetooth Security Monitor\n"
            "After=network.target bluetooth.target\n\n"
            "[Service]\n"
            f"ExecStart={python_exe()} -m blueshield --port 5000\n"
            f"WorkingDirectory={install_dir}\n"
            "Restart=on-failure\n"
            "User=pi\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        svc_path = Path("/etc/systemd/system/blueshield.service")
        try:
            svc_path.write_text(service_content)
            run(["sudo", "systemctl", "daemon-reload"])
            run(["sudo", "systemctl", "enable", "blueshield"])
            self._log_write("  Systemd service enabled (sudo systemctl start blueshield)\n", "ok")
        except PermissionError:
            # Try writing to home dir and ask user to copy manually
            alt = install_dir / "blueshield.service"
            alt.write_text(service_content)
            self._log_write(f"  ⚠ No sudo — service file saved to {alt}\n", "warn")
            self._log_write("  Run: sudo cp blueshield.service /etc/systemd/system/\n", "warn")
            self._log_write("       sudo systemctl enable --now blueshield\n", "warn")

    def _on_done(self):
        self._progress.stop()
        self._progress.config(mode="determinate", value=100,
                               style="Done.Horizontal.TProgressbar")
        ttk.Style().configure("Done.Horizontal.TProgressbar",
                              troughcolor=BG3, background=GREEN, thickness=4)
        self._install_btn.config(state="normal", text="Done ✓",
                                 bg=GREEN, activebackground="#2d8f40")
        if self._open_after.get():
            install_dir = Path(self._install_path.get())
            self._launch_app(install_dir)

    def _launch_app(self, install_dir):
        self._log_write("\n→ Launching BlueShield…\n", "hdr")
        subprocess.Popen(
            [python_exe(), "-m", "blueshield", "--sim", "--port", "5000"],
            cwd=str(install_dir),
            creationflags=subprocess.CREATE_NEW_CONSOLE if SYSTEM == "Windows" else 0,
        )
        import time; time.sleep(1.5)
        webbrowser.open("http://localhost:5000")

    def _log_write(self, msg, tag=None):
        self.after(0, lambda m=msg, t=tag: self._append_log(m, t))

    def _append_log(self, msg, tag=None):
        self._log.config(state="normal")
        if tag:
            self._log.insert("end", msg, tag)
        else:
            self._log.insert("end", msg)
        self._log.see("end")
        self._log.config(state="disabled")


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = InstallerApp()
    app.mainloop()
