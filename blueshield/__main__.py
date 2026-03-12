"""BlueShield entry point.

Usage:
    python -m blueshield              # Web dashboard (default)
    python -m blueshield --sim        # Web dashboard with simulated data
    python -m blueshield --terminal   # Legacy terminal (curses) dashboard
"""

import sys

if __name__ == "__main__":
    if "--terminal" in sys.argv:
        sys.argv.remove("--terminal")
        from blueshield.dashboard.terminal_ui import main
    else:
        from blueshield.dashboard.app import main
    main()
