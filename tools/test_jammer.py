#!/usr/bin/env python3
"""Test all jammer modes on real hardware."""
import time
from blueshield.jammer.bt_jammer import BluetoothJammer, JamMode

config = {
    "interface": "hci0",
    "jammer_secondary_interface": "hci3",
    "jam_enabled": True,
    "jam_power": -20,
}

jammer = BluetoothJammer(config)
modes = ["flood", "continuous", "sweep", "reactive", "deauth", "phantom_flood", "connection_disrupt"]

for mode in modes:
    try:
        session = jammer.start_jam(mode=mode, channel=39, target="FF:FF:FF:FF:FF:FF")
        time.sleep(3)
        status = jammer.get_status()
        pps = status["packets_per_second"]
        pkts = status["active_session"]["packets_sent"] if status["active_session"] else 0
        backend = status["backend_type"]
        dual = status["dual_adapter"]
        adapters = status["adapters_active"]
        jammer.stop_jam()
        time.sleep(0.3)
        print("  %-22s: %8.0f pps | %7d pkts | %s | dual=%s | %s" % (mode, pps, pkts, backend, dual, adapters))
    except Exception as e:
        print("  %-22s: ERROR - %s" % (mode, e))
        try:
            jammer.stop_jam()
        except:
            pass
        time.sleep(0.3)

print()
print("=== JAMMER TEST COMPLETE ===")
