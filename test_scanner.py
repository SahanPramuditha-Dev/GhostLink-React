#!/usr/bin/env python3
"""Test script for WiFiScanner"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from ghostlink.network.scanner import WiFiScanner

print("=== GhostLink WiFi Scanner Test ===\n")

print("[1/3] Listing available wireless interfaces...")
interfaces = WiFiScanner.list_interfaces()
print(f"Found {len(interfaces)} interfaces: {interfaces}\n")

print("[2/3] Scanning for networks...")
try:
    networks = WiFiScanner.scan()
    print(f"Scan complete! Found {len(networks)} networks.\n")

    if networks:
        print("=== Networks Found ===")
        for i, net in enumerate(networks, 1):
            print(f"\nNetwork {i}:")
            print(f"  SSID: {net.ssid}")
            print(f"  BSSID: {net.bssid}")
            print(f"  Signal: {net.signal}%")
            print(f"  Security: {net.security}")
            print(f"  Hidden: {net.hidden}")
            print(f"  Channel: {net.channel}")
            print(f"  Interface: {net.interface}")
    else:
        print("No networks found!")

except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
    import traceback
    print("\nTraceback:")
    traceback.print_exc()

print("\n=== Test Complete ===")
