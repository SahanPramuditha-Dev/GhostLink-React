#!/usr/bin/env python3
"""Test script to debug recon device detection"""

from ghostlink.network.recon import (
    full_network_recon,
    print_recon_result,
    get_local_network,
    read_arp_table,
    get_manufacturer,
    _guess_device_type
)

print("="*60)
print("GHOSTLINK RECON DEBUG TEST")
print("="*60)

# Step 1: Get local network info
print("\n[1] Getting local network info...")
try:
    net_info = get_local_network()
    print(f"   Local IP: {net_info.local_ip}")
    print(f"   Gateway: {net_info.gateway}")
    print(f"   Subnet Mask: {net_info.subnet_mask}")
    print(f"   CIDR Prefix: {net_info.cidr_prefix}")
    print(f"   Network CIDR: {net_info.network_cidr}")
except Exception as e:
    print(f"   Error: {e}")

# Step 2: Read ARP table
print("\n[2] Reading ARP table...")
try:
    arp_table = read_arp_table()
    print(f"   Found {len(arp_table)} ARP entries:")
    for ip, mac in arp_table.items():
        manufacturer = get_manufacturer(mac)
        print(f"   - {ip} | {mac} | {manufacturer}")
except Exception as e:
    print(f"   Error: {e}")

# Step 3: Run full recon
print("\n[3] Running full network recon...")
try:
    result = full_network_recon(do_ping_sweep=True)
    print_recon_result(result)
    
    print("\n" + "="*60)
    print("DEVICE TYPE DEBUG INFO")
    print("="*60)
    for device in result.devices:
        print(f"\nDevice: {device.ip}")
        print(f"  MAC: {device.mac}")
        print(f"  Hostname: {device.hostname}")
        print(f"  Manufacturer: {device.manufacturer}")
        print(f"  Open Ports: {device.open_ports}")
        print(f"  Device Type (from _guess_device_type): {_guess_device_type(device.manufacturer, device.open_ports, device.hostname)}")
        print(f"  Final Device Type: {device.device_type}")
except Exception as e:
    print(f"   Error: {e}")
    import traceback
    traceback.print_exc()
