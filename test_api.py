#!/usr/bin/env python3
"""Test script for FastAPI /api/scan endpoint"""

import requests

API_URL = "http://127.0.0.1:5966/api/scan"

print(f"=== Testing {API_URL} ===\n")

try:
    response = requests.post(API_URL, timeout=30)
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}\n")

    if response.status_code == 200:
        data = response.json()
        print(f"Response JSON: {data}\n")

        if "networks" in data:
            networks = data["networks"]
            print(f"Found {len(networks)} networks in response!")
            for net in networks:
                print(f"  - SSID: {net.get('ssid')}, Signal: {net.get('signal')}%, Security: {net.get('security')}")
        else:
            print("ERROR: 'networks' key not found in response!")

    else:
        print(f"ERROR: Non-200 status code!")
        print(f"Response text: {response.text}")

except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
    import traceback
    print("\nTraceback:")
    traceback.print_exc()

print("\n=== Test Complete ===")
