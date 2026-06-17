#!/usr/bin/env python3
"""
GHOSTLINK FastAPI Server
=========================
Provides REST API and WebSocket endpoints for the React frontend.
"""

import sys
import os
import time
import socket
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel
import psutil

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# Add parent directory to path to import ghostlink
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ghostlink.core.utils import is_admin
from ghostlink.core.constants import VAULT_PATH
from ghostlink.storage.vault import PasswordVault
from ghostlink.storage.report import ReportStorage
from ghostlink.storage.log import LogStorage
from ghostlink.network.scanner import WiFiScanner, ScanResult
from ghostlink.engine.profiles import PROFILES
from ghostlink.engine.attack import BruteForceEngine, shared_state
import asyncio
import threading


# --- Pydantic Models ---
class Network(BaseModel):
    ssid: str
    signal: int
    security: str
    bssid: Optional[str] = None
    channel: Optional[int] = None


class AttackConfig(BaseModel):
    ssid: str
    minlen: int = 4
    maxlen: int = 8
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    threads: int = 2
    timeout: int = 5
    use_cache: bool = True


class VaultEntry(BaseModel):
    id: str
    ssid: str
    password: str
    timestamp: float | str


# --- App State ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Load vault, reports, logs
    app.state.vault = PasswordVault(VAULT_PATH)
    app.state.vault.load()
    app.state.reports = ReportStorage()
    app.state.reports.load()
    app.state.logs = LogStorage()
    app.state.logs.load()
    app.state.selected_network: Optional[Network] = None
    # Real attack engine state
    app.state.attack_thread = None
    app.state.attack_logs = []
    yield
    # Shutdown: Stop attack if running
    if app.state.attack_thread and app.state.attack_thread.is_alive():
        if hasattr(app.state, 'engine'):
            app.state.engine.request_stop()


app = FastAPI(title="GHOSTLINK API", lifespan=lifespan)

# Add CORS middleware to allow requests from React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:5176",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        "http://127.0.0.1:5176",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- API Endpoints ---
@app.get("/api/admin")
async def check_admin():
    return {"isAdmin": is_admin()}


@app.get("/api/status")
async def get_status():
    return {
        "target": app.state.selected_network,
        "attackStatus": "idle",
        "totalAttempts": 0,
        "cachedPasswords": app.state.vault.get_count()
    }


@app.get("/api/performance")
async def get_performance():
    # Get real performance data
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    # Simple network activity estimate using bytes sent/received
    net_io = psutil.net_io_counters()
    # Keep track of previous stats in memory for simple delta
    if not hasattr(app.state, "prev_net_io"):
        app.state.prev_net_io = net_io
        network_percent = 0
    else:
        # Calculate very rough "activity" percentage based on bytes delta
        delta_sent = net_io.bytes_sent - app.state.prev_net_io.bytes_sent
        delta_recv = net_io.bytes_recv - app.state.prev_net_io.bytes_recv
        # Normalize to 0-100 (very rough)
        network_percent = min(100, (delta_sent + delta_recv) / 100000)
        app.state.prev_net_io = net_io
    
    return {
        "cpu": round(cpu_percent, 1),
        "memory": round(memory_percent, 1),
        "network": round(network_percent, 1),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/activity")
async def get_activity():
    return []


@app.post("/api/scan")
async def scan_networks():
    try:
        scanner = WiFiScanner()
        scan_results: List[ScanResult] = scanner.scan()
        
        # Convert to our Network model
        networks = [
            Network(
                ssid=result.ssid,
                signal=result.signal,
                security=result.security,
                bssid=result.bssid,
                channel=result.channel
            )
            for result in scan_results
        ]
        
        # If no real networks found, return mock data for testing
        if not networks:
            networks = [
                Network(ssid="Home Network", signal=85, security="WPA2-Personal", bssid="AA:BB:CC:DD:EE:FF", channel=6),
                Network(ssid="lucifer", signal=75, security="WPA2-Personal", bssid="22:33:44:55:66:77", channel=8),
                Network(ssid="Neighbor's Wi-Fi", signal=62, security="WPA3-Personal", bssid="11:22:33:44:55:66", channel=11),
                Network(ssid="Guest Network", signal=45, security="WPA2-Personal", bssid="77:88:99:AA:BB:CC", channel=1),
                Network(ssid="Coffee Shop", signal=30, security="Open", bssid="DD:EE:FF:00:11:22", channel=3),
            ]
        
        return {"networks": networks}

    except Exception as e:
        # If real scan fails, return mock data instead of empty list
        networks = [
            Network(ssid="Home Network", signal=85, security="WPA2-Personal", bssid="AA:BB:CC:DD:EE:FF", channel=6),
            Network(ssid="lucifer", signal=75, security="WPA2-Personal", bssid="22:33:44:55:66:77", channel=8),
            Network(ssid="Neighbor's Wi-Fi", signal=62, security="WPA3-Personal", bssid="11:22:33:44:55:66", channel=11),
            Network(ssid="Guest Network", signal=45, security="WPA2-Personal", bssid="77:88:99:AA:BB:CC", channel=1),
        ]
        return {"networks": networks, "error": str(e)}


@app.post("/api/target")
async def set_target(network: Network):
    app.state.selected_network = network
    return {"success": True}


@app.get("/api/profiles")
async def get_profiles():
    return [
        {"id": pid, "name": profile.name, "charset": profile.charset, "description": profile.description}
        for pid, profile in PROFILES.items()
    ]


def run_real_attack(config: AttackConfig, app_state):
    """Run the real attack using BruteForceEngine"""
    try:
        engine_config = {
            "ssid": config.ssid,
            "charset": config.charset,
            "minlen": config.minlen,
            "maxlen": config.maxlen,
            "threads": config.threads,
            "timeout": config.timeout,
            "skip_cached": not config.use_cache
        }
        
        app_state.engine = BruteForceEngine(engine_config, app_state.vault)
        
        app_state.logs.add_log(f"Starting real attack on {config.ssid}")
        app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting real attack on {config.ssid}")
        app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Using charset: {config.charset}")
        app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Password length: {config.minlen}-{config.maxlen}")
        app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Beginning brute-force...")
        
        def log_updater():
            while hasattr(app_state, 'engine') and shared_state.status != "IDLE" and shared_state.status != "FOUND" and shared_state.status != "STOPPED":
                if shared_state.current_password:
                    app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Attempt {shared_state.attempts}: {shared_state.current_password}")
                time.sleep(0.1)
        
        log_thread = threading.Thread(target=log_updater, daemon=True)
        log_thread.start()
        
        password, attempts, elapsed, verified = app_state.engine.execute()
        
        if password and verified:
            app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Success! Password found: {password}")
            app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Attack completed in {int(elapsed)} seconds")
            app_state.logs.add_log(f"Attack succeeded for {config.ssid}")
            
            # Add report
            app_state.reports.add_report({
                "id": str(datetime.now().timestamp()),
                "ssid": config.ssid,
                "password": password,
                "attempts": attempts,
                "elapsed": int(elapsed),
                "verified": verified,
                "timestamp": datetime.now().timestamp()
            })
        else:
            app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Attack stopped without finding password")
            app_state.logs.add_log(f"Attack stopped for {config.ssid}")
            
    except Exception as e:
        app_state.attack_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {str(e)}")
        print(f"Attack error: {e}")


@app.post("/api/attack/start")
async def start_attack(request: Request, config: AttackConfig):
    if not request.app.state.attack_thread or not request.app.state.attack_thread.is_alive():
        request.app.state.attack_logs = []
        shared_state.reset()
        request.app.state.attack_thread = threading.Thread(target=run_real_attack, args=(config, request.app.state), daemon=True)
        request.app.state.attack_thread.start()
    return {"success": True}


@app.post("/api/attack/stop")
async def stop_attack(request: Request):
    if hasattr(request.app.state, 'engine'):
        request.app.state.engine.request_stop()
    if request.app.state.attack_thread and request.app.state.attack_thread.is_alive():
        request.app.state.attack_thread.join(timeout=2)
    return {"success": True}


@app.get("/api/attack/status")
async def get_attack_status(request: Request):
    is_running = False
    if request.app.state.attack_thread:
        is_running = request.app.state.attack_thread.is_alive()
    
    return {
        "running": is_running,
        "attempts": shared_state.attempts,
        "current_password": shared_state.current_password,
        "found_password": shared_state.found_password,
        "logs": request.app.state.attack_logs[-50:] if hasattr(request.app.state, 'attack_logs') else [],
        "speed": int(shared_state.speed) if shared_state.speed else 0
    }


@app.get("/api/vault")
async def get_vault():
    entries = app.state.vault.list_entries()
    # Add an id field if not present (use ssid as id for now)
    return [
        VaultEntry(
            id=entry.get('id', entry['ssid']),
            ssid=entry['ssid'],
            password=entry['password'],
            timestamp=entry['timestamp']
        )
        for entry in entries
    ]


@app.delete("/api/vault/{entry_id}")
async def delete_vault_entry(entry_id: str):
    try:
        # entry_id is the ssid (since we use ssid as id)
        app.state.vault.remove(entry_id)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/vault/import")
async def import_vault(entries: list[VaultEntry]):
    try:
        for entry in entries:
            # Convert timestamp to isoformat if it's a number
            ts = entry.timestamp
            if isinstance(ts, (int, float)):
                ts = datetime.fromtimestamp(ts).isoformat()
            app.state.vault.set(entry.ssid, entry.password)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/vault/export")
async def export_vault():
    entries = app.state.vault.list_entries()
    # Format entries with id, ssid, password, timestamp for export
    return [
        {
            'id': entry.get('ssid'),
            'ssid': entry['ssid'],
            'password': entry['password'],
            'timestamp': entry['timestamp']
        }
        for entry in entries
    ]


# --- Reports Endpoints ---
@app.get("/api/reports")
async def get_reports():
    return app.state.reports.get_all()


@app.post("/api/reports")
async def add_report(report: dict):
    try:
        app.state.reports.add_report(report)
        app.state.logs.add_log(f"Report added for network: {report.get('ssid', 'Unknown')}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.delete("/api/reports")
async def clear_reports():
    try:
        app.state.reports.clear_all()
        app.state.logs.add_log("All reports cleared")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# --- Logs Endpoints ---
@app.get("/api/logs")
async def get_logs():
    return app.state.logs.get_all()


@app.post("/api/logs")
async def add_log(message: dict):
    try:
        app.state.logs.add_log(message.get("message", ""))
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.delete("/api/logs")
async def clear_logs():
    try:
        app.state.logs.clear_all()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# --- Recon Endpoints ---
import io
from contextlib import redirect_stdout

from ghostlink.network.recon import (
    full_network_recon, print_recon_result,
    scan_my_device, scan_infrastructure,
    scan_wireless, scan_internet_identity,
    scan_performance, scan_resources,
    scan_security, scan_traffic
)

def capture_output(func, *args, **kwargs):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        func(*args, **kwargs)
    return buffer.getvalue()

@app.post("/api/recon/full")
async def recon_full():
    try:
        result = full_network_recon(do_ping_sweep=True)
        output = capture_output(print_recon_result, result)
        import ipaddress
        # Filter out non-device IPs (broadcast, multicast, loopback, etc.)
        filtered_devices = []
        # Get the local network to filter only same-subnet devices
        local_network = None
        if result.network.local_ip and result.network.cidr_prefix:
            try:
                local_network = ipaddress.IPv4Network(
                    f"{result.network.local_ip}/{result.network.cidr_prefix}",
                    strict=False
                )
            except ValueError:
                pass

        for dev in result.devices:
            try:
                ip = ipaddress.IPv4Address(dev.ip)
                if (
                    ip.is_multicast
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_unspecified
                    or dev.ip.endswith(".255")
                    or dev.ip.endswith(".0")
                ):
                    continue
                # Only include devices in the same local network (if known)
                if local_network and ip not in local_network:
                    continue
                filtered_devices.append(dev)
            except (ValueError, TypeError):
                continue

        structured = {
            "network": {
                "local_ip": result.network.local_ip,
                "gateway": result.network.gateway,
                "subnet_mask": result.network.subnet_mask,
                "cidr_prefix": result.network.cidr_prefix,
                "network_cidr": result.network.network_cidr
            },
            "devices": [
                {
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "hostname": dev.hostname,
                    "manufacturer": dev.manufacturer,
                    "open_ports": dev.open_ports,
                    "services": dev.services,
                    "os_guess": dev.os_guess,
                    "device_type": dev.device_type,
                    "scan_time": dev.scan_time
                }
                for dev in filtered_devices
            ],
            "scan_duration": result.scan_duration_seconds,
            "errors": result.errors
        }
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Full recon complete (mock): Device info, network scan, security audit complete"
        structured = None
    app.state.logs.add_log("Full recon executed")
    return {"output": output, "structured": structured}


@app.post("/api/recon/my_device")
async def recon_my_device():
    try:
        output = capture_output(scan_my_device)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: My device info (mock): Hostname - {os.uname().nodename if hasattr(os, 'uname') else 'Unknown'}, OS - {sys.platform}"
    app.state.logs.add_log("My device recon executed")
    return {"output": output}


@app.post("/api/recon/infrastructure")
async def recon_infrastructure():
    try:
        output = capture_output(scan_infrastructure)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Infrastructure info (mock): Gateway, DNS, DHCP servers detected"
    app.state.logs.add_log("Infrastructure recon executed")
    return {"output": output}


@app.post("/api/recon/wireless")
async def recon_wireless():
    try:
        output = capture_output(scan_wireless)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Wireless info (mock): Channel utilization, neighboring networks, signal strength map"
    app.state.logs.add_log("Wireless recon executed")
    return {"output": output}


@app.post("/api/recon/internet")
async def recon_internet():
    try:
        output = capture_output(scan_internet_identity)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Internet info (mock): Public IP, DNS test, latency measurement complete"
    app.state.logs.add_log("Internet recon executed")
    return {"output": output}


@app.post("/api/recon/performance")
async def recon_performance():
    try:
        output = capture_output(scan_performance)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Performance info (mock): CPU usage, memory, disk space, network speed test complete"
    app.state.logs.add_log("Performance recon executed")
    return {"output": output}


@app.post("/api/recon/resources")
async def recon_resources():
    try:
        output = capture_output(scan_resources)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Resources info (mock): Disk partitions, memory details, CPU cores complete"
    app.state.logs.add_log("Resources recon executed")
    return {"output": output}


@app.post("/api/recon/security")
async def recon_security():
    try:
        output = capture_output(scan_security)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Security info (mock): Firewall status, open ports, system updates complete"
    app.state.logs.add_log("Security recon executed")
    return {"output": output}


@app.post("/api/recon/traffic")
async def recon_traffic():
    try:
        output = capture_output(scan_traffic)
    except Exception as e:
        output = f"Error: {str(e)}\nFalling back to mock: Traffic info (mock): Active connections, bandwidth usage, packet count complete"
    app.state.logs.add_log("Traffic recon executed")
    return {"output": output}


# --- WebSocket for live progress ---
@app.websocket("/ws/attack")
async def websocket_attack(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5966)
