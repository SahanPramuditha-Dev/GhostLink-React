"""
GHOSTLINK Wi-Fi Scanner
========================
Network scanning and detection.
"""

import re
from typing import List, Optional
from dataclasses import dataclass
import platform

from ..core.utils import run_cmd

@dataclass
class ScanResult:
    """Wi-Fi network scan result"""
    ssid: str
    bssid: str
    signal: int
    security: str
    hidden: bool
    interface: str
    channel: int = 0

class WiFiScanner:
    """Wi-Fi network scanner"""

    @staticmethod
    def list_interfaces() -> List[str]:
        """List available wireless interfaces."""
        try:
            if platform.system() == "Windows":
                res = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=10)
                if res.returncode != 0:
                    return []
                names = []
                for line in res.stdout.splitlines():
                    if line.strip().lower().startswith("name"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            name = parts[1].strip()
                            if name:
                                names.append(name)
                return sorted(set(names))
            if platform.system() == "Linux":
                res = run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE", "device"], timeout=10)
                if res.returncode != 0:
                    return []
                names = []
                for line in res.stdout.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1].strip().lower() == "wifi":
                        names.append(parts[0].strip())
                return sorted(set([n for n in names if n]))
        except Exception:
            return []
        return []
    
    @staticmethod
    def scan(interface: Optional[str] = None) -> List[ScanResult]:
        """Scan for available networks"""
        if platform.system() == "Windows":
            return WiFiScanner._scan_windows(interface)
        elif platform.system() == "Linux":
            return WiFiScanner._scan_linux(interface)
        else:
            print(f"[!] Unsupported platform: {platform.system()}")
            return []
    
    @staticmethod
    def _scan_windows(interface: Optional[str] = None) -> List[ScanResult]:
        """Windows network scanning"""
        # Primary attempt: mode=Bssid (detailed). If it fails, try a simpler 'show networks' as fallback.
        attempts = []
        def _run(cmd):
            res = run_cmd(cmd, timeout=15)
            attempts.append((cmd, res))
            return res

        base_cmd = ["netsh", "wlan", "show", "networks"]
        cmd = base_cmd + ["mode=Bssid"]
        if interface:
            # When passing via subprocess (no shell), no extra quoting is required
            cmd_with_interface = cmd + [f'interface={interface}']
            res = _run(cmd_with_interface)
        else:
            res = _run(cmd)

        # If initial attempt failed, try without mode (simpler output) and try alternative interface formatting
        if res.returncode != 0:
            alt_cmds = []
            if interface:
                alt_cmds.append(base_cmd + [f'interface={interface}'])
                alt_cmds.append(base_cmd + [f'interface="{interface}"'])
            alt_cmds.append(base_cmd)
            for c in alt_cmds:
                r = _run(c)
                if r.returncode == 0:
                    res = r
                    break

        if res.returncode != 0:
            # Collect some diagnostic info for the caller
            msgs = []
            for c, r in attempts:
                out = (r.stdout or "").strip()
                err = (r.stderr or "").strip()
                msgs.append(f"Command: {' '.join(c)}\nReturn: {r.returncode}\nStdout:\n{out}\nStderr:\n{err}\n")
            raise RuntimeError("Wi‑Fi scan failed. Attempts:\n\n" + "\n---\n".join(msgs))

        networks = []
        current: Optional[ScanResult] = None

        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                current = None
                continue

            # Detect a new SSID line
            if line.lower().startswith("ssid") and "bssid" not in line.lower():
                try:
                    ssid = line.split(":", 1)[1].strip()
                    if ssid:   # only add non-empty SSIDs
                        current = ScanResult(
                            ssid=ssid, bssid="", signal=0,
                            security="Unknown", hidden=False,
                            interface=interface or "Wi-Fi"
                        )
                        networks.append(current)
                except:
                    pass
            elif current:
                try:
                    if "signal" in line.lower():
                        match = re.search(r"(\d+)%?", line)
                        if match:
                            current.signal = int(match.group(1))
                    elif "authentication" in line.lower() or "security" in line.lower():
                        current.security = line.split(":", 1)[1].strip()
                    elif "bssid" in line.lower():
                        current.bssid = line.split(":", 1)[1].strip()
                    elif "channel" in line.lower():
                        match = re.search(r"(\d+)", line)
                        if match:
                            current.channel = int(match.group(1))
                    elif "radio type" in line.lower():
                        # not stored, but could be
                        pass
                except:
                    pass

        # Sort by signal strength descending
        return sorted(networks, key=lambda x: x.signal, reverse=True)
    
    @staticmethod
    def _scan_linux(interface: Optional[str] = None) -> List[ScanResult]:
        """Linux network scanning"""
        if not interface:
            interface = WiFiScanner._get_interface_linux()
        
        cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY",
               "device", "wifi", "list"]
        res = run_cmd(cmd, timeout=15)
        
        if res.returncode != 0:
            return []
        
        networks = []
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                networks.append(ScanResult(
                    ssid=parts[0] or "<hidden>",
                    bssid=parts[1],
                    signal=int(parts[2]) if parts[2] else 0,
                    security=parts[3] or "Unknown",
                    hidden=(parts[0] == ""),
                    interface=interface,
                ))
        
        return sorted(networks, key=lambda x: x.signal, reverse=True)
    
    @staticmethod
    def _get_interface_linux() -> str:
        """Get default wireless interface on Linux"""
        res = run_cmd(["iw", "dev"], timeout=5)
        match = re.search(r'Interface (\w+)', res.stdout)
        return match.group(1) if match else "wlan0"
    
    @staticmethod
    def display(networks: List[ScanResult], vault=None) -> None:
        """Display scan results"""
        if not networks:
            print("\n[!] No networks found")
            return
        
        print(f"\n[+] Found {len(networks)} networks:\n")
        print(f"  {'#':<4} {'SSID':<30} {'Signal':<15} {'Security':<12}")
        print(f"  {'─'*4} {'─'*30} {'─'*15} {'─'*12}")
        
        for i, net in enumerate(networks, 1):
            bars = "█" * (net.signal // 10) + "░" * (10 - net.signal // 10)
            cached = " 📦" if vault and vault.get(net.ssid) else ""
            hidden = " 👻" if net.hidden else ""
            
            print(f"  {i:<4} {net.ssid:<30} {bars} {net.signal:>3}%  "
                  f"{net.security:<12}{cached}{hidden}")
