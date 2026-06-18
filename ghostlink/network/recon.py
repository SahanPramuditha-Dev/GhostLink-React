"""
GHOSTLINK Network Reconnaissance Module  v3
============================================
Comprehensive network intelligence tool with 10 scan categories:

  1.  Full Network Recon          — subnet sweep, ARP, port scan, banners
  2.  My Device — Deep Info       — interfaces, IPv4/IPv6, DHCP, DNS,
                                    routing table, active connections, profiles
  3.  Network Infrastructure      — gateway probe, DHCP range, NAT, traceroute,
                                    router admin detection
  4.  Wireless Analysis           — SSID, BSSID, channel congestion, signal
                                    quality, nearby networks, interference map
  5.  Internet & External ID      — public IP, ISP, geolocation, DNS path
  6.  Performance & Stability     — latency, jitter, packet-loss, path MTU,
                                    pathping-style analysis
  7.  Network Resources & Sharing — SMB shares, printers, NAS, mDNS services,
                                    media streaming devices
  8.  Security Insights           — weak crypto, risky ports, rogue APs,
                                    unknown devices, firewall status,
                                    failed-connection monitoring
  9.  Traffic Analysis            — live DNS queries, protocol breakdown,
                                    Wireshark guidance, connection stats
  0.  Exit
"""

# ──────────────────────────────────────────────────────────────────────────────
# Standard library imports
# ──────────────────────────────────────────────────────────────────────────────
import collections
import ipaddress
import json
import logging
import platform
import re
import socket
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# ANSI colour palette
# ──────────────────────────────────────────────────────────────────────────────
class _C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    MAG    = "\033[95m"
    WHITE  = "\033[97m"
    ORANGE = "\033[38;5;208m"

C = _C()

# ──────────────────────────────────────────────────────────────────────────────
# Defaults / constants
# ──────────────────────────────────────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
]
RISKY_PORTS = {
    21:   "FTP (unencrypted)",
    23:   "Telnet (plaintext)",
    80:   "HTTP (unencrypted)",
    110:  "POP3 (unencrypted)",
    135:  "RPC / MSRPC",
    139:  "NetBIOS",
    445:  "SMB (EternalBlue target)",
    993:  "IMAP SSL",
    1723: "PPTP VPN (weak cipher)",
    3306: "MySQL (exposed DB)",
    3389: "RDP (brute-force target)",
    5432: "PostgreSQL (exposed DB)",
    5900: "VNC (often unencrypted)",
}

# Protocol port map for traffic analysis
PROTOCOL_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 194: "IRC", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    515: "LPD", 587: "SMTP-Sub", 631: "CUPS/IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9100: "JetDirect",
    27017: "MongoDB",
}

DEFAULT_PORT_TIMEOUT   = 1.5
DEFAULT_BANNER_TIMEOUT = 2.0
DEFAULT_PING_TIMEOUT   = 1
MAX_BANNER_BYTES       = 256
SYSNAME = platform.system()


# ──────────────────────────────────────────────────────────────────────────────
# OUI vendor table (first 3 MAC octets)
# ──────────────────────────────────────────────────────────────────────────────
_OUI_TABLE: Dict[str, str] = {
    "00:50:56": "VMware",      "00:0c:29": "VMware",
    "00:1a:11": "Google",      "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi","e4:5f:01": "Raspberry Pi",
    "00:17:88": "Philips Hue", "18:b4:30": "Nest Labs",
    "44:65:0d": "Amazon",      "fc:65:de": "Amazon Echo",
    "ac:63:be": "Apple",       "f0:18:98": "Apple",
    "3c:22:fb": "Apple",       "00:1b:63": "Apple",
    "28:cd:c1": "Apple",       "b8:8d:12": "Samsung",
    "a0:b4:a5": "Samsung",     "00:1d:09": "Dell",
    "00:14:22": "Dell",        "00:22:19": "Dell",
    "00:1b:21": "Intel",       "00:21:6a": "Intel",
    "8c:8d:28": "Intel",       "00:50:ba": "D-Link",
    "00:1c:f0": "D-Link",      "00:18:e7": "Netgear",
    "20:4e:7f": "Netgear",     "c0:ff:d4": "Netgear",
    "00:13:46": "TP-Link",     "54:af:97": "TP-Link",
    "b0:be:76": "TP-Link",     "00:1f:33": "Cisco",
    "00:0f:23": "Cisco",       "00:16:46": "Cisco",
    "74:d4:35": "Asus",        "04:d4:c4": "Asus",
    "00:25:9c": "Cisco-Linksys","c8:3a:35": "Tenda",
    "50:c7:bf": "TP-Link",     "ec:08:6b": "TP-Link",
    "f4:f2:6d": "Apple",       "a4:c3:f0": "Apple",
    "00:03:93": "Apple",       "00:05:02": "Apple",
    "00:0a:27": "Apple",       "00:0a:95": "Apple",
    "00:11:24": "Apple",       "00:14:51": "Apple",
    "b0:34:95": "Apple",       "d8:bb:2c": "Apple",
    "18:74:2e": "Huawei",      "30:3a:3e": "Xiaomi",
    "34:ab:37": "OnePlus",     "58:cb:52": "LG",
    "38:f9:d3": "Motorola",    "40:55:82": "Sony Mobile",
    "00:1e:4a": "Nokia",       "00:18:3a": "HP",
    "00:1d:92": "Lenovo",      "00:1e:8c": "Acer",
    "30:85:a9": "MSI",         "d8:5d:e4": "Gigabyte",
    "00:16:76": "Intel",       "f8:1a:67": "Intel",
    "d4:3b:04": "Intel",       "00:1b:fc": "Intel",
    "00:1c:42": "VMware",      "00:50:56": "VMware",
    "00:0c:29": "VMware",      "00:17:c4": "Broadcom",
    "00:10:18": "Realtek",     "00:e0:4c": "Realtek",
    "50:eb:71": "Arris",       "00:1d:aa": "Netgear",
    "68:7f:74": "Ubiquiti",    "44:d9:e7": "Ubiquiti",
    "00:15:6d": "Mikrotik",    "00:0c:42": "Cisco",
    "00:0a:41": "Linksys",     "00:0d:3a": "Amazon",
    "ac:de:48": "Amazon Echo", "18:59:36": "Nest Labs",
    "00:24:e4": "Philips",     "00:1b:63": "Apple",
    "00:1e:52": "Apple",       "00:21:e9": "Apple",
    "00:23:12": "Apple",       "00:25:00": "Apple",
    "00:26:bb": "Apple",       "00:26:b0": "Apple",
    "00:27:10": "Apple",       "00:30:65": "Apple",
    "00:37:37": "Apple",       "00:3e:e1": "Apple",
    "00:40:96": "Apple",       "00:50:fc": "Apple",
    "00:60:57": "Apple",       "00:6d:52": "Apple",
    "00:71:47": "Apple",       "00:7f:28": "Apple",
    "00:80:0f": "Apple",       "00:88:65": "Apple",
    "00:90:33": "Apple",       "00:a0:c9": "Apple",
    "00:c0:4f": "Apple",       "00:d0:59": "Apple",
    "00:e0:4c": "Realtek",     "70:85:c2": "Samsung",
    "74:23:44": "Samsung",     "78:ca:39": "Samsung",
    "8c:77:12": "Samsung",     "94:10:3c": "Samsung",
    "98:01:a7": "Samsung",     "a0:48:1c": "Samsung",
    "a4:08:ea": "Samsung",     "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi","e4:5f:01": "Raspberry Pi",
    "e8:4e:06": "Raspberry Pi","2c:f0:a2": "Arduino",
    "84:cc:a8": "Arduino",     "00:23:a9": "Espressif",
    "24:0a:c4": "Espressif",   "24:6f:28": "Espressif",
    "30:ae:a4": "Espressif",   "58:cf:79": "Espressif",
    "60:01:94": "Espressif",   "84:f3:eb": "Espressif",
    "ac:0b:fb": "Espressif",   "c4:4f:33": "Espressif",
    "d8:bf:c0": "Espressif",   "e0:98:06": "Espressif",
    "f8:f0:05": "Espressif",   "00:1d:09": "Dell",
    "00:14:22": "Dell",        "00:22:19": "Dell",
    "00:0e:0c": "Dell",        "00:1c:23": "Dell",
    "00:21:70": "Dell",        "00:24:e8": "Dell",
    "00:26:b9": "Dell",        "00:27:0e": "Dell",
    "00:19:99": "HP",          "00:21:5a": "HP",
    "00:23:7d": "HP",          "00:24:81": "HP",
    "00:25:b3": "HP",          "00:26:bb": "HP",
    "00:1e:67": "Lenovo",      "00:21:6a": "Lenovo",
    "00:23:8b": "Lenovo",      "00:24:54": "Lenovo",
    "00:26:c7": "Lenovo",      "00:17:9a": "Asus",
    "00:1e:8c": "Acer",        "00:19:db": "Acer",
    "00:22:15": "Acer",        "00:24:1d": "Acer",
    "00:26:2d": "Acer",        "60:eb:69": "MSI",
    "40:2c:f4": "Gigabyte",    "00:13:46": "TP-Link",
    "50:c7:bf": "TP-Link",     "b0:be:76": "TP-Link",
    "c0:4a:00": "TP-Link",     "d4:6e:0e": "TP-Link",
    "e0:05:c5": "TP-Link",     "ec:08:6b": "TP-Link",
    "f8:1a:67": "TP-Link",     "00:0c:42": "Cisco",
    "00:0f:23": "Cisco",       "00:16:47": "Cisco",
    "00:1a:a1": "Cisco",       "00:1d:70": "Cisco",
    "00:23:33": "Cisco",       "00:25:84": "Cisco",
    "00:0d:3a": "Amazon",      "ac:de:48": "Amazon Echo",
    "00:17:88": "Philips Hue", "18:b4:30": "Nest Labs",
    "18:59:36": "Nest Labs",   "00:1e:4a": "Nokia",
    "58:cb:52": "LG",          "70:85:c2": "Samsung",
}

# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class InterfaceInfo:
    name: str
    ipv4: str = ""
    ipv4_prefix: int = 24
    ipv6: List[str] = field(default_factory=list)
    mac: str = ""
    state: str = ""
    type: str = ""
    dhcp: bool = False
    dhcp_server: str = ""
    dhcp_lease_obtained: str = ""
    dhcp_lease_expires: str = ""
    dns_servers: List[str] = field(default_factory=list)
    dns_suffix: str = ""
    profile: str = ""           # Public / Private / Domain
    speed: str = ""             # Link speed
    mtu: str = ""

@dataclass
class DeviceInfo:
    ip: str
    mac: str = ""
    hostname: str = ""
    manufacturer: str = "Unknown"
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    os_guess: str = ""
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    device_type: str = "Unknown"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

@dataclass
class NetworkInfo:
    local_ip: str = ""
    gateway: str = ""
    subnet_mask: str = ""
    interface: str = ""
    cidr_prefix: int = 24

    @property
    def network_cidr(self) -> Optional[str]:
        if self.local_ip and self.cidr_prefix:
            try:
                net = ipaddress.IPv4Network(
                    f"{self.local_ip}/{self.cidr_prefix}", strict=False)
                return str(net)
            except ValueError:
                return None
        return None

@dataclass
class ReconResult:
    network: NetworkInfo
    devices: List[DeviceInfo]
    scan_duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

@dataclass
class WirelessNetwork:
    ssid: str = ""
    bssid: str = ""
    channel: str = ""
    band: str = ""
    signal: str = ""
    security: str = ""
    authentication: str = ""
    encryption: str = ""
    connected: bool = False
    signal_dbm: int = -100
    frequency: str = ""

@dataclass
class PingStats:
    host: str
    sent: int = 0
    received: int = 0
    min_ms: float = 0.0
    max_ms: float = 0.0
    avg_ms: float = 0.0
    jitter_ms: float = 0.0
    packet_loss_pct: float = 0.0

@dataclass
class ConnectionEntry:
    protocol: str = ""
    local_addr: str = ""
    local_port: str = ""
    remote_addr: str = ""
    remote_port: str = ""
    state: str = ""
    pid: str = ""
    process: str = ""

# ──────────────────────────────────────────────────────────────────────────────
# Subprocess / utility helpers
# ──────────────────────────────────────────────────────────────────────────────
def _run(cmd: List[str], timeout: int = 20,
         log_errors: bool = True) -> Optional[subprocess.CompletedProcess]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and log_errors and r.stderr:
            logger.debug("CMD %s stderr: %s", cmd, r.stderr.strip())
        return r
    except FileNotFoundError:
        logger.debug("Not found: %s", cmd[0]); return None
    except subprocess.TimeoutExpired:
        logger.debug("Timeout: %s", cmd); return None
    except Exception as exc:
        logger.debug("CMD %s raised: %s", cmd, exc); return None

def _tool(name: str) -> bool:
    return _run([name, "--version"], timeout=3, log_errors=False) is not None

def _tool_exists(name: str) -> bool:
    """Check if a tool is available via 'which' or 'where'."""
    cmd = ["where", name] if SYSNAME == "Windows" else ["which", name]
    r = _run(cmd, timeout=3, log_errors=False)
    return r is not None and r.returncode == 0

def _http_get(url: str, timeout: int = 8) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GHOSTLINK/3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None

def _sep(char: str = "─", width: int = 66) -> str:
    return f"{C.CYAN}{char * width}{C.RESET}"

def _hdr(title: str) -> None:
    print(f"\n{_sep('═')}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(_sep('═'))

def _section(title: str, idx: str = "") -> None:
    prefix = f"[{idx}] " if idx else ""
    print(f"\n{C.BOLD}{prefix}{title}{C.RESET}")
    print(_sep("─", 66))

def _row(label: str, value: str, color: str = "") -> None:
    val_str = f"{color}{value}{C.RESET}" if color else value
    print(f"  {C.BOLD}{label:<30}{C.RESET}{val_str}")

def _bullet(text: str, color: str = "") -> None:
    col = color or C.DIM
    print(f"  {col}• {text}{C.RESET}")

def _ok(text: str) -> None:
    print(f"  {C.GREEN}✓  {text}{C.RESET}")

def _warn(text: str) -> None:
    print(f"  {C.YELLOW}⚠  {text}{C.RESET}")

def _err(text: str) -> None:
    print(f"  {C.RED}✗  {text}{C.RESET}")

# ──────────────────────────────────────────────────────────────────────────────
# Network detection helpers
# ──────────────────────────────────────────────────────────────────────────────
def _detect_iface_linux() -> Tuple[str, str]:
    r = _run(["ip", "route", "get", "8.8.8.8"])
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            p = line.split()
            if "dev" in p and "src" in p:
                try:
                    return p[p.index("dev")+1], p[p.index("src")+1]
                except (ValueError, IndexError):
                    pass
    return "wlan0", ""

def get_local_network() -> NetworkInfo:
    return _net_windows() if SYSNAME == "Windows" else _net_linux()

def _net_linux() -> NetworkInfo:
    info = NetworkInfo()
    iface, _ = _detect_iface_linux()
    info.interface = iface
    r = _run(["ip", "-4", "addr", "show", iface])
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            if "inet " in line:
                p = line.strip().split(); cidr = p[1]
                info.local_ip = cidr.split("/")[0]
                info.cidr_prefix = int(cidr.split("/")[1])
                bits = (0xFFFFFFFF << (32 - info.cidr_prefix)) & 0xFFFFFFFF
                info.subnet_mask = ".".join(
                    str((bits >> (8*i)) & 0xFF) for i in reversed(range(4)))
                break
    r2 = _run(["ip", "route", "show", "default"])
    if r2 and r2.returncode == 0:
        for line in r2.stdout.splitlines():
            if "default via" in line:
                info.gateway = line.split()[2]; break
    return info

def _net_windows() -> NetworkInfo:
    info = NetworkInfo()
    r = _run(["route", "print", "0.0.0.0"])
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            p = line.split()
            if p and p[0] == "0.0.0.0" and len(p) >= 5:
                info.gateway = p[2]; info.local_ip = p[3]; break
    if not info.local_ip:
        for adapter in ("Wi-Fi", "Ethernet", "Local Area Connection"):
            r2 = _run(["netsh", "interface", "ip", "show", "addresses", adapter])
            if not r2 or r2.returncode != 0: continue
            for line in r2.stdout.splitlines():
                if "IP Address:" in line and "169.254" not in line:
                    info.local_ip = line.split(":")[-1].strip()
                    info.interface = adapter
                if "Subnet Prefix:" in line and "255" in line:
                    try:
                        info.cidr_prefix = int(line.split(":")[-1].strip().split("/")[-1])
                    except ValueError:
                        info.cidr_prefix = 24
                if not info.gateway and "Default Gateway:" in line:
                    gw = line.split(":")[-1].strip()
                    if gw: info.gateway = gw
            if info.local_ip: break
    if info.cidr_prefix:
        bits = (0xFFFFFFFF << (32 - info.cidr_prefix)) & 0xFFFFFFFF
        info.subnet_mask = ".".join(
            str((bits >> (8*i)) & 0xFF) for i in reversed(range(4)))
    return info

def get_manufacturer(mac: str) -> str:
    if not mac or mac in ("<incomplete>", "?", ""): return "Unknown"
    norm = mac.lower().replace("-", ":").strip()
    return _OUI_TABLE.get(":".join(norm.split(":")[:3]), "Unknown")

def ping_host(ip: str, timeout: int = DEFAULT_PING_TIMEOUT) -> bool:
    cmd = (["ping", "-n", "1", "-w", str(timeout*1000), ip]
           if SYSNAME == "Windows" else
           ["ping", "-c", "1", "-W", str(timeout), ip])
    r = _run(cmd, timeout=timeout+2, log_errors=False)
    return r is not None and r.returncode == 0

def ping_sweep(cidr: str, workers: int = 64,
               timeout: int = DEFAULT_PING_TIMEOUT) -> List[str]:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return []
    hosts = [str(h) for h in net.hosts()]
    alive: List[str] = []
    lock = threading.Lock()
    def _chk(ip):
        if ping_host(ip, timeout):
            with lock: alive.append(ip)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_chk, hosts))
    return sorted(alive, key=lambda x: ipaddress.IPv4Address(x))

def read_arp_table() -> Dict[str, str]:
    return _arp_windows() if SYSNAME == "Windows" else _arp_linux()

def _arp_linux() -> Dict[str, str]:
    result: Dict[str, str] = {}
    r = _run(["ip", "neigh", "show"])
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            p = line.split()
            if len(p) >= 5 and "lladdr" in p:
                ip = p[0]; mac = p[p.index("lladdr")+1]
                state = p[-1].upper()
                if state not in ("FAILED", "INCOMPLETE") and mac:
                    result[ip] = mac
        return result
    r2 = _run(["arp", "-a"])
    if r2:
        for line in r2.stdout.splitlines():
            if "(" in line and ")" in line:
                p = line.split()
                ip = p[1].strip("()")
                mac = p[3] if len(p) >= 4 else ""
                if mac and mac != "<incomplete>":
                    result[ip] = mac
    return result

def _arp_windows() -> Dict[str, str]:
    result: Dict[str, str] = {}
    r = _run(["arp", "-a"])
    if not r: return result
    for line in r.stdout.splitlines():
        if "." in line and ("dynamic" in line.lower() or "static" in line.lower()):
            p = line.split()
            if len(p) >= 2:
                result[p[0]] = p[1].replace("-", ":")
    return result

def resolve_hostname(ip: str, timeout: float = 2.0) -> str:
    old = socket.getdefaulttimeout(); socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)

def _scan_port(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0

def port_scan(ip: str, ports: List[int] = COMMON_PORTS,
              timeout: float = DEFAULT_PORT_TIMEOUT,
              workers: int = 50) -> List[int]:
    open_ports: List[int] = []
    lock = threading.Lock()
    def _chk(p):
        if _scan_port(ip, p, timeout):
            with lock: open_ports.append(p)
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        list(pool.map(_chk, ports))
    return sorted(open_ports)

def _svc_name(port: int, proto: str = "tcp") -> str:
    if port in PROTOCOL_PORTS:
        return PROTOCOL_PORTS[port]
    try: return socket.getservbyport(port, proto)
    except OSError: return f"port-{port}"

def grab_banner(ip: str, port: int,
                timeout: float = DEFAULT_BANNER_TIMEOUT) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout); s.connect((ip, port))
            if port in (80, 8080, 8443, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                return s.recv(MAX_BANNER_BYTES).decode("utf-8", errors="ignore").strip()[:120]
            except (socket.timeout, OSError): return ""
    except (ConnectionRefusedError, OSError): return ""

def get_service_info(ip: str, port: int) -> str:
    name = _svc_name(port)
    banner = grab_banner(ip, port)
    if banner:
        return f"{name} ({banner.splitlines()[0][:80]})"
    return name

def _guess_device_type(manufacturer: str, open_ports: List[int],
                        hostname: str) -> str:
    mfr = manufacturer.lower() if manufacturer else ""
    host = hostname.lower() if hostname else ""
    
    # --- Network Equipment/Router Detection ---
    # Gateway IP (common ones: .1, .254)
    if host.endswith(".1") or host.endswith(".254") or "router" in host or "gateway" in host or "modem" in host or "gpon" in host:
        return "Network Equipment"
    # Common router ports: DNS(53), HTTP(80), HTTPS(443) often together
    if 53 in open_ports and (80 in open_ports or 443 in open_ports):
        return "Network Equipment"
    
    # --- Locally Administered MAC Address (often mobile/virtual) ---
    # First two bytes: 02, 06, 0A, 0E, 22, 26, 2A, 2E, 32, 36, 3A, 3E, etc.
    # First byte second least significant bit is 1 (locally administered)
    # Check if manufacturer is Unknown and open ports are mostly email ports (common for some mobile devices)
    email_ports = [25, 110, 143, 465, 587, 993, 995]
    common_alt_ports = [8443, 8080, 8000, 8444]  # Common alternative web ports that might be on mobile devices
    
    # Count how many ports are NOT email or common alt ports
    non_email_port_count = sum(1 for p in open_ports if p not in email_ports and p not in common_alt_ports)
    
    if mfr == "unknown" and non_email_port_count == 0:
        return "Mobile / Tablet"
    
    # --- Mobile/Tablet Detection ---
    if any(x in mfr for x in ("apple", "samsung", "huawei", "xiaomi", "oneplus", "google", "lg", "motorola", "nokia", "sony mobile")):
        if 5900 not in open_ports and 3389 not in open_ports:
            return "Mobile / Tablet"
    if any(x in host for x in ("iphone", "ipad", "android", "pixel", "galaxy", "samsung", "huawei", "xiaomi", "oneplus", "motorola")):
        return "Mobile / Tablet"
    
    # --- Computer Detection ---
    if any(x in host for x in ("desktop", "laptop", "pc", "workstation", "macbook", "imac", "macmini")):
        return "Computer"
    if any(x in mfr for x in ("intel", "amd", "dell", "hp", "lenovo", "asus", "acer", "msi", "gigabyte")):
        return "Computer"
    if 3389 in open_ports:  # RDP
        return "Windows Computer"
    if 22 in open_ports:  # SSH
        return "Linux / Unix Host"
    # If multiple common OS ports are open
    if (135 in open_ports or 139 in open_ports or 445 in open_ports) and 3389 not in open_ports:
        return "Computer"
    
    # --- Embedded/IoT ---
    if any(x in mfr for x in ("raspberry", "arduino", "espressif", "tuya", "smartthings", "ring", "nest", "amazon echo", "alexa", "google home", "philips hue", "wemo")):
        return "Smart Home / IoT"
    
    # --- Network Equipment ---
    if any(x in mfr for x in ("cisco", "netgear", "tp-link", "d-link", "asus", "ubiquiti", "mikrotik", "aruba", "juniper", "linksys", "belkin")):
        return "Network Equipment"
    
    # --- Printer Detection ---
    if 9100 in open_ports or 515 in open_ports or 631 in open_ports:
        return "Printer"
    if any(x in mfr for x in ("hp", "epson", "canon", "brother", "xerox", "lexmark", "samsung printer")):
        return "Printer"
    
    # --- Server/NAS Detection ---
    if 445 in open_ports:  # SMB
        return "Server / NAS"
    if (80 in open_ports or 443 in open_ports) and (21 in open_ports or 22 in open_ports):
        return "Server / NAS"
    if any(x in mfr for x in ("synology", "qnap", "western digital", "seagate", "buffalo")):
        return "Server / NAS"
    
    # --- Email Server Detection (only if other server ports present) ---
    email_port_count = sum(1 for p in open_ports if p in email_ports)
    if email_port_count >= 2 and non_email_port_count > 0:
        return "Server / NAS"
    
    # --- Fallback: If we have open ports, guess something ---
    if open_ports:
        # If it has web ports and other service ports
        if 80 in open_ports or 443 in open_ports:
            return "Server / NAS"
        # If it has just a few common ports, maybe IoT
        if len(open_ports) <= 3:
            return "Smart Home / IoT"
    
    return "Unknown"

def scan_device(ip: str, mac: str = "",
                ports: List[int] = COMMON_PORTS,
                port_timeout: float = DEFAULT_PORT_TIMEOUT,
                grab_banners: bool = True,
                use_nmap: bool = False) -> DeviceInfo:
    dev = DeviceInfo(ip=ip, mac=mac)
    if mac: dev.manufacturer = get_manufacturer(mac)
    dev.hostname = resolve_hostname(ip)
    dev.open_ports = port_scan(ip, ports=ports, timeout=port_timeout)
    if dev.open_ports:
        if grab_banners:
            with ThreadPoolExecutor(max_workers=10) as pool:
                futs = {pool.submit(get_service_info, ip, p): p
                        for p in dev.open_ports}
                for fut in as_completed(futs):
                    p = futs[fut]
                    try: dev.services[p] = fut.result()
                    except Exception: dev.services[p] = _svc_name(p)
        else:
            for p in dev.open_ports: dev.services[p] = _svc_name(p)
    dev.device_type = _guess_device_type(dev.manufacturer,
                                          dev.open_ports, dev.hostname)
    if use_nmap and _tool("nmap"):
        r = _run(["nmap", "-O", "--osscan-guess", ip], timeout=60)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                if "OS details:" in line or "Aggressive OS guesses:" in line:
                    dev.os_guess = line.split(":", 1)[-1].strip(); break
    return dev

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 1 — Full Network Recon
# ──────────────────────────────────────────────────────────────────────────────
def full_network_recon(ports=COMMON_PORTS, port_timeout=DEFAULT_PORT_TIMEOUT,
                        max_device_workers=20, device_scan_limit=50,
                        grab_banners=True, use_nmap=False,
                        do_ping_sweep=True) -> ReconResult:
    start = time.time(); errors: List[str] = []
    net_info = get_local_network()
    if do_ping_sweep and net_info.network_cidr:
        ping_sweep(net_info.network_cidr)
    arp = read_arp_table()
    if not arp:
        errors.append("ARP table empty — ping sweep may have been blocked.")
    
    # Filter IPs to only include those in the main local network
    local_network = None
    if net_info.local_ip and net_info.cidr_prefix:
        try:
            local_network = ipaddress.IPv4Network(
                f"{net_info.local_ip}/{net_info.cidr_prefix}", strict=False)
        except ValueError:
            pass
    
    filtered_ips = []
    for ip in arp.keys():
        try:
            ip_addr = ipaddress.IPv4Address(ip)
            # Skip non-device IPs
            if (ip_addr.is_multicast or 
                ip_addr.is_loopback or 
                ip_addr.is_link_local or 
                ip_addr.is_unspecified or
                ip.endswith(".0") or 
                ip.endswith(".255")):
                continue
            # Only include IPs in the main local network
            if local_network and ip_addr not in local_network:
                continue
            filtered_ips.append(ip)
        except (ValueError, TypeError):
            continue
    
    ips = sorted(filtered_ips, key=lambda x: ipaddress.IPv4Address(x))[:device_scan_limit]
    devices: List[DeviceInfo] = []
    lock = threading.Lock()
    def _scan(ip):
        try:
            d = scan_device(ip, arp.get(ip, ""), ports, port_timeout, grab_banners, use_nmap)
            with lock: devices.append(d)
        except Exception as exc:
            with lock:
                errors.append(f"Failed {ip}: {exc}")
                devices.append(DeviceInfo(ip=ip, mac=arp.get(ip, "")))
    with ThreadPoolExecutor(max_workers=max_device_workers) as pool:
        pool.map(_scan, ips)
    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return ReconResult(network=net_info, devices=devices,
                       scan_duration_seconds=round(time.time()-start, 2),
                       errors=errors)

def print_recon_result(result: ReconResult) -> None:
    _hdr("GHOSTLINK — Full Network Recon")
    n = result.network
    _row("Interface",   n.interface or "unknown")
    _row("IP Address",  n.local_ip or "Unknown")
    _row("Gateway",     n.gateway  or "Unknown")
    _row("Subnet Mask", n.subnet_mask or "Unknown")
    _row("CIDR Block",  n.network_cidr or "Unknown")
    print()
    print(f"{C.BOLD}[+] Discovered Devices{C.RESET}  ({len(result.devices)} total)\n")

    # Summary by device type
    type_counts: Dict[str, int] = {}
    for dev in result.devices:
        type_counts[dev.device_type] = type_counts.get(dev.device_type, 0) + 1
    if type_counts:
        print(f"  {C.DIM}Device Types: " +
              "  ".join(f"{k}: {v}" for k, v in sorted(type_counts.items())) +
              f"{C.RESET}\n")

    for dev in result.devices:
        hn = f"  {C.DIM}{dev.hostname}{C.RESET}" if dev.hostname else ""
        mfr = f"  [{dev.manufacturer}]" if dev.manufacturer != "Unknown" else ""
        dtype = f"  {C.BLUE}〈{dev.device_type}〉{C.RESET}"
        print(f"  {C.BOLD}{dev.ip:<16}{C.RESET}{dev.mac:<18}{mfr}{hn}{dtype}")
        for p in dev.open_ports:
            svc = dev.services.get(p, _svc_name(p))
            flag = f"  {C.RED}⚠ RISKY{C.RESET}" if p in RISKY_PORTS else ""
            print(f"    {C.GREEN}→ {p:<6}{C.RESET}{svc}{flag}")
        if dev.os_guess:
            print(f"    {C.YELLOW}OS:{C.RESET} {dev.os_guess}")
        print()
    if result.errors:
        print(_sep()); print(f"{C.YELLOW}[!] Warnings:{C.RESET}")
        for e in result.errors: print(f"    {C.RED}•{C.RESET} {e}")
    print(_sep())
    print(f"{C.GREEN}[✓] Scan complete{C.RESET}  "
          f"{len(result.devices)} device(s)  "
          f"({result.scan_duration_seconds}s)")

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 2 — My Device Deep Info  (ENHANCED)
# ──────────────────────────────────────────────────────────────────────────────
def _get_all_interfaces_linux() -> List[InterfaceInfo]:
    interfaces: List[InterfaceInfo] = []
    r = _run(["ip", "-j", "addr"])
    if r and r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            for iface_data in data:
                iface = InterfaceInfo(name=iface_data.get("ifname", ""))
                iface.state = iface_data.get("operstate", "")
                iface.mac = iface_data.get("address", "")
                iface.mtu = str(iface_data.get("mtu", ""))
                flags = iface_data.get("flags", [])
                if "LOOPBACK" in flags:
                    iface.type = "Loopback"
                elif iface.name.startswith(("wlan", "wlp", "wifi")):
                    iface.type = "Wi-Fi"
                elif iface.name.startswith(("eth", "enp", "eno", "ens")):
                    iface.type = "Ethernet"
                elif iface.name.startswith(("tun", "tap", "vpn", "virbr", "docker")):
                    iface.type = "Virtual / VPN"
                else:
                    iface.type = "Unknown"
                for addr_info in iface_data.get("addr_info", []):
                    family = addr_info.get("family", "")
                    addr   = addr_info.get("local", "")
                    if family == "inet" and not iface.ipv4:
                        iface.ipv4 = addr
                        iface.ipv4_prefix = addr_info.get("prefixlen", 24)
                    elif family == "inet6":
                        scope = addr_info.get("scope", "")
                        iface.ipv6.append(f"{addr}/{addr_info.get('prefixlen',64)} ({scope})")
                interfaces.append(iface)
        except (json.JSONDecodeError, KeyError):
            pass
    # DNS via /etc/resolv.conf
    try:
        with open("/etc/resolv.conf") as f:
            dns_servers: List[str] = []
            dns_search: str = ""
            for line in f:
                if line.startswith("nameserver"):
                    dns_servers.append(line.split()[1])
                elif line.startswith("search") or line.startswith("domain"):
                    dns_search = " ".join(line.split()[1:])
            for iface in interfaces:
                if iface.type not in ("Loopback",) and iface.ipv4:
                    iface.dns_servers = dns_servers
                    iface.dns_suffix = dns_search
    except FileNotFoundError:
        pass
    # Get ethtool speed for ethernet
    for iface in interfaces:
        if iface.type == "Ethernet":
            r_e = _run(["ethtool", iface.name], timeout=5, log_errors=False)
            if r_e and r_e.returncode == 0:
                for line in r_e.stdout.splitlines():
                    if "Speed:" in line:
                        iface.speed = line.strip().split(":", 1)[-1].strip()
    return interfaces

def _get_all_interfaces_windows() -> List[InterfaceInfo]:
    interfaces: List[InterfaceInfo] = []
    r = _run(["ipconfig", "/all"], timeout=15)
    if not r or r.returncode != 0: return interfaces
    current: Optional[InterfaceInfo] = None
    for line in r.stdout.splitlines():
        if line and not line.startswith(" ") and "adapter" in line.lower():
            if current and current.ipv4: interfaces.append(current)
            name = line.strip().rstrip(":").replace("Wireless LAN adapter ", "").replace("Ethernet adapter ", "")
            current = InterfaceInfo(name=name)
            if "wireless" in line.lower() or "wi-fi" in line.lower():
                current.type = "Wi-Fi"
            elif "ethernet" in line.lower():
                current.type = "Ethernet"
            elif "loopback" in line.lower():
                current.type = "Loopback"
            else:
                current.type = "Virtual / VPN"
            continue
        if current is None: continue
        l = line.strip()
        if "Physical Address" in l:      current.mac = l.split(":")[-1].strip().replace("-", ":")
        elif "IPv4 Address" in l and "169.254" not in l:
            current.ipv4 = l.split(":")[-1].strip().rstrip("(Preferred)").strip()
        elif "IPv6 Address" in l:        current.ipv6.append(l.split(":", 1)[-1].strip())
        elif "Subnet Mask" in l:
            mask = l.split(":")[-1].strip()
            try:
                prefix = bin(int(ipaddress.IPv4Address(mask))).count("1")
                current.ipv4_prefix = prefix
            except Exception: pass
        elif "DHCP Enabled" in l:        current.dhcp = "Yes" in l
        elif "DHCP Server" in l:         current.dhcp_server = l.split(":", 1)[-1].strip()
        elif "Lease Obtained" in l:      current.dhcp_lease_obtained = l.split(":", 1)[-1].strip()
        elif "Lease Expires" in l:       current.dhcp_lease_expires = l.split(":", 1)[-1].strip()
        elif "DNS Servers" in l:
            dns = l.split(":", 1)[-1].strip()
            if dns: current.dns_servers.append(dns)
        elif "DNS Suffix" in l:          current.dns_suffix = l.split(":", 1)[-1].strip()
        elif "Media State" in l:         current.state = l.split(":", 1)[-1].strip()
    if current and current.ipv4: interfaces.append(current)

    # Get network profiles via netsh
    try:
        r_prof = _run(["netsh", "wlan", "show", "profiles"], timeout=8, log_errors=False)
        # Also try network profile from PowerShell
        r_ps = _run(["powershell", "-Command",
                      "Get-NetConnectionProfile | Select-Object Name,NetworkCategory | ConvertTo-Json"],
                     timeout=10, log_errors=False)
        if r_ps and r_ps.returncode == 0:
            try:
                profiles = json.loads(r_ps.stdout)
                if isinstance(profiles, dict): profiles = [profiles]
                for prof in profiles:
                    name = str(prof.get("Name", ""))
                    cat = str(prof.get("NetworkCategory", ""))
                    for iface in interfaces:
                        if name.lower() in iface.name.lower() or iface.name.lower() in name.lower():
                            iface.profile = cat
            except Exception:
                pass
    except Exception:
        pass
    return interfaces

def _get_active_connections_detailed() -> List[ConnectionEntry]:
    """Parse netstat/ss output into structured ConnectionEntry objects."""
    entries: List[ConnectionEntry] = []
    if SYSNAME == "Windows":
        r = _run(["netstat", "-ano"], timeout=15)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                p = line.split()
                if len(p) >= 4 and p[0] in ("TCP", "UDP"):
                    entry = ConnectionEntry(protocol=p[0])
                    la = p[1].rsplit(":", 1)
                    entry.local_addr = la[0] if len(la) > 0 else ""
                    entry.local_port = la[1] if len(la) > 1 else ""
                    if p[0] == "TCP" and len(p) >= 5:
                        ra = p[2].rsplit(":", 1)
                        entry.remote_addr = ra[0] if len(ra) > 0 else ""
                        entry.remote_port = ra[1] if len(ra) > 1 else ""
                        entry.state = p[3]
                        entry.pid = p[4] if len(p) > 4 else ""
                    entries.append(entry)
    else:
        r = _run(["ss", "-tnpH"], timeout=10)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                p = line.split()
                if len(p) >= 4:
                    entry = ConnectionEntry(protocol="TCP", state=p[0])
                    la = p[3].rsplit(":", 1)
                    entry.local_addr = la[0] if len(la) > 0 else ""
                    entry.local_port = la[1] if len(la) > 1 else ""
                    ra = p[4].rsplit(":", 1) if len(p) > 4 else ["", ""]
                    entry.remote_addr = ra[0] if len(ra) > 0 else ""
                    entry.remote_port = ra[1] if len(ra) > 1 else ""
                    if len(p) > 5:
                        proc_info = p[5]
                        pid_match = re.search(r'pid=(\d+)', proc_info)
                        name_match = re.search(r'"([^"]+)"', proc_info)
                        if pid_match: entry.pid = pid_match.group(1)
                        if name_match: entry.process = name_match.group(1)
                    entries.append(entry)
        if not entries:
            r2 = _run(["netstat", "-tnp"], timeout=10)
            if r2 and r2.returncode == 0:
                for line in r2.stdout.splitlines():
                    p = line.split()
                    if len(p) >= 4 and p[0] in ("tcp", "tcp6"):
                        entry = ConnectionEntry(protocol="TCP", state=p[5] if len(p) > 5 else "")
                        la = p[3].rsplit(":", 1)
                        entry.local_addr = la[0] if len(la) > 0 else ""
                        entry.local_port = la[1] if len(la) > 1 else ""
                        ra = p[4].rsplit(":", 1)
                        entry.remote_addr = ra[0] if len(ra) > 0 else ""
                        entry.remote_port = ra[1] if len(ra) > 1 else ""
                        if len(p) > 6:
                            pid_proc = p[6].split("/")
                            entry.pid = pid_proc[0]
                            entry.process = pid_proc[1] if len(pid_proc) > 1 else ""
                        entries.append(entry)
    return entries[:50]

def _get_routing_table() -> List[str]:
    if SYSNAME == "Windows":
        r = _run(["route", "print"], timeout=10)
    else:
        r = _run(["ip", "route", "show"], timeout=10)
    if r and r.returncode == 0:
        return [l for l in r.stdout.splitlines() if l.strip()]
    return []

def _get_network_profile_linux() -> str:
    """Detect if connected to home/work/public network (best-effort)."""
    r = _run(["nmcli", "-t", "-f", "NAME,TYPE,STATE,CONNECTIVITY", "con", "show", "--active"],
              timeout=5, log_errors=False)
    if r and r.returncode == 0:
        return r.stdout.strip()
    return ""

def scan_my_device() -> None:
    _hdr("GHOSTLINK — My Device Deep Info")
    ifaces = (_get_all_interfaces_windows() if SYSNAME == "Windows"
              else _get_all_interfaces_linux())

    # ── 1. Network Interfaces
    _section("Network Interfaces", "1")
    for iface in ifaces:
        if iface.type == "Loopback": continue
        state_color = C.GREEN if iface.state.lower() in ("up", "", "connected") else C.RED
        state_label = iface.state or "UP"
        print(f"\n  {C.BOLD}{C.CYAN}{iface.name}{C.RESET}  "
              f"{C.DIM}{iface.type}{C.RESET}  "
              f"{state_color}[{state_label}]{C.RESET}")
        if iface.mac:         _row("  MAC Address",    iface.mac)
        if iface.ipv4:        _row("  IPv4 Address",   f"{iface.ipv4}/{iface.ipv4_prefix}")
        for v6 in iface.ipv6: _row("  IPv6 Address",   v6)
        if iface.mtu:         _row("  MTU",             iface.mtu + " bytes")
        if iface.speed:       _row("  Link Speed",      iface.speed)
        _row("  DHCP Enabled",   "Yes" if iface.dhcp else "No")
        if iface.dhcp_server:           _row("  DHCP Server",    iface.dhcp_server)
        if iface.dhcp_lease_obtained:   _row("  Lease Obtained", iface.dhcp_lease_obtained)
        if iface.dhcp_lease_expires:    _row("  Lease Expires",  iface.dhcp_lease_expires, C.YELLOW)
        if iface.dns_servers:           _row("  DNS Servers",    ", ".join(iface.dns_servers))
        if iface.dns_suffix:            _row("  DNS Suffix",     iface.dns_suffix)
        if iface.profile:               _row("  Network Profile", iface.profile)

    # ── 2. Network Profile (Linux via nmcli)
    if SYSNAME != "Windows":
        profile_info = _get_network_profile_linux()
        if profile_info:
            _section("Active Network Connections (nmcli)", "2")
            for line in profile_info.splitlines():
                parts = line.split(":")
                if len(parts) >= 4:
                    name, ntype, state, conn = parts[0], parts[1], parts[2], parts[3]
                    color = C.GREEN if state == "activated" else C.YELLOW
                    print(f"  {color}{name:<20}{C.RESET} {C.DIM}{ntype:<12} {state:<12} {conn}{C.RESET}")
        idx = "3"
    else:
        idx = "2"

    # ── 3. Routing Table
    _section("Routing Table", idx)
    routes = _get_routing_table()
    if SYSNAME == "Windows":
        in_ipv4 = False
        for line in routes:
            if "IPv4 Route Table" in line:
                in_ipv4 = True
            if in_ipv4:
                print(f"  {C.DIM}{line}{C.RESET}")
            if in_ipv4 and "==========" in line and routes.index(line) > 5:
                break
    else:
        for line in routes[:25]:
            # Highlight default route
            if line.startswith("default"):
                print(f"  {C.CYAN}{line}{C.RESET}")
            else:
                print(f"  {C.DIM}{line}{C.RESET}")
        if len(routes) > 25:
            print(f"  {C.DIM}... {len(routes)-25} more routes{C.RESET}")

    # ── 4. Active TCP Connections
    next_idx = str(int(idx) + 1)
    _section("Active TCP Connections (ESTABLISHED / LISTEN)", next_idx)
    conns = _get_active_connections_detailed()
    if conns:
        established = [c for c in conns if c.state in ("ESTABLISHED", "ESTAB")]
        listening   = [c for c in conns if c.state in ("LISTEN", "LISTENING")]
        print(f"  {C.DIM}{'Proto':<6} {'Local Addr':<22} {'Remote Addr':<22} {'State':<14} {'Process'}{C.RESET}")
        print(f"  {'─'*6} {'─'*22} {'─'*22} {'─'*14} {'─'*15}")
        # Show established first (most interesting)
        shown = 0
        for c in established[:15]:
            proc = f"{c.process}({c.pid})" if c.process else c.pid
            local = f"{c.local_addr}:{c.local_port}"
            remote = f"{c.remote_addr}:{c.remote_port}"
            svc = PROTOCOL_PORTS.get(int(c.remote_port), "") if c.remote_port.isdigit() else ""
            svc_str = f" {C.DIM}[{svc}]{C.RESET}" if svc else ""
            print(f"  {C.GREEN}{c.protocol:<6}{C.RESET} {local:<22} {remote:<22} "
                  f"{C.GREEN}{c.state:<14}{C.RESET} {C.DIM}{proc}{C.RESET}{svc_str}")
            shown += 1
        if listening:
            print(f"\n  {C.DIM}── Listening ports ({len(listening)}) ──{C.RESET}")
        for c in listening[:10]:
            local = f"{c.local_addr}:{c.local_port}"
            svc = PROTOCOL_PORTS.get(int(c.local_port), "") if c.local_port.isdigit() else ""
            svc_str = f"  {C.DIM}[{svc}]{C.RESET}" if svc else ""
            print(f"  {C.BLUE}{c.protocol:<6}{C.RESET} {local:<22} {'*':<22} "
                  f"{C.BLUE}{c.state:<14}{C.RESET}{svc_str}")
        if len(conns) > 25:
            print(f"\n  {C.DIM}... and {len(conns)-25} more connections{C.RESET}")
    else:
        print(f"  {C.DIM}No connections found (may require elevated privileges){C.RESET}")

    # ── 5. System Hostname
    last_idx = str(int(next_idx) + 1)
    _section("System Identity", last_idx)
    try:
        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
        _row("  Hostname", hostname)
        if fqdn != hostname:
            _row("  FQDN",     fqdn)
        _row("  OS Platform", platform.platform())
        _row("  Python",      platform.python_version())
    except Exception as e:
        print(f"  {C.DIM}Could not retrieve system identity: {e}{C.RESET}")
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 3 — Network Infrastructure  (ENHANCED)
# ──────────────────────────────────────────────────────────────────────────────
def _traceroute(host: str = "8.8.8.8") -> List[str]:
    if SYSNAME == "Windows":
        r = _run(["tracert", "-d", "-h", "20", host], timeout=45)
    else:
        for cmd_base in (["traceroute", "-n", "-m", "20", host],
                          ["tracepath", "-n", host]):
            r = _run(cmd_base, timeout=45)
            if r and r.returncode == 0: break
    if r and r.returncode == 0:
        return [l for l in r.stdout.splitlines() if l.strip()]
    return []

def _estimate_dhcp_range(gateway: str) -> Tuple[str, str]:
    """Best-effort DHCP range estimation based on common router defaults."""
    parts = gateway.rsplit(".", 1)
    if len(parts) == 2:
        base = parts[0]
        # Most home routers use .100-.200 or .2-.254
        return f"{base}.100", f"{base}.200"
    return "", ""

def _detect_nat(gateway: str) -> str:
    """Try to determine NAT type by checking public vs local IP."""
    data = _http_get("http://ip-api.com/json/")
    if data:
        try:
            j = json.loads(data)
            public_ip = j.get("query", "")
            if public_ip and public_ip != gateway:
                return f"NAT active (public: {public_ip}, gateway: {gateway})"
        except Exception:
            pass
    return "Could not determine"

def scan_infrastructure() -> None:
    _hdr("GHOSTLINK — Network Infrastructure")
    net = get_local_network()

    # ── 1. Gateway Information
    _section("Gateway / Router Information", "1")
    _row("Gateway IP",    net.gateway or "Unknown")
    _row("Your LAN IP",   net.local_ip or "Unknown")
    _row("Network CIDR",  net.network_cidr or "Unknown")
    _row("Interface",     net.interface or "Unknown")

    if net.gateway:
        gw_alive = ping_host(net.gateway, timeout=2)
        _row("Gateway Ping", "Responsive ✓" if gw_alive else "No response ✗",
             C.GREEN if gw_alive else C.RED)

        # Ping stats to gateway
        if gw_alive:
            print(f"\n  {C.DIM}Measuring gateway latency (5 pings)…{C.RESET}")
            times = []
            for _ in range(5):
                cmd = (["ping", "-n", "1", "-w", "2000", net.gateway]
                        if SYSNAME == "Windows"
                        else ["ping", "-c", "1", "-W", "2", net.gateway])
                r = _run(cmd, timeout=5, log_errors=False)
                if r and r.returncode == 0:
                    m = re.search(r"time[=<]([\d.]+)\s*ms", r.stdout, re.I)
                    if m: times.append(float(m.group(1)))
                time.sleep(0.2)
            if times:
                _row("  Gateway RTT avg", f"{round(sum(times)/len(times),2)} ms  "
                     f"(min {min(times)} / max {max(times)})")

        # Admin interface detection
        print(f"\n  {C.DIM}Checking for router admin interface…{C.RESET}")
        admin_found = False
        for port in (80, 443, 8080, 8443):
            if _scan_port(net.gateway, port, 1.5):
                proto = "https" if port in (443, 8443) else "http"
                print(f"    {C.GREEN}→ Admin interface: {proto}://{net.gateway}:{port}/{C.RESET}")
                admin_found = True
        if not admin_found:
            print(f"    {C.DIM}No web admin interface detected on standard ports.{C.RESET}")

    # ── 2. DHCP Range Estimation
    _section("DHCP Range (Estimated)", "2")
    if net.gateway:
        dhcp_start, dhcp_end = _estimate_dhcp_range(net.gateway)
        _row("Estimated Start", dhcp_start or "Unknown")
        _row("Estimated End",   dhcp_end or "Unknown")
        print(f"  {C.DIM}Note: Actual range shown in router admin → DHCP settings.{C.RESET}")
        # Count active IPs in range
        arp = read_arp_table()
        active_in_range = 0
        if dhcp_start and dhcp_end:
            try:
                start_int = int(ipaddress.IPv4Address(dhcp_start))
                end_int   = int(ipaddress.IPv4Address(dhcp_end))
                for ip in arp:
                    try:
                        ip_int = int(ipaddress.IPv4Address(ip))
                        if start_int <= ip_int <= end_int:
                            active_in_range += 1
                    except Exception:
                        pass
                _row("Active leases (est.)", str(active_in_range))
            except Exception:
                pass

    # ── 3. NAT Detection
    _section("NAT / Internet Gateway", "3")
    print(f"  {C.DIM}Checking NAT configuration…{C.RESET}")
    nat_info = _detect_nat(net.gateway or "")
    _row("NAT Status", nat_info)

    # ── 4. Traceroute
    _section("Route to Internet (traceroute → 8.8.8.8)", "4")
    print(f"  {C.DIM}Running traceroute, please wait…{C.RESET}")
    hops = _traceroute("8.8.8.8")
    hop_count = 0
    for hop in hops:
        # Highlight hops with IPs
        if re.search(r'\d+\.\d+\.\d+\.\d+', hop):
            hop_count += 1
            print(f"  {C.DIM}{hop}{C.RESET}")
        else:
            print(f"  {C.DIM}{hop}{C.RESET}")
    if hop_count:
        print(f"\n  {C.GREEN}Total hops detected: {hop_count}{C.RESET}")
    if not hops:
        print(f"  {C.YELLOW}Traceroute unavailable or timed out.{C.RESET}")
    if SYSNAME == "Windows":
        print(f"\n  {C.DIM}Tip: Run 'pathping 8.8.8.8' for per-hop packet loss stats.{C.RESET}")
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 4 — Wireless Analysis  (ENHANCED)
# ──────────────────────────────────────────────────────────────────────────────
def _wifi_windows() -> Tuple[Optional[WirelessNetwork], List[WirelessNetwork]]:
    connected: Optional[WirelessNetwork] = None
    visible: List[WirelessNetwork] = []
    r = _run(["netsh", "wlan", "show", "interfaces"], timeout=10)
    if r and r.returncode == 0:
        w = WirelessNetwork(connected=True)
        for line in r.stdout.splitlines():
            l = line.strip()
            if l.startswith("SSID")         and "BSSID" not in l: w.ssid           = l.split(":", 1)[-1].strip()
            elif l.startswith("BSSID"):                             w.bssid          = l.split(":", 1)[-1].strip()
            elif l.startswith("Signal"):                            w.signal         = l.split(":", 1)[-1].strip()
            elif l.startswith("Channel"):                           w.channel        = l.split(":", 1)[-1].strip()
            elif l.startswith("Radio type"):                        w.band           = l.split(":", 1)[-1].strip()
            elif l.startswith("Authentication"):                    w.authentication = l.split(":", 1)[-1].strip()
            elif l.startswith("Cipher"):                            w.encryption     = l.split(":", 1)[-1].strip()
        if w.ssid: connected = w
    r2 = _run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=15)
    if r2 and r2.returncode == 0:
        current: Optional[WirelessNetwork] = None
        for line in r2.stdout.splitlines():
            l = line.strip()
            if l.startswith("SSID") and "BSSID" not in l and ":" in l:
                if current: visible.append(current)
                current = WirelessNetwork(ssid=l.split(":", 1)[-1].strip())
            elif current:
                if l.startswith("BSSID"):            current.bssid        = l.split(":", 1)[-1].strip()
                elif l.startswith("Signal"):          current.signal       = l.split(":", 1)[-1].strip()
                elif l.startswith("Channel"):         current.channel      = l.split(":", 1)[-1].strip()
                elif l.startswith("Radio"):           current.band         = l.split(":", 1)[-1].strip()
                elif l.startswith("Authentication"):  current.authentication = l.split(":", 1)[-1].strip()
                elif l.startswith("Encryption"):      current.encryption   = l.split(":", 1)[-1].strip()
        if current: visible.append(current)
    return connected, visible

def _wifi_linux() -> Tuple[Optional[WirelessNetwork], List[WirelessNetwork]]:
    connected: Optional[WirelessNetwork] = None
    visible: List[WirelessNetwork] = []
    r = _run(["iw", "dev"], timeout=10)
    iface = ""
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            if "Interface" in line:
                iface = line.strip().split()[-1]
    if iface:
        r2 = _run(["iw", iface, "link"], timeout=10)
        if r2 and r2.returncode == 0 and "Connected" in r2.stdout:
            w = WirelessNetwork(connected=True)
            for line in r2.stdout.splitlines():
                l = line.strip()
                if l.startswith("SSID"):    w.ssid    = l.split(":", 1)[-1].strip()
                elif l.startswith("freq"):  w.band    = l.split(":", 1)[-1].strip() + " MHz"
                elif "signal" in l.lower(): w.signal  = l.split(":", 1)[-1].strip()
                elif "channel" in l.lower():
                    m = re.search(r'channel (\d+)', l)
                    if m: w.channel = m.group(1)
            connected = w
        r3 = _run(["iwlist", iface, "scan"], timeout=20)
        if r3 and r3.returncode == 0:
            current: Optional[WirelessNetwork] = None
            for line in r3.stdout.splitlines():
                l = line.strip()
                if l.startswith("Cell "):
                    if current: visible.append(current)
                    current = WirelessNetwork()
                    m = re.search(r"Address:\s*([0-9A-Fa-f:]+)", l)
                    if m: current.bssid = m.group(1)
                elif current:
                    if "ESSID" in l:        current.ssid = l.split('"')[1] if '"' in l else ""
                    elif "Frequency" in l:  current.band = l.split(":")[-1].strip()
                    elif "Channel" in l and ":" in l: current.channel = l.split(":")[-1].strip()
                    elif "Signal level" in l:
                        m2 = re.search(r"Signal level=([^\s]+)", l)
                        if m2:
                            current.signal = m2.group(1)
                            # Try to parse dBm value
                            dbm_match = re.search(r'(-\d+)', current.signal)
                            if dbm_match:
                                try: current.signal_dbm = int(dbm_match.group(1))
                                except: pass
                    elif "Encryption key" in l:
                        current.security = "Encrypted" if "on" in l.lower() else "Open"
                    elif "IE:" in l and "WPA" in l:
                        current.authentication = l.split("IE:")[-1].strip()
            if current: visible.append(current)
    return connected, visible

def _signal_bar(signal_str: str) -> str:
    """Convert signal string to visual bar."""
    # Windows percentage
    pct_match = re.search(r'(\d+)%', signal_str)
    if pct_match:
        pct = int(pct_match.group(1))
        bars = int(pct / 20)
        bar = "█" * bars + "░" * (5 - bars)
        color = C.GREEN if pct >= 70 else (C.YELLOW if pct >= 40 else C.RED)
        return f"{color}{bar}{C.RESET} {pct}%"
    # Linux dBm
    dbm_match = re.search(r'(-\d+)', signal_str)
    if dbm_match:
        dbm = int(dbm_match.group(1))
        pct = max(0, min(100, 2 * (dbm + 100)))
        bars = int(pct / 20)
        bar = "█" * bars + "░" * (5 - bars)
        color = C.GREEN if dbm >= -60 else (C.YELLOW if dbm >= -75 else C.RED)
        return f"{color}{bar}{C.RESET} {dbm} dBm"
    return signal_str

def _channel_to_frequency(ch: str) -> str:
    """Map Wi-Fi channel to frequency band."""
    try:
        ch_int = int(ch.strip())
        if 1 <= ch_int <= 14:
            return "2.4 GHz"
        elif 36 <= ch_int <= 165:
            return "5 GHz"
    except (ValueError, AttributeError):
        pass
    return ""

def scan_wireless() -> None:
    _hdr("GHOSTLINK — Wireless Network Analysis")
    connected, visible = (_wifi_windows() if SYSNAME == "Windows"
                           else _wifi_linux())

    # ── 1. Connected Network
    _section("Connected Network", "1")
    if connected:
        _row("SSID",            connected.ssid or "Hidden")
        _row("BSSID (AP MAC)",  connected.bssid or "N/A")
        ch = connected.channel or "N/A"
        freq = _channel_to_frequency(connected.channel or "")
        _row("Channel",         f"{ch}  {C.DIM}{freq}{C.RESET}" if freq else ch)
        _row("Band / Type",     connected.band or "N/A")
        sig_bar = _signal_bar(connected.signal or "")
        _row("Signal Strength", sig_bar or connected.signal or "N/A")
        _row("Authentication",  connected.authentication or "N/A")
        _row("Encryption",      connected.encryption or "N/A")

        # Security assessment
        auth_low = (connected.authentication or "").lower()
        enc_low  = (connected.encryption or "").lower()
        print()
        if "wpa3" in auth_low:
            _ok("WPA3 — Excellent security (SAE handshake).")
        elif "wpa2" in auth_low:
            _ok("WPA2 — Good encryption. Consider WPA3 if router supports it.")
        elif "wep" in auth_low or "wep" in enc_low:
            _err("WEP — CRITICALLY WEAK! Can be cracked in under 60 seconds!")
        elif "wpa" in auth_low and "2" not in auth_low:
            _warn("WPA (v1) — Outdated. Upgrade to WPA2/WPA3 strongly recommended.")
        elif "open" in auth_low or auth_low == "":
            _err("OPEN NETWORK — No encryption! All traffic is visible to anyone nearby!")
    else:
        print(f"  {C.DIM}Not connected to a wireless network, or Wi-Fi adapter not found.{C.RESET}")

    # ── 2. Channel Congestion Analysis
    _section("Channel Congestion Analysis", "2")
    if visible:
        channel_counts: Dict[str, int] = {}
        for net in visible:
            ch = net.channel or "?"
            channel_counts[ch] = channel_counts.get(ch, 0) + 1

        print(f"  {C.DIM}Networks per channel:{C.RESET}")
        for ch in sorted(channel_counts.keys(), key=lambda x: int(x) if x.isdigit() else 999):
            count = channel_counts[ch]
            bar   = "▓" * count
            freq  = _channel_to_frequency(ch)
            color = C.RED if count >= 5 else (C.YELLOW if count >= 3 else C.GREEN)
            congestion = "HIGH" if count >= 5 else ("MEDIUM" if count >= 3 else "Low")
            print(f"  Ch {ch:<4} {color}{bar:<15}{C.RESET} {count} network(s)  "
                  f"{C.DIM}{freq}  [{congestion}]{C.RESET}")

        if connected and connected.channel:
            my_ch = connected.channel.strip()
            my_count = channel_counts.get(my_ch, 0)
            print()
            if my_count >= 4:
                _warn(f"Your channel {my_ch} is congested ({my_count} networks). "
                      f"Consider switching channels in router settings.")
            else:
                _ok(f"Your channel {my_ch} has low congestion ({my_count} network(s)).")

    # ── 3. Visible Networks
    _section(f"Visible Networks ({len(visible)} found)", "3")
    if visible:
        # Sort by signal (best first)
        def signal_sort_key(n: WirelessNetwork) -> int:
            pct_m = re.search(r'(\d+)%', n.signal or "")
            if pct_m: return -int(pct_m.group(1))
            dbm_m = re.search(r'(-\d+)', n.signal or "")
            if dbm_m: return -int(dbm_m.group(1)) - 100
            return 999

        sorted_nets = sorted(visible, key=signal_sort_key)
        print(f"  {C.DIM}{'SSID':<28} {'BSSID':<19} {'CH':<4} {'Band':<8} {'Signal':<14} Auth{C.RESET}")
        print(f"  {'─'*28} {'─'*19} {'─'*4} {'─'*8} {'─'*14} {'─'*12}")
        for net in sorted_nets:
            ssid   = (net.ssid or "〈Hidden〉")[:26]
            bssid  = (net.bssid or "")[:17]
            ch     = (net.channel or "?")[:3]
            freq   = _channel_to_frequency(net.channel or "")
            band   = freq[:7] if freq else (net.band or "")[:7]
            sig    = _signal_bar(net.signal or "") if net.signal else "N/A"
            auth   = (net.authentication or net.security or "Unknown")[:12]

            # Highlight connected
            prefix = f"{C.GREEN}►{C.RESET}" if connected and net.ssid == connected.ssid else " "
            # Weak encryption warning
            al = auth.lower()
            weak_flag = ""
            if "wep" in al:   weak_flag = f" {C.RED}[WEP!]{C.RESET}"
            elif auth == "Unknown" or "open" in al: weak_flag = f" {C.YELLOW}[Open?]{C.RESET}"
            print(f" {prefix} {ssid:<28} {bssid:<19} {ch:<4} {band:<8} {sig:<14} {auth}{weak_flag}")
    else:
        print(f"  {C.DIM}No nearby networks found (may require elevated privileges).{C.RESET}")
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 5 — Internet & External Identity
# ──────────────────────────────────────────────────────────────────────────────
def scan_internet_identity() -> None:
    _hdr("GHOSTLINK — Internet & External Identity")

    _section("Public IP & ISP", "1")
    print(f"  {C.DIM}Querying ip-api.com…{C.RESET}")
    data = _http_get("http://ip-api.com/json/")
    if data:
        try:
            j = json.loads(data)
            _row("Public IP",     j.get("query",       "N/A"), C.CYAN)
            _row("ISP / Org",     j.get("isp",         j.get("org", "N/A")))
            _row("AS Number",     j.get("as",          "N/A"))
            _row("Country",       j.get("country",     "N/A"))
            _row("Region",        j.get("regionName",  "N/A"))
            _row("City",          j.get("city",        "N/A"))
            _row("Timezone",      j.get("timezone",    "N/A"))
            _row("Latitude",      str(j.get("lat",     "N/A")))
            _row("Longitude",     str(j.get("lon",     "N/A")))

            # VPN/proxy detection hint
            is_proxy = j.get("proxy", False)
            is_hosting = j.get("hosting", False)
            if is_proxy:
                _warn("IP flagged as proxy/VPN by ip-api.com")
            if is_hosting:
                _warn("IP associated with hosting/datacenter (possible VPS/VPN)")
        except (json.JSONDecodeError, KeyError):
            print(f"  {C.YELLOW}Could not parse geolocation data.{C.RESET}")
    else:
        print(f"  {C.YELLOW}Could not reach ip-api.com.{C.RESET}")

    _section("DNS Resolution Path", "2")
    test_domains = ["google.com", "cloudflare.com", "amazon.com", "github.com"]
    for domain in test_domains:
        try:
            start = time.time()
            ip = socket.gethostbyname(domain)
            ms = round((time.time() - start) * 1000, 2)
            speed_color = C.GREEN if ms < 50 else (C.YELLOW if ms < 150 else C.RED)
            print(f"  {C.GREEN}✓{C.RESET} {domain:<22} → {ip:<16}  {speed_color}{ms}ms{C.RESET}")
        except socket.gaierror:
            print(f"  {C.RED}✗{C.RESET} {domain:<22} → DNS resolution FAILED")

    _section("DNS Server Analysis", "3")
    dns_servers_found: List[str] = []
    if SYSNAME != "Windows":
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_ip = line.split()[1]
                        dns_servers_found.append(dns_ip)
                        label = ""
                        if dns_ip.startswith("8.8"):   label = "  (Google DNS)"
                        elif dns_ip.startswith("1.1"): label = "  (Cloudflare)"
                        elif dns_ip.startswith("9.9"): label = "  (Quad9)"
                        elif dns_ip.startswith("208.67"): label = "  (OpenDNS)"
                        elif dns_ip.startswith("192.168") or dns_ip.startswith("10."): label = "  (Local / Router)"
                        print(f"  {C.CYAN}{dns_ip}{C.RESET}{C.DIM}{label}{C.RESET}")
        except FileNotFoundError:
            print(f"  {C.DIM}/etc/resolv.conf not found.{C.RESET}")
    else:
        r = _run(["netsh", "interface", "ip", "show", "dnsservers"], timeout=8)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                if re.search(r'\d+\.\d+\.\d+\.\d+', line):
                    print(f"  {C.CYAN}{line.strip()}{C.RESET}")

    # DNS leak check hint
    if dns_servers_found:
        local_dns = [d for d in dns_servers_found if
                      d.startswith("192.168") or d.startswith("10.") or d.startswith("172.")]
        if local_dns:
            _ok("Using local DNS (router) — normal home network behavior.")
            print(f"  {C.DIM}Tip: For DNS privacy, consider using encrypted DNS (DoH/DoT).{C.RESET}")

    _section("Connectivity Check", "4")
    test_endpoints = [
        ("http://connectivitycheck.gstatic.com/generate_204", "Google Connectivity"),
        ("http://www.msftconnecttest.com/connecttest.txt",    "Microsoft NCSI"),
    ]
    for url, label in test_endpoints:
        result = _http_get(url, timeout=5)
        if result is not None:
            _ok(f"{label}: Connected")
        else:
            _err(f"{label}: No response")
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 6 — Performance & Stability  (ENHANCED)
# ──────────────────────────────────────────────────────────────────────────────
def _single_ping_ms(host: str, timeout: float = 2.0) -> Optional[float]:
    if SYSNAME == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout*1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
    r = _run(cmd, timeout=int(timeout)+2, log_errors=False)
    if r and r.returncode == 0:
        m = re.search(r"time[=<]([\d.]+)\s*ms", r.stdout, re.I)
        if m: return float(m.group(1))
    return None

def _latency_test(host: str, count: int = 20) -> PingStats:
    stats = PingStats(host=host, sent=count)
    times: List[float] = []
    print(f"  {C.DIM}Pinging {host} ({count} packets)…{C.RESET}", end="", flush=True)
    for i in range(count):
        ms = _single_ping_ms(host)
        if ms is not None:
            times.append(ms)
            # Show live indicator
            if ms < 20:   print(f"{C.GREEN}·{C.RESET}", end="", flush=True)
            elif ms < 80: print(f"{C.YELLOW}·{C.RESET}", end="", flush=True)
            else:          print(f"{C.RED}·{C.RESET}", end="", flush=True)
        else:
            print(f"{C.RED}✗{C.RESET}", end="", flush=True)
        time.sleep(0.15)
    print()
    if times:
        stats.received = len(times)
        stats.min_ms   = round(min(times), 2)
        stats.max_ms   = round(max(times), 2)
        stats.avg_ms   = round(statistics.mean(times), 2)
        if len(times) > 1:
            stats.jitter_ms = round(statistics.stdev(times), 2)
        stats.packet_loss_pct = round((count - len(times)) / count * 100, 1)
    return stats

def _print_ping_stats(stats: PingStats) -> None:
    loss_color = C.GREEN if stats.packet_loss_pct == 0 else (
                 C.YELLOW if stats.packet_loss_pct < 10 else C.RED)
    jit_color  = C.GREEN if stats.jitter_ms < 5 else (
                 C.YELLOW if stats.jitter_ms < 20 else C.RED)
    lat_color  = C.GREEN if stats.avg_ms < 20 else (
                 C.YELLOW if stats.avg_ms < 80 else C.RED)
    _row(f"  {stats.host} — Sent",    str(stats.sent))
    _row("  Received",                str(stats.received))
    _row("  Packet Loss",             f"{stats.packet_loss_pct}%", loss_color)
    _row("  Min / Avg / Max RTT",     f"{stats.min_ms} / {stats.avg_ms} / {stats.max_ms} ms",
         lat_color)
    _row("  Jitter (std-dev)",        f"{stats.jitter_ms} ms", jit_color)
    # Quality label
    if stats.avg_ms == 0 and stats.received == 0:
        quality = "Unreachable"; qcolor = C.RED
    elif stats.packet_loss_pct > 20 or stats.avg_ms > 200:
        quality = "Poor ✗"; qcolor = C.RED
    elif stats.packet_loss_pct > 5 or stats.avg_ms > 80:
        quality = "Fair △"; qcolor = C.YELLOW
    elif stats.avg_ms < 20 and stats.jitter_ms < 5:
        quality = "Excellent ✓"; qcolor = C.GREEN
    else:
        quality = "Good ✓"; qcolor = C.GREEN
    _row("  Connection Quality",      quality, qcolor)

    # Use-case assessment
    if stats.received > 0:
        print()
        if stats.avg_ms < 20 and stats.jitter_ms < 5 and stats.packet_loss_pct == 0:
            _ok("Excellent for gaming, VoIP, video calls, and streaming.")
        elif stats.avg_ms < 50 and stats.jitter_ms < 10:
            _ok("Good for video streaming and video calls.")
            if stats.avg_ms > 30:
                _warn("Latency may cause occasional lag in competitive gaming.")
        elif stats.avg_ms < 100:
            _warn("Suitable for browsing and streaming. VoIP quality may degrade.")
        else:
            _err("High latency. VoIP and gaming will be significantly impacted.")

def _path_mtu_discovery(host: str = "8.8.8.8") -> Optional[int]:
    """Estimate path MTU by pinging with different packet sizes."""
    if SYSNAME == "Windows":
        for size in (1472, 1400, 1300, 1200):
            r = _run(["ping", "-n", "1", "-l", str(size), "-f", host],
                      timeout=5, log_errors=False)
            if r and r.returncode == 0 and "TTL=" in r.stdout:
                return size + 28  # +28 for IP+ICMP header
    else:
        for size in (1472, 1400, 1300, 1200):
            r = _run(["ping", "-c", "1", "-s", str(size), "-M", "do", host],
                      timeout=5, log_errors=False)
            if r and r.returncode == 0:
                return size + 28
    return None

def _show_speed_test():
    _section("🚀 Internet Speed Test", "6")
    
    if _tool_exists("speedtest-cli"):
        print(f"  {C.DIM}Running speedtest-cli (this may take 30s)…{C.RESET}")
        r = _run(["speedtest-cli", "--simple"], timeout=60)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                print(f"  {C.GREEN}{line}{C.RESET}")
            return
        else:
            print(f"  {C.YELLOW}speedtest-cli failed, falling back to HTTP test.{C.RESET}")

    # Fallback: download test only
    print(f"  {C.DIM}Measuring download (1 MB)…{C.RESET}")
    url = "http://speedtest.tele2.net/1MB.zip"
    try:
        start = time.time()
        with urllib.request.urlopen(url, timeout=10) as f:
            data = f.read()
        elapsed = time.time() - start
        if elapsed > 0:
            speed = (len(data) * 8) / (elapsed * 1_000_000)
            print(f"  {C.GREEN}Download: {speed:.1f} Mbps{C.RESET}")
        else:
            print(f"  {C.GREEN}Download: too fast to measure{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}Download test failed: {e}{C.RESET}")

    print(f"\n  {C.YELLOW}⚠  Upload test requires speedtest-cli.{C.RESET}")
    print(f"  {C.DIM}Install: pip install speedtest-cli{C.RESET}")
    print(f"  {C.DIM}Then re-run this module.{C.RESET}")

def scan_performance() -> None:
    _hdr("GHOSTLINK — Performance & Stability")
    net = get_local_network()
    targets = [
        ("Gateway",      net.gateway  or "192.168.1.1"),
        ("Google DNS",   "8.8.8.8"),
        ("Cloudflare",   "1.1.1.1"),
        ("Google",       "8.8.4.4"),
    ]
    for label, host in targets:
        _section(f"Latency Test → {host}  [{label}]")
        stats = _latency_test(host, count=15)
        _print_ping_stats(stats)

    # Path MTU
    _section("Path MTU Discovery", "5")
    print(f"  {C.DIM}Detecting maximum transmission unit to 8.8.8.8…{C.RESET}")
    mtu = _path_mtu_discovery("8.8.8.8")
    if mtu:
        _row("Estimated Path MTU", f"{mtu} bytes")
        if mtu >= 1500:
            _ok("Standard Ethernet MTU — no fragmentation expected.")
        elif mtu >= 1400:
            _warn("Slightly reduced MTU. May indicate VPN or PPPoE tunnel.")
        else:
            _warn(f"Low MTU ({mtu}). May cause performance issues — check VPN/tunnel config.")
    else:
        print(f"  {C.DIM}MTU discovery inconclusive.{C.RESET}")

    # Bandwidth test
    _show_speed_test()
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 7 — Network Resources & Sharing  (ENHANCED)
# ──────────────────────────────────────────────────────────────────────────────
def _mdns_discover() -> List[str]:
    results: List[str] = []
    r = _run(["avahi-browse", "-a", "-t", "-r", "--no-db-lookup"],
              timeout=10, log_errors=False)
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            if "=" in line and any(svc in line for svc in
                ("_http", "_smb", "_printer", "_ftp", "_ssh", "_airplay",
                 "_raop", "_ipp", "_pdl", "_rfb", "_nfs")):
                results.append(line.strip())
    return results[:20]

def scan_resources() -> None:
    _hdr("GHOSTLINK — Network Resources & Sharing")

    # ── 1. SMB Shares
    _section("SMB Shares / Shared Folders", "1")
    if SYSNAME == "Windows":
        r_view = _run(["net", "view"], timeout=12)
        if r_view and r_view.returncode == 0 and r_view.stdout.strip():
            for line in r_view.stdout.splitlines():
                if line.strip(): print(f"  {C.DIM}{line}{C.RESET}")
        else:
            print(f"  {C.DIM}No shared computers visible via 'net view'.{C.RESET}")
        # Also show local shares
        r_share = _run(["net", "share"], timeout=10)
        if r_share and r_share.returncode == 0:
            print(f"\n  {C.BOLD}Local shared resources:{C.RESET}")
            for line in r_share.stdout.splitlines():
                if line.strip() and not line.startswith("-"):
                    print(f"  {C.DIM}{line}{C.RESET}")
    else:
        if _tool_exists("smbclient"):
            arp = read_arp_table()
            found_any = False
            for ip in list(sorted(arp.keys()))[:15]:
                r = _run(["smbclient", "-N", "-L", ip], timeout=8, log_errors=False)
                if r and r.returncode == 0 and "Sharename" in r.stdout:
                    found_any = True
                    print(f"\n  {C.CYAN}► {ip}{C.RESET}")
                    for line in r.stdout.splitlines():
                        if any(x in line for x in ("Disk", "Printer", "IPC", "Sharename")):
                            print(f"    {C.DIM}{line.strip()}{C.RESET}")
            if not found_any:
                print(f"  {C.DIM}No anonymous SMB shares found on LAN.{C.RESET}")
        else:
            print(f"  {C.YELLOW}smbclient not found. Install: sudo apt install smbclient{C.RESET}")

    # ── 2. NAS / Printer Detection
    _section("NAS / Printer / Service Detection", "2")
    arp = read_arp_table()
    svc_ports = {
        80:   "Web UI / NAS",
        443:  "HTTPS",
        21:   "FTP",
        22:   "SSH",
        445:  "SMB Share",
        9100: "RAW Print",
        515:  "LPD Print",
        631:  "CUPS/IPP",
        8080: "Alt Web UI",
        5000: "Synology NAS",
        5001: "Synology HTTPS",
        8200: "Plex Media",
        32400: "Plex Media Server",
        8096: "Jellyfin",
        32469: "Plex DLNA",
    }
    device_list = list(sorted(arp.keys()))[:15]
    print(f"  {C.DIM}Scanning {len(device_list)} devices for service ports…{C.RESET}\n")
    for ip in device_list:
        hits = {}
        for port, label in svc_ports.items():
            if _scan_port(ip, port, 0.8):
                hits[port] = label
        if hits:
            hostname = resolve_hostname(ip)
            hn_str = f"  {C.DIM}({hostname}){C.RESET}" if hostname else ""
            mfr = get_manufacturer(arp.get(ip, ""))
            mfr_str = f"  {C.DIM}[{mfr}]{C.RESET}" if mfr != "Unknown" else ""
            print(f"  {C.BOLD}{C.CYAN}{ip:<16}{C.RESET}{hn_str}{mfr_str}")
            for port, label in hits.items():
                proto = "https" if port in (443, 5001, 8443) else "http"
                if port in (80, 443, 8080, 8443, 5000, 5001, 8200, 32400, 8096):
                    print(f"    {C.GREEN}→ {port:<6}{C.RESET} {label}  "
                          f"{C.DIM}{proto}://{ip}:{port}/{C.RESET}")
                else:
                    print(f"    {C.GREEN}→ {port:<6}{C.RESET} {label}")
            print()

    # ── 3. mDNS / Bonjour
    _section("mDNS / Bonjour Service Discovery", "3")
    if SYSNAME == "Linux":
        services = _mdns_discover()
        if services:
            for s in services:
                print(f"  {C.DIM}{s}{C.RESET}")
        else:
            if not _tool_exists("avahi-browse"):
                print(f"  {C.YELLOW}avahi-browse not found. Install: sudo apt install avahi-utils{C.RESET}")
            else:
                print(f"  {C.DIM}No mDNS services discovered.{C.RESET}")
    else:
        r_dns = _run(["dns-sd", "-B", "_services._dns-sd._udp", "local"], timeout=5)
        if r_dns and r_dns.stdout:
            for line in r_dns.stdout.splitlines():
                if line.strip(): print(f"  {C.DIM}{line}{C.RESET}")
        else:
            print(f"  {C.DIM}Use Windows Network Explorer to browse shared devices.{C.RESET}")
            print(f"  {C.DIM}Tip: Open File Explorer → Network to see mDNS/UPnP devices.{C.RESET}")
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 8 — Security Insights  (ENHANCED)
# ──────────────────────────────────────────────────────────────────────────────
def _get_failed_connections_windows() -> List[str]:
    """Try to read recent failed connections from Windows event log."""
    lines = []
    r = _run(["powershell", "-Command",
               "Get-WinEvent -LogName Security -MaxEvents 50 2>$null | "
               "Where-Object {$_.Id -in 4625,5152} | "
               "Select-Object TimeCreated,Message | Format-List | "
               "Select-Object -First 10"], timeout=15, log_errors=False)
    if r and r.returncode == 0:
        lines = [l for l in r.stdout.splitlines() if l.strip()][:20]
    return lines

def scan_security() -> None:
    _hdr("GHOSTLINK — Security Insights")
    net = get_local_network()

    # ── 1. Wireless Encryption
    _section("Wireless Encryption Assessment", "1")
    conn, visible = (_wifi_windows() if SYSNAME == "Windows" else _wifi_linux())
    if conn:
        auth = (conn.authentication or "").lower()
        enc  = (conn.encryption or "").lower()
        _row("Connected SSID",  conn.ssid or "Hidden")
        _row("BSSID",           conn.bssid or "N/A")
        if "wpa3" in auth:
            _row("Security",    "WPA3 — Excellent ✓", C.GREEN)
            _ok("SAE (Simultaneous Authentication of Equals) in use.")
        elif "wpa2" in auth and "enterprise" in auth:
            _row("Security",    "WPA2-Enterprise — Very Good ✓", C.GREEN)
        elif "wpa2" in auth:
            _row("Security",    "WPA2-Personal — Good ✓", C.GREEN)
            _warn("Consider upgrading to WPA3 when possible.")
        elif "wpa" in auth and "2" not in auth:
            _row("Security",    "WPA (v1) — Weak ⚠", C.YELLOW)
            _warn("WPA v1 is vulnerable. Upgrade router firmware to enable WPA2/3.")
        elif "wep" in auth or "wep" in enc:
            _row("Security",    "WEP — CRITICALLY WEAK ✗", C.RED)
            _err("WEP can be cracked in under 60 seconds. Change immediately!")
        else:
            _row("Security",    "Open / Unknown ✗", C.RED)
            _err("No encryption detected. All traffic is exposed!")
    else:
        print(f"  {C.DIM}No wireless connection detected.{C.RESET}")

    # ── 2. Rogue AP Detection
    if visible:
        _section("Rogue AP / Evil Twin Detection", "2")
        ssid_map: Dict[str, List[str]] = {}
        for n in visible:
            if n.ssid:
                ssid_map.setdefault(n.ssid, []).append(n.bssid or "Unknown")
        found_rogue = False
        for ssid, bssids in ssid_map.items():
            if len(bssids) > 1:
                found_rogue = True
                _warn(f"SSID '{ssid}' seen on {len(bssids)} BSSIDs — possible Evil Twin or multi-AP!")
                for b in bssids:
                    mfr = get_manufacturer(b)
                    print(f"    {C.DIM}BSSID: {b}  [{mfr}]{C.RESET}")
        if not found_rogue:
            _ok("No duplicate SSIDs detected.")
        # Check for deauth flood indicators (Linux only)
        if SYSNAME == "Linux":
            r_dmesg = _run(["dmesg"], timeout=5, log_errors=False)
            if r_dmesg:
                deauth_count = sum(1 for l in r_dmesg.stdout.splitlines()
                                   if "deauth" in l.lower() or "disassoc" in l.lower())
                if deauth_count > 5:
                    _warn(f"{deauth_count} deauth/disassoc events in kernel log — possible deauth attack!")
                else:
                    _ok("No deauthentication flood detected in kernel log.")

    # ── 3. Risky Ports Scan
    _section("Risky Ports Scan Across LAN Devices", "3")
    arp = read_arp_table()
    risky_found = False
    risk_summary: Dict[str, List[Tuple[int, str]]] = {}
    for ip in list(sorted(arp.keys()))[:20]:
        open_risky = [p for p in RISKY_PORTS if _scan_port(ip, p, 0.8)]
        if open_risky:
            risky_found = True
            risk_summary[ip] = [(p, RISKY_PORTS[p]) for p in open_risky]
    if risky_found:
        for ip, risks in sorted(risk_summary.items()):
            hostname = resolve_hostname(ip)
            hn_str = f"  ({hostname})" if hostname else ""
            mfr = get_manufacturer(arp.get(ip, ""))
            print(f"\n  {C.BOLD}{ip}{C.RESET}{C.DIM}{hn_str}  [{mfr}]{C.RESET}")
            for port, desc in risks:
                severity = "CRITICAL" if port in (23, 21, 5900) else "HIGH" if port in (3389, 445, 3306) else "MEDIUM"
                color = C.RED if severity in ("CRITICAL", "HIGH") else C.YELLOW
                print(f"    {color}⚠  Port {port:<6}{C.RESET} {desc}  {C.DIM}[{severity}]{C.RESET}")
    else:
        _ok("No risky open ports found on scanned devices.")

    # ── 4. Unknown Device Detection
    _section("Unknown / Unrecognised Devices", "4")
    unknown_count = 0
    known_count = 0
    for ip, mac in sorted(arp.items()):
        mfr = get_manufacturer(mac)
        if mfr == "Unknown":
            hostname = resolve_hostname(ip)
            hn_str = f"  {hostname}" if hostname else ""
            print(f"  {C.YELLOW}?  {ip:<16}{mac:<20}{C.DIM}{hn_str}{C.RESET}")
            unknown_count += 1
        else:
            known_count += 1
    if unknown_count == 0:
        _ok(f"All {known_count} device(s) have recognised manufacturer prefixes.")
    else:
        print(f"\n  {C.DIM}Note: Unknown OUI doesn't always mean intruder "
              f"(randomised MAC, OUI table gaps).{C.RESET}")
        print(f"  {C.DIM}Cross-reference with your router's device list to verify.{C.RESET}")

    # ── 5. Firewall Status
    _section("Local Firewall Status", "5")
    if SYSNAME == "Windows":
        r = _run(["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=8)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                if "Profile" in line:
                    print(f"\n  {C.BOLD}{line.strip()}{C.RESET}")
                elif "State" in line:
                    color = C.GREEN if "ON" in line.upper() else C.RED
                    status = "ENABLED ✓" if "ON" in line.upper() else "DISABLED ✗"
                    print(f"    {color}{line.strip()}  [{status}]{C.RESET}")
    else:
        r = _run(["ufw", "status", "verbose"], timeout=5)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines()[:15]:
                if line.strip():
                    color = (C.GREEN if "active" in line.lower()
                             else C.RED if "inactive" in line.lower()
                             else C.DIM)
                    print(f"  {color}{line}{C.RESET}")
        else:
            r2 = _run(["iptables", "-L", "-n", "--line-numbers"], timeout=8)
            if r2 and r2.returncode == 0:
                lines = [l for l in r2.stdout.splitlines() if l.strip()][:15]
                for line in lines:
                    print(f"  {C.DIM}{line}{C.RESET}")
            else:
                print(f"  {C.DIM}Firewall check requires elevated privileges (sudo).{C.RESET}")

    # ── 6. Failed Connection Monitoring (Windows)
    if SYSNAME == "Windows":
        _section("Recent Failed Connections (Security Log)", "6")
        print(f"  {C.DIM}Checking Windows Security Event Log…{C.RESET}")
        failed = _get_failed_connections_windows()
        if failed:
            for line in failed[:15]:
                print(f"  {C.DIM}{line}{C.RESET}")
        else:
            print(f"  {C.DIM}No failed connections found "
                  f"(requires Administrator privileges or audit policy enabled).{C.RESET}")

    # ── 7. Security Summary Score
    _section("Security Summary", "7" if SYSNAME == "Windows" else "6")
    score = 100
    issues = []
    if conn:
        auth_l = (conn.authentication or "").lower()
        if "wep" in auth_l:           score -= 40; issues.append("WEP encryption in use (-40)")
        elif "wpa" in auth_l and "2" not in auth_l and "3" not in auth_l:
                                        score -= 20; issues.append("WPA v1 in use (-20)")
        elif "open" in auth_l or not auth_l:
                                        score -= 50; issues.append("Open/no encryption (-50)")
    if risky_found:
        count = sum(len(v) for v in risk_summary.values())
        score -= min(30, count * 5); issues.append(f"{count} risky port(s) open (-{min(30, count*5)})")
    if unknown_count > 0:
        score -= min(10, unknown_count * 2); issues.append(f"{unknown_count} unknown device(s) (-{min(10, unknown_count*2)})")
    score = max(0, score)
    bar_len = score // 5
    bar = "█" * bar_len + "░" * (20 - bar_len)
    color = C.GREEN if score >= 75 else (C.YELLOW if score >= 50 else C.RED)
    print(f"\n  {C.BOLD}Security Score: {color}{score}/100{C.RESET}")
    print(f"  {color}{bar}{C.RESET}")
    if issues:
        print(f"\n  {C.BOLD}Issues found:{C.RESET}")
        for issue in issues:
            _warn(issue)
    else:
        _ok("No significant security issues detected.")
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  MODULE 9 — Traffic Analysis  (NEW)
# ──────────────────────────────────────────────────────────────────────────────
def _get_current_connections_breakdown() -> Dict[str, Any]:
    """Analyse current connections to produce protocol/destination breakdown."""
    result: Dict[str, Any] = {
        "by_protocol": {},
        "by_remote_port": {},
        "by_state": {},
        "external_ips": set(),
        "local_ips": set(),
        "total": 0,
    }
    entries = _get_active_connections_detailed()
    result["total"] = len(entries)
    for c in entries:
        # State breakdown
        s = c.state or "UNKNOWN"
        result["by_state"][s] = result["by_state"].get(s, 0) + 1
        # Protocol
        proto_name = PROTOCOL_PORTS.get(int(c.remote_port), None) if c.remote_port.isdigit() else None
        if not proto_name:
            proto_name = PROTOCOL_PORTS.get(int(c.local_port), "Other") if c.local_port.isdigit() else "Other"
        result["by_protocol"][proto_name] = result["by_protocol"].get(proto_name, 0) + 1
        # Remote port frequency
        if c.remote_port.isdigit():
            port = int(c.remote_port)
            key = f"{port} ({PROTOCOL_PORTS.get(port, 'unknown')})"
            result["by_remote_port"][key] = result["by_remote_port"].get(key, 0) + 1
        # IP categorisation
        addr = c.remote_addr.strip("[]")
        if addr and addr not in ("0.0.0.0", "*", "::"):
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj.is_private:
                    result["local_ips"].add(addr)
                else:
                    result["external_ips"].add(addr)
            except ValueError:
                pass
    return result

def _dns_query_snapshot() -> List[str]:
    """Capture a snapshot of DNS activity using ss/netstat (passive)."""
    lines = []
    if SYSNAME == "Windows":
        r = _run(["netstat", "-ano"], timeout=10)
    else:
        r = _run(["ss", "-unp"], timeout=8)
        if not r: r = _run(["netstat", "-unp"], timeout=8)
    if r and r.returncode == 0:
        for line in r.stdout.splitlines():
            if ":53 " in line or ".53 " in line:
                lines.append(line.strip())
    return lines[:20]

def _get_interface_stats() -> Dict[str, Dict[str, str]]:
    """Read per-interface RX/TX byte counters."""
    stats: Dict[str, Dict[str, str]] = {}
    if SYSNAME == "Linux":
        r = _run(["cat", "/proc/net/dev"], timeout=5)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(":")
                    stats[iface] = {
                        "rx_bytes": parts[1],
                        "rx_packets": parts[2],
                        "rx_errors": parts[3],
                        "rx_drop": parts[4],
                        "tx_bytes": parts[9],
                        "tx_packets": parts[10],
                        "tx_errors": parts[11],
                    }
    elif SYSNAME == "Windows":
        r = _run(["netstat", "-e"], timeout=8)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                if "Bytes" in line or "bytes" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        stats["total"] = {"rx_bytes": parts[1], "tx_bytes": parts[2]}
    return stats

def _format_bytes(b_str: str) -> str:
    """Format byte count string into human-readable."""
    try:
        b = int(b_str)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"
    except (ValueError, TypeError):
        return b_str

def _check_wireshark() -> bool:
    return _tool_exists("wireshark") or _tool_exists("tshark")

def _check_tcpdump() -> bool:
    return _tool_exists("tcpdump")

def _run_tcpdump_snapshot(iface: str = "", duration: int = 5) -> List[str]:
    """Run a brief tcpdump capture and summarise (requires sudo on Linux)."""
    if not _check_tcpdump():
        return []
    cmd = ["tcpdump", "-nn", "-c", "50", "-q"]
    if iface: cmd += ["-i", iface]
    r = _run(cmd, timeout=duration + 5, log_errors=False)
    if r and (r.returncode == 0 or r.stdout):
        return [l for l in r.stdout.splitlines() if l.strip()][:40]
    return []

def scan_traffic() -> None:
    _hdr("GHOSTLINK — Traffic Analysis")

    # ── 1. Live Connection Breakdown
    _section("Current Connection Breakdown", "1")
    breakdown = _get_current_connections_breakdown()
    print(f"  {C.BOLD}Total tracked connections:{C.RESET} {breakdown['total']}")

    if breakdown["by_state"]:
        print(f"\n  {C.BOLD}By State:{C.RESET}")
        for state, count in sorted(breakdown["by_state"].items(),
                                    key=lambda x: -x[1]):
            bar = "▓" * min(count, 20)
            color = (C.GREEN if state in ("ESTABLISHED", "ESTAB")
                     else C.BLUE if state in ("LISTEN", "LISTENING")
                     else C.DIM)
            print(f"    {color}{state:<16}{C.RESET}  {bar} {count}")

    if breakdown["by_protocol"]:
        print(f"\n  {C.BOLD}By Protocol (inferred from port):{C.RESET}")
        sorted_protos = sorted(breakdown["by_protocol"].items(), key=lambda x: -x[1])
        for proto, count in sorted_protos[:12]:
            bar = "▓" * min(count * 2, 20)
            print(f"    {C.CYAN}{proto:<18}{C.RESET}  {bar} {count}")

    if breakdown["by_remote_port"]:
        print(f"\n  {C.BOLD}Top Remote Ports:{C.RESET}")
        top_ports = sorted(breakdown["by_remote_port"].items(), key=lambda x: -x[1])[:8]
        for port_label, count in top_ports:
            print(f"    {C.DIM}{port_label:<30}{C.RESET} {count} connection(s)")

    ext_ips = list(breakdown["external_ips"])
    if ext_ips:
        print(f"\n  {C.BOLD}External Destinations ({len(ext_ips)} unique IPs):{C.RESET}")
        for ip in ext_ips[:10]:
            hostname = resolve_hostname(ip)
            hn = f"  → {hostname}" if hostname else ""
            print(f"    {C.CYAN}{ip:<18}{C.RESET}{C.DIM}{hn}{C.RESET}")
        if len(ext_ips) > 10:
            print(f"    {C.DIM}... and {len(ext_ips)-10} more{C.RESET}")

    # ── 2. Interface Traffic Counters
    _section("Interface Traffic Counters (Since Boot)", "2")
    stats = _get_interface_stats()
    if stats:
        print(f"  {C.DIM}{'Interface':<16} {'RX (Received)':<20} {'TX (Sent)':<20} {'Errors'}{C.RESET}")
        print(f"  {'─'*16} {'─'*20} {'─'*20} {'─'*10}")
        for iface, s in stats.items():
            if iface in ("lo", "loopback"): continue
            rx = _format_bytes(s.get("rx_bytes", "0"))
            tx = _format_bytes(s.get("tx_bytes", "0"))
            rx_err = s.get("rx_errors", "0")
            tx_err = s.get("tx_errors", "0")
            err_str = ""
            if rx_err != "0" or tx_err != "0":
                err_str = f"{C.RED}RX:{rx_err} TX:{tx_err}{C.RESET}"
            print(f"  {C.BOLD}{iface:<16}{C.RESET} {C.GREEN}{rx:<20}{C.RESET} "
                  f"{C.CYAN}{tx:<20}{C.RESET} {err_str or C.DIM+'None'+C.RESET}")
    else:
        print(f"  {C.DIM}Interface statistics unavailable.{C.RESET}")

    # ── 3. DNS Activity Snapshot
    _section("DNS Activity Snapshot", "3")
    dns_lines = _dns_query_snapshot()
    if dns_lines:
        print(f"  {C.DIM}Active DNS connections detected:{C.RESET}")
        for line in dns_lines[:10]:
            print(f"  {C.DIM}{line}{C.RESET}")
    else:
        print(f"  {C.DIM}No active DNS connections detected at this moment.{C.RESET}")
        print(f"  {C.DIM}DNS queries are typically short-lived and may not appear here.{C.RESET}")

    # ── 4. Live Traffic Capture (tcpdump)
    _section("Live Packet Capture (tcpdump)", "4")
    if _check_tcpdump():
        net = get_local_network()
        iface = net.interface or ""
        perms_ok = SYSNAME == "Windows"  # tcpdump on Windows usually needs WinPcap
        if not perms_ok:
            # Try a quick test
            test_r = _run(["tcpdump", "-c", "1", "-nn", "--immediate-mode"],
                           timeout=4, log_errors=False)
            perms_ok = test_r is not None and test_r.returncode == 0

        if perms_ok:
            print(f"  {C.DIM}Capturing 50 packets on interface '{iface or 'auto'}'…{C.RESET}")
            captured = _run_tcpdump_snapshot(iface, duration=8)
            if captured:
                # Summarise by protocol
                proto_counts: Dict[str, int] = {}
                for line in captured:
                    if " > " in line or " < " in line:
                        if "UDP" in line.upper() or ".53 " in line:
                            proto_counts["DNS/UDP"] = proto_counts.get("DNS/UDP", 0) + 1
                        elif "HTTP" in line or ".80 " in line or ".443 " in line:
                            proto_counts["HTTP/S"]  = proto_counts.get("HTTP/S", 0) + 1
                        elif ".22 " in line:
                            proto_counts["SSH"]     = proto_counts.get("SSH", 0) + 1
                        elif "ICMP" in line.upper():
                            proto_counts["ICMP"]    = proto_counts.get("ICMP", 0) + 1
                        elif "ARP" in line.upper():
                            proto_counts["ARP"]     = proto_counts.get("ARP", 0) + 1
                        else:
                            proto_counts["Other"]   = proto_counts.get("Other", 0) + 1
                print(f"  {C.BOLD}Protocol breakdown from {len(captured)} captured packets:{C.RESET}")
                for proto, cnt in sorted(proto_counts.items(), key=lambda x: -x[1]):
                    bar = "▓" * min(cnt * 2, 20)
                    print(f"    {C.CYAN}{proto:<14}{C.RESET}  {bar} {cnt}")
                print(f"\n  {C.DIM}First 10 packets:{C.RESET}")
                for line in captured[:10]:
                    print(f"  {C.DIM}{line}{C.RESET}")
            else:
                print(f"  {C.DIM}No packets captured (or interface has no traffic).{C.RESET}")
        else:
            print(f"  {C.YELLOW}tcpdump requires root/sudo for packet capture.{C.RESET}")
            print(f"  {C.DIM}Run: sudo python3 ghostlink_v3.py --module 9{C.RESET}")
    else:
        print(f"  {C.YELLOW}tcpdump not found.{C.RESET}")
        if SYSNAME == "Windows":
            print(f"  {C.DIM}Install Wireshark (includes WinPcap) from wireshark.org{C.RESET}")
        else:
            print(f"  {C.DIM}Install: sudo apt install tcpdump{C.RESET}")

    # ── 5. Wireshark Guidance
    _section("Traffic Analysis with Wireshark", "5")
    ws_found = _check_wireshark()
    if ws_found:
        _ok("Wireshark/tshark is installed on this system.")
    else:
        print(f"  {C.DIM}Wireshark not detected.{C.RESET}")
        if SYSNAME == "Windows":
            print(f"  {C.CYAN}Download: https://www.wireshark.org/download.html{C.RESET}")
        else:
            print(f"  {C.DIM}Install: sudo apt install wireshark tshark{C.RESET}")

    print(f"\n  {C.BOLD}Wireshark Filters Quick Reference:{C.RESET}")
    filters = [
        ("DNS queries",          "dns"),
        ("HTTP traffic",         "http"),
        ("HTTPS (TLS)",          "tls"),
        ("Your device only",     "ip.addr == <YOUR_IP>"),
        ("FTP (cleartext)",      "ftp"),
        ("Telnet (cleartext)",   "telnet"),
        ("ARP packets",          "arp"),
        ("ICMP (ping)",          "icmp"),
        ("SSH traffic",          "tcp.port == 22"),
        ("RDP sessions",         "tcp.port == 3389"),
        ("SMB traffic",          "smb or smb2"),
        ("Unusual ports",        "tcp.port > 1024 and not tcp.port == 8080"),
        ("Large packets (>1400)","frame.len > 1400"),
    ]
    for label, filt in filters:
        print(f"    {C.DIM}{label:<28}{C.RESET}  {C.CYAN}{filt}{C.RESET}")

    print(f"\n  {C.BOLD}Common Wireshark CLI (tshark) Commands:{C.RESET}")
    net = get_local_network()
    iface = net.interface or "eth0"
    cmds = [
        (f"tshark -i {iface} -a duration:30",         "Capture 30 seconds"),
        (f"tshark -i {iface} -Y dns -T fields -e dns.qry.name",
                                                        "Live DNS query names"),
        (f"tshark -i {iface} -Y 'http.request'",       "HTTP requests only"),
        (f"tshark -r capture.pcap -z io,phs",           "Protocol hierarchy stats"),
    ]
    for cmd, desc in cmds:
        print(f"    {C.DIM}{desc}:{C.RESET}")
        print(f"      {C.CYAN}{cmd}{C.RESET}")

    # ── 6. Switched Network Warning
    _section("Switched Network Limitations", "6")
    print(f"  {C.YELLOW}⚠{C.RESET}  {C.BOLD}Important:{C.RESET} On a switched network, you can only capture:")
    _bullet("Your own device's traffic (always visible)")
    _bullet("Broadcast/multicast packets (ARP, mDNS, etc.)")
    _bullet("Traffic mirrored via SPAN/port-mirror if configured on switch")
    print(f"\n  {C.DIM}To capture ALL LAN traffic:{C.RESET}")
    _bullet("Enable 'port mirroring' on your managed switch", C.CYAN)
    _bullet("Or use an inline network tap device",             C.CYAN)
    _bullet("Or capture directly on the router (if running OpenWrt)", C.CYAN)
    print()

# ──────────────────────────────────────────────────────────────────────────────
# ░░  Interactive menu
# ──────────────────────────────────────────────────────────────────────────────
MENU_ITEMS = [
    ("1", "Full Network Recon",           "Subnet sweep, ARP, port scan, banners, device types"),
    ("2", "My Device — Deep Info",        "All interfaces, IPv4/IPv6, DHCP, routing, active connections"),
    ("3", "Network Infrastructure",       "Gateway probe, DHCP range, NAT, traceroute"),
    ("4", "Wireless Analysis",            "SSID, BSSID, channel congestion, signal bars, nearby nets"),
    ("5", "Internet & External Identity", "Public IP, ISP, geolocation, DNS analysis, connectivity"),
    ("6", "Performance & Stability",      "Latency, jitter, packet-loss, path MTU, live quality bars"),
    ("7", "Network Resources & Sharing",  "SMB, NAS, printers, Plex, mDNS discovery"),
    ("8", "Security Insights",            "Encryption, rogue APs, risky ports, security score"),
    ("9", "Traffic Analysis",             "Connection breakdown, interface stats, tcpdump, Wireshark guide"),
    ("A", "Run All Modules",              "Execute all 9 modules back-to-back"),
    ("0", "Exit",                         ""),
]

def print_menu() -> None:
    print(f"\n{C.CYAN}{'═'*66}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  GHOSTLINK  v3  —  Network Intelligence & Analysis{C.RESET}")
    print(f"{C.CYAN}{'═'*66}{C.RESET}\n")
    for key, title, desc in MENU_ITEMS:
        if key == "0":
            print(f"  {C.DIM}[{key}] {title}{C.RESET}")
        elif key == "A":
            print(f"\n  {C.MAG}[{key}] {C.BOLD}{title}{C.RESET}")
        else:
            num_color = C.MAG if key == "9" else C.CYAN
            print(f"  {num_color}[{key}]{C.RESET} {C.BOLD}{title}{C.RESET}")
            if desc:
                print(f"       {C.DIM}{desc}{C.RESET}")
    print(f"\n{C.CYAN}{'─'*66}{C.RESET}")

def _run_module(choice: str) -> None:
    dispatch = {
        "1": lambda: print_recon_result(full_network_recon()),
        "2": scan_my_device,
        "3": scan_infrastructure,
        "4": scan_wireless,
        "5": scan_internet_identity,
        "6": scan_performance,
        "7": scan_resources,
        "8": scan_security,
        "9": scan_traffic,
    }
    if choice == "1":
        print(f"\n{C.DIM}Running full recon… this may take 30–120s.{C.RESET}")
    fn = dispatch.get(choice)
    if fn: fn()

def run_menu() -> None:
    while True:
        print_menu()
        try:
            choice = input(f"  {C.BOLD}Select option: {C.RESET}").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.DIM}Interrupted.{C.RESET}\n"); break
        if choice == "0":
            print(f"\n{C.DIM}Exiting GHOSTLINK. Stay secure.{C.RESET}\n"); break
        elif choice in [str(i) for i in range(1, 10)]:
            try:
                _run_module(choice)
            except KeyboardInterrupt:
                print(f"\n{C.YELLOW}[!] Module interrupted.{C.RESET}")
            input(f"\n  {C.DIM}Press Enter to return to menu…{C.RESET}")
        elif choice == "A":
            print(f"\n{C.MAG}Running all modules sequentially…{C.RESET}")
            for c in [str(i) for i in range(1, 10)]:
                try:
                    _run_module(c)
                except KeyboardInterrupt:
                    print(f"\n{C.YELLOW}[!] Skipping to next module.{C.RESET}")
            input(f"\n  {C.DIM}Press Enter to return to menu…{C.RESET}")
        else:
            print(f"  {C.RED}Invalid option.{C.RESET}")

# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="GHOSTLINK v3 — Network Reconnaissance & Intelligence")
    parser.add_argument("--module", "-m", type=str, default=None,
        choices=["1","2","3","4","5","6","7","8","9","A"],
        help="Run a specific module directly (skips interactive menu)")
    parser.add_argument("--no-banners", action="store_true",
        help="[Module 1] Skip banner grabbing")
    parser.add_argument("--nmap", action="store_true",
        help="[Module 1] Enable nmap OS/service detection")
    parser.add_argument("--no-ping-sweep", action="store_true",
        help="[Module 1] Skip ICMP ping sweep")
    parser.add_argument("--limit", type=int, default=50,
        help="[Module 1] Max devices to deep-scan (default: 50)")
    parser.add_argument("--port-timeout", type=float,
        default=DEFAULT_PORT_TIMEOUT,
        help=f"[Module 1] Per-port timeout in seconds (default: {DEFAULT_PORT_TIMEOUT})")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)

    if args.module:
        if args.module == "1":
            result = full_network_recon(
                grab_banners=not args.no_banners,
                use_nmap=args.nmap,
                do_ping_sweep=not args.no_ping_sweep,
                device_scan_limit=args.limit,
                port_timeout=args.port_timeout,
            )
            print_recon_result(result)
        elif args.module == "A":
            for c in [str(i) for i in range(1, 10)]:
                _run_module(c)
        else:
            _run_module(args.module)
    else:
        run_menu()

