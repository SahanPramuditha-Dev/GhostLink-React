from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable
from pathlib import Path
import json


@dataclass(frozen=True)
class ScanSnapshot:
    bssid: str
    signal: int


def channel_to_band(channel: int) -> str:
    if channel >= 36:
        return "5 GHz"
    if 1 <= channel <= 14:
        return "2.4 GHz"
    return "Unknown"


_OUI_CACHE: dict[str, str] | None = None


def _load_optional_oui_db() -> dict[str, str]:
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    built_in = {
        "00:1A:11": "Cisco",
        "00:26:5A": "Apple",
        "3C:84:6A": "TP-Link",
        "D8:0D:17": "Huawei",
        "F4:F2:6D": "Samsung",
        "FC:FB:FB": "Google",
        "B8:27:EB": "RPi",
        "9C:3D:CF": "Xiaomi",
        "50:C7:BF": "TP-Link",
        "EC:08:6B": "TP-Link",
        "18:D6:C7": "Apple",
        "AC:37:43": "HTC",
    }
    db_path = Path(__file__).with_name("oui_vendors.json")
    if db_path.exists():
        try:
            raw = json.loads(db_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                built_in.update({str(k).upper(): str(v) for k, v in raw.items()})
        except Exception:
            pass
    _OUI_CACHE = built_in
    return _OUI_CACHE


def vendor_from_bssid(bssid: str) -> str:
    oui = (bssid or "").upper().replace("-", ":")
    if len(oui) < 8:
        return "Unknown"
    vendors = _load_optional_oui_db()
    return vendors.get(oui[:8], "Unknown")


def risk_label(signal: int, security: str) -> str:
    sec = (security or "").upper()
    score = 0
    if "OPEN" in sec:
        score += 2
    elif "WPA2" in sec:
        score += 1
    if signal >= 70:
        score += 1
    if score >= 3:
        return "HIGH"
    if score == 2:
        return "MED"
    return "LOW"


def status_label(
    bssid: str,
    signal: int,
    compare_enabled: bool,
    prev_by_bssid: dict[str, dict[str, int]],
    new_bssids: set[str],
    seen_at: dict[str, datetime],
) -> str:
    key = (bssid or "").strip().lower()
    if compare_enabled and key and key in prev_by_bssid:
        prev_signal = int(prev_by_bssid[key].get("signal", signal))
        delta = signal - prev_signal
        if abs(delta) >= 3:
            sign = "+" if delta > 0 else ""
            return f"Seen {sign}{delta}%"
    if key in new_bssids:
        return "NEW now"
    ts = seen_at.get(key)
    if not ts:
        return "Seen now"
    return f"Seen {ts.strftime('%H:%M:%S')}"


def congestion_map(networks: Iterable) -> dict[int, str]:
    counts: dict[int, int] = {}
    for net in networks:
        ch = int(getattr(net, "channel", 0) or 0)
        if ch > 0:
            counts[ch] = counts.get(ch, 0) + 1
    return {ch: ("Crowded" if c >= 4 else "Busy" if c >= 2 else "Clear") for ch, c in counts.items()}


def calc_scan_summary(networks: Iterable) -> dict[str, int]:
    rows = list(networks)
    return {
        "total": len(rows),
        "open": sum(1 for n in rows if "OPEN" in (getattr(n, "security", "") or "").upper()),
        "secure": sum(1 for n in rows if any(k in (getattr(n, "security", "") or "").upper() for k in ("WPA2", "WPA3"))),
        "strong": sum(1 for n in rows if int(getattr(n, "signal", 0) or 0) > 70),
    }
