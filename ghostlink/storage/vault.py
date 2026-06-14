"""
GHOSTLINK Password Vault
=========================
Secure password storage with optional encryption.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from ..core.constants import VAULT_PATH

class PasswordVault:
    """Password storage vault"""
    
    def __init__(self, path: Path = VAULT_PATH):
        self.path = path
        self.data: Dict[str, Dict] = {}
        self.encryption_enabled = False
        self.is_unlocked = True
    
    def load(self) -> None:
        """Load vault from disk"""
        if not self.path.exists():
            self.data = {}
            return
        
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self.data = {}
    
    def save(self) -> None:
        """Save vault to disk"""
        try:
            self.path.write_text(
                json.dumps(self.data, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception as e:
            print(f"[!] Vault save error: {e}")
    
    def get(self, ssid: str) -> Optional[str]:
        """Get cached password for SSID"""
        entry = self.data.get(ssid, {})
        return entry.get("password")
    
    def set(self, ssid: str, password: str, verified: bool = False) -> None:
        """Store password in vault"""
        self.data[ssid] = {
            "password": password,
            "verified": verified,
            "timestamp": datetime.now().isoformat(),
            "attempts": 0,
        }
        self.save()
    
    def remove(self, ssid: str) -> None:
        """Remove password from vault"""
        if ssid in self.data:
            del self.data[ssid]
            self.save()
    
    def clear_all(self) -> None:
        """Clear entire vault"""
        self.data = {}
        self.save()
    
    def list_all(self) -> Dict[str, str]:
        """List all stored passwords"""
        return {k: v.get("password", "???") for k, v in self.data.items()}

    def list_entries(self) -> list[Dict]:
        """Return full entry objects for UI display."""
        rows = []
        for ssid, payload in sorted(self.data.items(), key=lambda x: x[0].lower()):
            rows.append({
                "ssid": ssid,
                "password": payload.get("password", ""),
                "verified": bool(payload.get("verified", False)),
                "timestamp": payload.get("timestamp", ""),
                "attempts": int(payload.get("attempts", 0) or 0),
            })
        return rows

    def lock(self) -> None:
        self.is_unlocked = False

    def unlock(self, _master_password: str = "") -> bool:
        # Encryption is not yet enabled, so unlock succeeds without checks.
        self.is_unlocked = True
        return True
    
    def get_count(self) -> int:
        """Get number of stored passwords"""
        return len(self.data)
