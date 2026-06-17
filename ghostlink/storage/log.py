"""
GHOSTLINK Log Storage
======================
Log storage with JSON persistence.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

LOG_PATH = Path("ghostlink_logs.json")


class LogStorage:
    """Log storage manager"""

    def __init__(self, path: Path = LOG_PATH):
        self.path = path
        self.logs: List[str] = []

    def load(self) -> None:
        """Load logs from disk"""
        if not self.path.exists():
            self.logs = []
            self.save()
            return

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                self.logs = data
        except Exception:
            self.logs = []

    def save(self) -> None:
        """Save logs to disk"""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self.logs, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception as e:
            print(f"[!] Log save error: {e}")

    def add_log(self, message: str) -> None:
        """Add a log entry"""
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{ts}] {message}")
        # Keep only last 1000 logs
        self.logs = self.logs[-1000:]
        self.save()

    def get_all(self) -> List[str]:
        """Get all logs"""
        return self.logs

    def clear_all(self) -> None:
        """Clear all logs"""
        self.logs = []
        self.save()
