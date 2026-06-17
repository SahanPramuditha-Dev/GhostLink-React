"""
GHOSTLINK Report Storage
=========================
Secure report storage with JSON persistence.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

REPORT_PATH = Path("ghostlink_reports.json")


class ReportStorage:
    """Report storage manager"""

    def __init__(self, path: Path = REPORT_PATH):
        self.path = path
        self.reports: List[Dict] = []

    def load(self) -> None:
        """Load reports from disk"""
        if not self.path.exists():
            self.reports = []
            self.save()
            return

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                self.reports = data
        except Exception:
            self.reports = []

    def save(self) -> None:
        """Save reports to disk"""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self.reports, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception as e:
            print(f"[!] Report save error: {e}")

    def add_report(self, report: Dict) -> None:
        """Add a report to storage"""
        self.reports.append(report)
        self.save()

    def get_all(self) -> List[Dict]:
        """Get all reports"""
        return self.reports

    def clear_all(self) -> None:
        """Clear all reports"""
        self.reports = []
        self.save()
