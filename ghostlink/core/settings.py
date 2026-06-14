"""
Application settings persistence for GhostLink GUI.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path


SETTINGS_PATH = Path(".ghostlink_settings.json")


@dataclass
class GhostLinkSettings:
    theme: str = "Professional"
    default_scan_interval: int = 20
    default_report_format: str = "HTML"
    default_export_folder: str = "reports"
    safe_mode: bool = True
    require_authorization_before_audit: bool = True
    log_level: str = "Normal"
    table_density: str = "Comfortable"
    font_size: str = "Normal"
    demo_lab_mode: bool = False


class SettingsStore:
    def __init__(self, path: Path = SETTINGS_PATH):
        self.path = path
        self.settings = GhostLinkSettings()

    def load(self) -> GhostLinkSettings:
        if not self.path.exists():
            self.settings = GhostLinkSettings()
            return self.settings
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                self.settings = GhostLinkSettings()
                return self.settings
            defaults = asdict(GhostLinkSettings())
            merged = {**defaults, **data}
            self.settings = GhostLinkSettings(**merged)
        except Exception:
            self.settings = GhostLinkSettings()
        return self.settings

    def save(self, settings: GhostLinkSettings | None = None) -> None:
        if settings is not None:
            self.settings = settings
        self.path.write_text(
            json.dumps(asdict(self.settings), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def reset(self) -> GhostLinkSettings:
        self.settings = GhostLinkSettings()
        self.save(self.settings)
        return self.settings
