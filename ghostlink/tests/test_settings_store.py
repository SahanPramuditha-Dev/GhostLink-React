from pathlib import Path

from ghostlink.core.settings import SettingsStore, GhostLinkSettings


def test_settings_save_and_load(tmp_path: Path):
    settings_path = tmp_path / "settings.json"
    store = SettingsStore(settings_path)
    data = GhostLinkSettings(
        theme="Dark",
        default_scan_interval=42,
        default_report_format="JSON",
        default_export_folder="out",
        safe_mode=False,
        require_authorization_before_audit=False,
        log_level="Debug",
        table_density="Compact",
        font_size="Large",
        demo_lab_mode=True,
    )
    store.save(data)
    loaded = store.load()
    assert loaded.theme == "Dark"
    assert loaded.default_scan_interval == 42
    assert loaded.demo_lab_mode is True


def test_settings_reset(tmp_path: Path):
    settings_path = tmp_path / "settings.json"
    store = SettingsStore(settings_path)
    store.save(GhostLinkSettings(theme="Cyber"))
    reset = store.reset()
    assert reset.theme == "Professional"
