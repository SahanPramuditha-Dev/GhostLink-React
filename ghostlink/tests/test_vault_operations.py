from pathlib import Path

from ghostlink.storage.vault import PasswordVault


def test_vault_set_get_remove(tmp_path: Path):
    vault = PasswordVault(tmp_path / "vault.json")
    vault.load()
    vault.set("HomeWiFi", "abc123", verified=True)
    assert vault.get("HomeWiFi") == "abc123"
    entries = vault.list_entries()
    assert entries and entries[0]["ssid"] == "HomeWiFi"
    vault.remove("HomeWiFi")
    assert vault.get("HomeWiFi") is None


def test_vault_lock_unlock(tmp_path: Path):
    vault = PasswordVault(tmp_path / "vault.json")
    assert vault.is_unlocked is True
    vault.lock()
    assert vault.is_unlocked is False
    assert vault.unlock("ignored") is True
    assert vault.is_unlocked is True
