import subprocess

from ghostlink.network import scanner as scanner_mod
from ghostlink.network.scanner import WiFiScanner


def test_list_interfaces_windows_parsing(monkeypatch):
    sample = """
    Name                   : Wi-Fi
    Description            : Adapter
    Name                   : Wi-Fi 2
    """

    def fake_run_cmd(_cmd, timeout=10):
        return subprocess.CompletedProcess(_cmd, 0, sample, "")

    monkeypatch.setattr(scanner_mod, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(scanner_mod.platform, "system", lambda: "Windows")
    ifaces = WiFiScanner.list_interfaces()
    assert "Wi-Fi" in ifaces
    assert "Wi-Fi 2" in ifaces
