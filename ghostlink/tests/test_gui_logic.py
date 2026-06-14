from ghostlink.gui.scan_logic import (
    channel_to_band,
    risk_label,
    status_label,
    calc_scan_summary,
)
from ghostlink.gui.recon_parser import classify_line, looks_like_table_header, parse_recon_output
from ghostlink.gui.attack_estimator import estimate_attack, format_duration


def test_channel_to_band():
    assert channel_to_band(1) == "2.4 GHz"
    assert channel_to_band(36) == "5 GHz"
    assert channel_to_band(0) == "Unknown"


def test_risk_label():
    assert risk_label(80, "OPEN") == "HIGH"
    assert risk_label(20, "WPA2-PSK") == "LOW"
    assert risk_label(80, "WPA2-PSK") == "MED"


def test_status_label_delta_and_new():
    s = status_label(
        bssid="aa:bb:cc:dd:ee:ff",
        signal=70,
        compare_enabled=True,
        prev_by_bssid={"aa:bb:cc:dd:ee:ff": {"signal": 60}},
        new_bssids=set(),
        seen_at={},
    )
    assert s == "Seen +10%"


def test_calc_scan_summary():
    class N:
        def __init__(self, signal, security):
            self.signal = signal
            self.security = security

    summary = calc_scan_summary([N(80, "OPEN"), N(30, "WPA2"), N(75, "WPA3")])
    assert summary == {"total": 3, "open": 1, "secure": 2, "strong": 2}


def test_recon_classify_and_table_header():
    assert classify_line("WARN low disk")[0] == "WARN"
    assert looks_like_table_header("Name   Status   Details") is True
    assert looks_like_table_header("192.168.1.1   up") is False


def test_parse_recon_output_basic():
    out = "INFO start\nInterface: Wi-Fi\nName   State\nwlan0   up"
    recs = parse_recon_output(out)
    kinds = [r["kind"] for r in recs]
    assert "line" in kinds
    assert "kv" in kinds
    assert "table_header" in kinds or "table_row" in kinds


def test_attack_estimator():
    est = estimate_attack("01", 1, 3, 2, per_thread_rate=10)
    assert est.candidates == 14
    assert est.speed_per_sec == 20
    assert format_duration(est.est_seconds).endswith("s")
