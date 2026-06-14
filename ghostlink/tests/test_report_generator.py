from pathlib import Path

import ghostlink.storage.report as report_mod
from ghostlink.storage.report import ReportGenerator


def test_report_generation_outputs(tmp_path: Path):
    report_mod.REPORTS_DIR = tmp_path / "reports"
    out = tmp_path / "legacy_report.json"
    result = ReportGenerator.generate(
        config={"ssid": "TestWiFi", "charset": "0123", "minlen": 1, "maxlen": 2, "threads": 2, "timeout": 5},
        password="pass123",
        attempts=120,
        elapsed=12.5,
        verified=True,
        output_path=out,
        authorization={
            "tester_name": "Alice",
            "network_owner_or_organization": "Lab",
            "purpose_of_test": "Course demo",
            "date_time": "2026-05-17 10:00:00",
            "confirmed": "yes",
        },
        security_score={"score": 82, "label": "Good"},
        timeline=["Audit initialized", "Authorization confirmed"],
    )
    outputs = result["outputs"]
    assert Path(outputs["json"]).exists()
    assert Path(outputs["html"]).exists()
    assert Path(outputs["csv"]).exists()
    assert Path(outputs["legacy_json"]).exists()

    payload = result["report"]
    assert payload["authorization"]["tester_name"] == "Alice"
    assert payload["security_score"]["score"] == 82
