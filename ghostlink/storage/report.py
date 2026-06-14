"""
GhostLink report generation and export helpers.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.constants import DEFAULT_REPORT, REPORTS_DIR
from ..core.recommendations import recommendations_for_audit_result
from ..core.version import APP_NAME, APP_TAGLINE, APP_VERSION


DISCLAIMER = (
    "This report is intended only for authorized Wi-Fi security assessments. "
    "Testing without ownership or written permission may violate policy and law."
)


def _json_dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _safe_name(text: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in text).strip("_") or "network"


class ReportGenerator:
    """Authorized audit report generator."""

    @staticmethod
    def _build_report_payload(
        config: dict[str, Any],
        password: str,
        attempts: int,
        elapsed: float,
        verified: bool,
        authorization: dict[str, Any] | None = None,
        scan_summary: dict[str, Any] | None = None,
        selected_network: dict[str, Any] | None = None,
        security_score: dict[str, Any] | None = None,
        findings: list[str] | None = None,
        recommendations: list[str] | None = None,
        timeline: list[str] | None = None,
        checklist: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        now = datetime.now()
        findings = findings or []
        recommendations = recommendations or recommendations_for_audit_result(bool(verified and password), bool(password))
        timeline = timeline or []
        checklist = checklist or []

        network_block = selected_network or {
            "ssid": config.get("ssid", "Unknown"),
            "bssid": config.get("target_bssid", ""),
            "security": config.get("security", "Unknown"),
            "channel": config.get("channel", 0),
            "band": config.get("band", "Unknown"),
            "signal": config.get("signal", 0),
        }

        report = {
            "cover": {
                "title": APP_NAME,
                "subtitle": APP_TAGLINE,
                "generated_at": now.isoformat(),
            },
            "tool": APP_NAME,
            "version": APP_VERSION,
            "authorization": authorization or {},
            "scan_summary": scan_summary or {},
            "selected_network": network_block,
            "security_score": security_score or {},
            "audit_configuration": {
                "charset_size": len(config.get("charset", "")),
                "length_range": f"{config.get('minlen', 0)}-{config.get('maxlen', 0)}",
                "threads": config.get("threads", 0),
                "timeout": config.get("timeout", 0),
                "wordlist": str(config.get("wordlist", "None")),
                "wordlist_inline_count": len(config.get("wordlist_inline") or []),
                "skip_cached": bool(config.get("skip_cached", True)),
            },
            "audit_progress": {
                "attempts": attempts,
                "elapsed_seconds": round(elapsed, 2),
                "speed_per_second": round(attempts / max(elapsed, 0.001), 2),
            },
            "result": {
                "credential_match_detected": bool(password and verified),
                "weak_credential_verified": bool(password and verified),
                "credential": password if verified else "Not verified",
                "verified": bool(verified),
            },
            "findings": findings,
            "recommendations": recommendations,
            "timeline": timeline,
            "checklist": checklist,
            "disclaimer": DISCLAIMER,
        }
        return report

    @staticmethod
    def _report_basename(report: dict[str, Any]) -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ssid = report.get("selected_network", {}).get("ssid", "network")
        return f"ghostlink_{_safe_name(str(ssid))}_{stamp}"

    @staticmethod
    def _to_html(report: dict[str, Any]) -> str:
        def _kv_rows(block: dict[str, Any]) -> str:
            rows = []
            for k, v in block.items():
                rows.append(f"<tr><th>{k}</th><td>{v}</td></tr>")
            return "".join(rows) or "<tr><td colspan='2'>No data</td></tr>"

        recs = "".join(f"<li>{r}</li>" for r in report.get("recommendations", [])) or "<li>No recommendations.</li>"
        finds = "".join(f"<li>{f}</li>" for f in report.get("findings", [])) or "<li>No findings.</li>"
        timeline = "".join(f"<li>{x}</li>" for x in report.get("timeline", [])) or "<li>No timeline entries.</li>"
        checklist_rows = "".join(
            f"<tr><td>{i.get('item', '')}</td><td>{i.get('status', '')}</td></tr>"
            for i in report.get("checklist", [])
        ) or "<tr><td colspan='2'>No checklist entries.</td></tr>"

        return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{APP_NAME} Report</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#f7fafc; color:#1f2937; margin:24px; }}
    h1,h2 {{ margin: 0 0 8px 0; }}
    .card {{ background:#fff; border:1px solid #dbe4ef; border-radius:8px; padding:14px; margin:10px 0; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border:1px solid #e5e7eb; padding:8px; text-align:left; font-size: 13px; }}
    th {{ width: 240px; background:#f3f4f6; }}
    .muted {{ color:#6b7280; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>{APP_NAME}</h1>
  <div class="muted">{APP_TAGLINE} · v{APP_VERSION}</div>
  <div class="card"><strong>Disclaimer:</strong> {report.get("disclaimer", DISCLAIMER)}</div>
  <div class="card"><h2>Authorization</h2><table>{_kv_rows(report.get("authorization", {}))}</table></div>
  <div class="card"><h2>Scan Summary</h2><table>{_kv_rows(report.get("scan_summary", {}))}</table></div>
  <div class="card"><h2>Selected Network</h2><table>{_kv_rows(report.get("selected_network", {}))}</table></div>
  <div class="card"><h2>Security Score</h2><table>{_kv_rows(report.get("security_score", {}))}</table></div>
  <div class="card"><h2>Audit Configuration</h2><table>{_kv_rows(report.get("audit_configuration", {}))}</table></div>
  <div class="card"><h2>Audit Progress</h2><table>{_kv_rows(report.get("audit_progress", {}))}</table></div>
  <div class="card"><h2>Findings</h2><ul>{finds}</ul></div>
  <div class="card"><h2>Recommendations</h2><ul>{recs}</ul></div>
  <div class="card"><h2>Timeline</h2><ul>{timeline}</ul></div>
  <div class="card"><h2>Audit Checklist</h2>
    <table><tr><th>Item</th><th>Status</th></tr>{checklist_rows}</table>
  </div>
</body>
</html>"""

    @staticmethod
    def _to_csv_rows(report: dict[str, Any]) -> list[list[str]]:
        rows: list[list[str]] = [["section", "key", "value"]]
        for section in ("authorization", "scan_summary", "selected_network", "security_score", "audit_configuration", "audit_progress", "result"):
            block = report.get(section, {})
            if isinstance(block, dict):
                for k, v in block.items():
                    rows.append([section, str(k), str(v)])
        for finding in report.get("findings", []):
            rows.append(["finding", "", str(finding)])
        for rec in report.get("recommendations", []):
            rows.append(["recommendation", "", str(rec)])
        for tl in report.get("timeline", []):
            rows.append(["timeline", "", str(tl)])
        for item in report.get("checklist", []):
            rows.append(["checklist", str(item.get("item", "")), str(item.get("status", ""))])
        return rows

    @staticmethod
    def _write_pdf_if_available(report: dict[str, Any], out_path: Path) -> bool:
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.units import inch
            from reportlab.pdfgen import canvas
        except Exception:
            return False

        c = canvas.Canvas(str(out_path), pagesize=letter)
        width, height = letter
        y = height - inch
        line_h = 14

        def line(text: str, step: int = 1):
            nonlocal y
            if y < inch:
                c.showPage()
                y = height - inch
            c.drawString(inch, y, text[:120])
            y -= line_h * step

        line(f"{APP_NAME} - {APP_TAGLINE}")
        line(f"Version: {APP_VERSION}")
        line(f"Generated: {report.get('cover', {}).get('generated_at', '')}", 2)
        for heading in ("authorization", "scan_summary", "selected_network", "security_score", "audit_configuration", "audit_progress", "result"):
            line(heading.upper(), 1)
            for k, v in (report.get(heading, {}) or {}).items():
                line(f"  {k}: {v}")
            line("", 1)
        line("Findings:")
        for finding in report.get("findings", []):
            line(f"  - {finding}")
        line("Recommendations:")
        for rec in report.get("recommendations", []):
            line(f"  - {rec}")
        line(f"Disclaimer: {report.get('disclaimer', DISCLAIMER)}", 2)
        c.save()
        return True

    @staticmethod
    def generate(
        config: dict[str, Any],
        password: str,
        attempts: int,
        elapsed: float,
        verified: bool = True,
        output_path: Path = DEFAULT_REPORT,
        authorization: dict[str, Any] | None = None,
        scan_summary: dict[str, Any] | None = None,
        selected_network: dict[str, Any] | None = None,
        security_score: dict[str, Any] | None = None,
        findings: list[str] | None = None,
        recommendations: list[str] | None = None,
        timeline: list[str] | None = None,
        checklist: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Generate a report package (JSON + HTML + CSV + optional PDF)."""
        report = ReportGenerator._build_report_payload(
            config=config,
            password=password,
            attempts=attempts,
            elapsed=elapsed,
            verified=verified,
            authorization=authorization,
            scan_summary=scan_summary,
            selected_network=selected_network,
            security_score=security_score,
            findings=findings,
            recommendations=recommendations,
            timeline=timeline,
            checklist=checklist,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        _json_dump(output_path, report)  # backward-compatible file

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        base = ReportGenerator._report_basename(report)
        json_path = REPORTS_DIR / f"{base}.json"
        html_path = REPORTS_DIR / f"{base}.html"
        csv_path = REPORTS_DIR / f"{base}.csv"
        pdf_path = REPORTS_DIR / f"{base}.pdf"

        _json_dump(json_path, report)
        html_path.write_text(ReportGenerator._to_html(report), encoding="utf-8")
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(ReportGenerator._to_csv_rows(report))

        pdf_created = ReportGenerator._write_pdf_if_available(report, pdf_path)
        outputs: dict[str, str] = {
            "json": str(json_path),
            "html": str(html_path),
            "csv": str(csv_path),
            "legacy_json": str(output_path),
        }
        if pdf_created:
            outputs["pdf"] = str(pdf_path)

        return {"report": report, "outputs": outputs}

    @staticmethod
    def list_reports(directory: Path = REPORTS_DIR) -> list[Path]:
        if not directory.exists():
            return []
        return sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    @staticmethod
    def load_report(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def display_summary(password: str, attempts: int, elapsed: float, verified: bool, ssid: str) -> None:
        print()
        if password and verified:
            print("=" * 60)
            print("  WEAK CREDENTIAL VERIFIED")
            print("=" * 60)
        else:
            print("=" * 60)
            print("  AUTHORIZED TEST COMPLETE - NO CREDENTIAL MATCH")
            print("=" * 60)
        print(f"  SSID:      {ssid}")
        if password:
            print(f"  Credential:{password}")
        print(f"  Attempts:  {attempts:,}")
        print(f"  Time:      {elapsed:.1f}s")
        if elapsed > 0:
            print(f"  Speed:     {attempts/elapsed:.1f} checks/s")
        print(f"  Verified:  {'Yes' if verified else 'No'}")
