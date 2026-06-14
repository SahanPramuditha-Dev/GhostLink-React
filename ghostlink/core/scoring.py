"""
Wi-Fi security scoring model.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityScore:
    score: int
    label: str
    findings: list[str]


def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def score_network(
    security: str,
    signal: int,
    congestion: str = "Clear",
    hidden_ssid: bool = False,
    wps_enabled: bool = False,
) -> SecurityScore:
    sec = (security or "").upper()
    congestion_up = (congestion or "").upper()

    score = 100
    findings: list[str] = []

    if "OPEN" in sec:
        score -= 62
        findings.append("Open network detected.")
    elif "WEP" in sec:
        score -= 45
        findings.append("Legacy WEP security detected.")
    elif "WPA3" in sec:
        score -= 2
        findings.append("WPA3 in use.")
    elif "WPA2" in sec:
        score -= 8
        findings.append("WPA2 in use.")
    elif "WPA" in sec:
        score -= 24
        findings.append("Older WPA mode detected.")
    else:
        score -= 30
        findings.append("Unknown encryption profile.")

    if signal >= 90:
        score -= 12
        findings.append("Very strong signal may increase external exposure.")
    elif signal >= 80:
        score -= 8
        findings.append("Strong signal has moderate exposure risk.")

    if congestion_up == "CROWDED":
        score -= 10
        findings.append("High channel congestion detected.")
    elif congestion_up == "BUSY":
        score -= 5
        findings.append("Moderate channel congestion detected.")

    if hidden_ssid:
        score -= 4
        findings.append("Hidden SSID observed (not a strong security control).")

    if wps_enabled:
        score -= 15
        findings.append("WPS appears enabled.")

    score = _clamp(score)
    if score >= 90:
        label = "Excellent"
    elif score >= 75:
        label = "Good"
    elif score >= 55:
        label = "Moderate Risk"
    elif score >= 35:
        label = "High Risk"
    else:
        label = "Critical"

    return SecurityScore(score=score, label=label, findings=findings)
