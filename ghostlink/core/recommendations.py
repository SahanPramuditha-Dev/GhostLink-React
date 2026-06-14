"""
Recommendation engine for scan and audit findings.
"""

from __future__ import annotations


def recommendations_for_network(
    security: str,
    signal: int,
    congestion: str = "Clear",
    wps_enabled: bool = False,
    hidden_ssid: bool = False,
) -> list[str]:
    recs: list[str] = []
    sec = (security or "").upper()
    congestion_up = (congestion or "").upper()

    if "OPEN" in sec:
        recs.append("Enable WPA2-AES or WPA3 encryption immediately.")
    elif "WEP" in sec or sec == "WPA":
        recs.append("Upgrade router security mode to WPA2-AES or WPA3.")
    elif "WPA2" in sec and "WPA3" not in sec:
        recs.append("Consider enabling WPA3 if all client devices support it.")
    elif "UNKNOWN" in sec or not sec.strip():
        recs.append("Validate encryption settings from router admin panel.")

    if signal >= 85:
        recs.append("Reduce transmit power if coverage exceeds required area.")

    if congestion_up == "CROWDED":
        recs.append("Move to a less crowded Wi-Fi channel.")
    elif congestion_up == "BUSY":
        recs.append("Monitor channel usage and consider channel adjustment.")

    if wps_enabled:
        recs.append("Disable WPS to reduce credential attack surface.")

    if hidden_ssid:
        recs.append("Do not rely on hidden SSID as a primary security control.")

    if not recs:
        recs.append("Maintain current settings and review firmware updates regularly.")
    return recs


def recommendations_for_audit_result(verified: bool, credential_match: bool) -> list[str]:
    if credential_match and verified:
        return [
            "Rotate Wi-Fi passphrase to a longer unique value.",
            "Audit connected devices and remove unknown clients.",
            "Review router admin credentials and firmware status.",
        ]
    return [
        "Continue periodic authorized testing with updated wordlists.",
        "Keep WPA2/WPA3 enabled and maintain firmware updates.",
    ]
