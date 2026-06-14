"""
GhostLink version metadata.
Single source of truth for versioning across GUI, CLI, reports, and packaging.
"""

APP_NAME = "GhostLink"
APP_TAGLINE = "Authorized Wi-Fi Security Audit Toolkit"
APP_VERSION = "3.1.0"


def versioned_name() -> str:
    return f"{APP_NAME} v{APP_VERSION}"
