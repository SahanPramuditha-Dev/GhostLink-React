"""
GHOSTLINK Core Constants
=========================
All configuration constants and default values.
"""

import os
from pathlib import Path
from .version import APP_VERSION, APP_NAME

# System
SYSTEM = os.name  # 'nt' for Windows, 'posix' for Linux/Mac
CPU_COUNT = os.cpu_count() or 4

# Default Values
DEFAULT_THREADS = min(CPU_COUNT, 8)
DEFAULT_TIMEOUT = 10
DEFAULT_MAXLEN = 6
DEFAULT_MINLEN = 1
DEFAULT_CHARSET = "0123456789"

# File Paths
DEFAULT_REPORT = Path("ghostlink_report.json")
REPORTS_DIR = Path("reports")
DEFAULT_STATE = Path(".ghostlink_state.json")
VAULT_PATH = Path(".ghostlink_vault.json")
PATTERNS_PATH = Path(".ghostlink_patterns.json")
SETTINGS_PATH = Path(".ghostlink_settings.json")

# Alias
STATE_FILE = DEFAULT_STATE

# Version
SCRIPT_VERSION = APP_VERSION
SCRIPT_CODENAME = APP_NAME.upper()

# Threading
MAX_THREADS = 8
MIN_THREADS = 1

# Timeouts
MIN_TIMEOUT = 3
MAX_TIMEOUT = 30
SCAN_TIMEOUT = 15
