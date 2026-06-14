"""
Structured GhostLink logging with an AUDIT level.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path


AUDIT_LEVEL = 25
logging.addLevelName(AUDIT_LEVEL, "AUDIT")


class _SensitiveFilter(logging.Filter):
    _patterns = (
        re.compile(r"(?i)(password\s*[:=]\s*)(\S+)"),
        re.compile(r"(?i)(passphrase\s*[:=]\s*)(\S+)"),
        re.compile(r"(?i)(credential\s*[:=]\s*)(\S+)"),
    )

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern in self._patterns:
            msg = pattern.sub(r"\1***", msg)
        record.msg = msg
        record.args = ()
        return True


def setup_audit_logger(path: Path | str = Path("logs/ghostlink_audit.log")) -> logging.Logger:
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("ghostlink.audit")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(module)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(formatter)
    handler.addFilter(_SensitiveFilter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def audit(logger: logging.Logger, message: str) -> None:
    logger.log(AUDIT_LEVEL, message)
