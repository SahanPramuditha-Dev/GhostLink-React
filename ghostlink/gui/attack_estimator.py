from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackEstimate:
    candidates: int
    est_seconds: float
    speed_per_sec: int


def calc_candidates(charset: str, minlen: int, maxlen: int) -> int:
    base = len(charset)
    if base == 0:
        return 0
    return sum(base ** n for n in range(max(1, minlen), maxlen + 1))


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}m"


def estimate_attack(charset: str, minlen: int, maxlen: int, threads: int, per_thread_rate: int = 500) -> AttackEstimate:
    total = calc_candidates(charset, minlen, maxlen)
    speed = max(0, threads) * max(1, per_thread_rate)
    est_s = (total / speed) if speed > 0 else 0.0
    return AttackEstimate(candidates=total, est_seconds=est_s, speed_per_sec=speed)
