#!/usr/bin/env python3
"""
GHOSTLINK - Main Entry Point
=============================
Wi-Fi Security Testing Framework
"""
import time
import re
import sys
import argparse
from dataclasses import dataclass
from pathlib import Path
from datetime import timedelta
from typing import Optional

from .core.colors import C
from .core.utils import is_admin, format_number
from .core.constants import (
    DEFAULT_MINLEN, DEFAULT_MAXLEN, DEFAULT_THREADS,
    DEFAULT_TIMEOUT, DEFAULT_CHARSET, DEFAULT_REPORT,
    VAULT_PATH, SCRIPT_VERSION,
)
from .engine.profiles import PROFILES
from .engine.attack import BruteForceEngine
from .storage.vault import PasswordVault
from .storage.report import ReportGenerator
from .cli.menu import InteractiveMenu


# ─────────────────────────────────────────────────────────────
#  Audit result wrapper (engine returns a tuple)
# ─────────────────────────────────────────────────────────────
@dataclass
class AttackResult:
    password: Optional[str]
    attempts: int
    elapsed: float
    verified: bool

    @property
    def success(self) -> bool:
        return self.password is not None and self.verified


# ─────────────────────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────────────────────
BANNER = rf"""
{C.GHOST_CYAN}{C.BOLD}
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗     ██╗███╗   ██╗██╗  ██╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║     ██║████╗  ██║██║ ██╔╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██║     ██║██╔██╗ ██║█████╔╝
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██║██║╚██╗██║██╔═██╗
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████╗██║██║ ╚████║██║  ██╗
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
{C.RESET}{C.DIM}                   Wi-Fi Security Testing Framework  v{SCRIPT_VERSION}{C.RESET}
{C.GHOST_CYAN}  {'─' * 70}{C.RESET}
"""


# ─────────────────────────────────────────────────────────────
#  Display helpers
# ─────────────────────────────────────────────────────────────

_BOX_WIDTH = 60
_LINE = "─" * _BOX_WIDTH


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _box_row(content: str, border_color: str = C.GHOST_CYAN) -> str:
    """Wrap content in a fixed-width bordered row."""
    visible = _strip_ansi(content)
    pad = max(_BOX_WIDTH - len(visible), 0)
    return f"{border_color}│{C.RESET}{content}{' ' * pad}{border_color}│{C.RESET}"


def _row(label: str, value: str, value_color: str = "") -> str:
    """Return one padded table row."""
    reset = C.RESET if value_color else ""
    content = f"  {C.BOLD}{label:<12}{C.RESET}  {value_color}{value}{reset}"
    return _box_row(content, C.GHOST_CYAN)


def display_success(result: AttackResult, ssid: str) -> None:
    """Render a well-formatted success summary box."""
    elapsed_td  = str(timedelta(seconds=int(result.elapsed)))
    speed_str   = f"{result.attempts / max(result.elapsed, 0.001):,.1f} pwd/s"
    attempts_str = f"{result.attempts:,}"
    verified_str = "Yes ✓" if result.verified else "No"
    verified_clr = C.GREEN if result.verified else C.RED

    print(f"\n{C.GHOST_CYAN}┌{_LINE}┐{C.RESET}")
    print(_box_row(f"  {C.BOLD}{C.GREEN}WEAK CREDENTIAL VERIFIED{C.RESET}", C.GHOST_CYAN))
    print(f"{C.GHOST_CYAN}├{_LINE}┤{C.RESET}")
    print(_row("SSID",     ssid))
    print(_row("Credential", result.password,  C.GREEN))
    print(_row("Attempts", attempts_str))
    print(_row("Time",     f"{elapsed_td}  ({result.elapsed:.1f}s)"))
    print(_row("Speed",    speed_str))
    print(_row("Verified", verified_str, verified_clr))
    print(f"{C.GHOST_CYAN}└{_LINE}┘{C.RESET}\n")


def display_failure(result: AttackResult) -> None:
    """Render a clean failure summary box."""
    elapsed_td   = str(timedelta(seconds=int(result.elapsed)))
    speed_str    = f"{result.attempts / max(result.elapsed, 0.001):,.1f} pwd/s"
    attempts_str = f"{result.attempts:,}"

    print(f"\n{C.RED}┌{_LINE}┐{C.RESET}")
    print(_box_row(f"  {C.BOLD}{C.RED}NO CREDENTIAL MATCH{C.RESET}", C.RED))
    print(f"{C.RED}├{_LINE}┤{C.RESET}")
    print(_box_row(f"  {C.BOLD}{'Attempts':<12}{C.RESET}  {attempts_str}", C.RED))
    print(_box_row(f"  {C.BOLD}{'Time':<12}{C.RESET}  {elapsed_td}", C.RED))
    print(_box_row(f"  {C.BOLD}{'Speed':<12}{C.RESET}  {speed_str}", C.RED))
    print(f"{C.RED}└{_LINE}┘{C.RESET}\n")


def _section(title: str) -> None:
    """Print a subtle section divider."""
    print(f"\n{C.DIM}  ┄┄  {title}  {'┄' * max(40 - len(title), 4)}{C.RESET}")


# ─────────────────────────────────────────────────────────────
#  Argument parser
# ─────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"GHOSTLINK v{SCRIPT_VERSION} – Wi-Fi Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python run.py\n"
            "  python run.py --ssid MyWiFi --profile 1 --minlen 4 --maxlen 8\n"
            "  python run.py --ssid MyWiFi --charset 0123456789 --wordlist ~/lists.txt"
        ),
    )

    target = parser.add_argument_group("Target")
    target.add_argument("--ssid",      type=str,  help="Target network SSID")
    target.add_argument("--interface", type=str,  help="Wireless interface to use (e.g. wlan0)")

    attack = parser.add_argument_group("Audit options")
    attack.add_argument("--profile",  type=str,  choices=list(PROFILES.keys()),
                        help="Built-in audit profile (overrides --charset)")
    attack.add_argument("--charset",  type=str,  help="Custom charset string")
    attack.add_argument("--minlen",   type=int,  default=DEFAULT_MINLEN,  metavar="N")
    attack.add_argument("--maxlen",   type=int,  default=DEFAULT_MAXLEN,  metavar="N")
    attack.add_argument("--wordlist", type=Path, help="Path to wordlist file")
    attack.add_argument("--threads",  type=int,  default=DEFAULT_THREADS,
                        metavar="N", help="Number of concurrent workers")
    attack.add_argument("--timeout",  type=int,  default=DEFAULT_TIMEOUT,
                        metavar="SEC", help="Per-attempt connection timeout")

    misc = parser.add_argument_group("Misc")
    misc.add_argument("--use-cache", action="store_true",
                      help="Test cached password before brute-forcing")
    misc.add_argument("--force",     action="store_true",
                      help="Skip admin-privilege check (use with caution)")
    misc.add_argument("--debug",     action="store_true",
                      help="Enable verbose debug output")

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
#  Config builder
# ─────────────────────────────────────────────────────────────

def _build_config(args: argparse.Namespace) -> dict:
    if args.profile and args.profile in PROFILES:
        charset = PROFILES[args.profile].charset
    elif args.charset:
        charset = args.charset
    else:
        charset = DEFAULT_CHARSET

    return {
        "ssid":        args.ssid,
        "minlen":      args.minlen,
        "maxlen":      args.maxlen,
        "charset":     charset,
        "wordlist":    args.wordlist,
        "threads":     args.threads,          # ← now included
        "timeout":     args.timeout,
        "skip_cached": not args.use_cache,
        "force":       args.force,
        "debug":       args.debug,
        "interface":   getattr(args, "interface", None),
        "report":      DEFAULT_REPORT,
    }


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────

def main() -> None:
    print(BANNER)

    args = parse_args()

    # ── Interactive mode when no SSID is given ──────────────────────────
    if not args.ssid:
        try:
            config = InteractiveMenu().run()
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[!] Interrupted. Goodbye.{C.RESET}\n")
            sys.exit(0)
    else:
        config = _build_config(args)

    # ── Guard: valid SSID ───────────────────────────────────────────────
    if not config.get("ssid"):
        print(f"{C.RED}[!] No SSID specified. Aborting.{C.RESET}")
        sys.exit(1)

    # ── Guard: admin privileges ─────────────────────────────────────────
    if not config.get("force") and not is_admin():
        print(f"{C.RED}[!] Administrator privileges are required.{C.RESET}")
        print(f"{C.DIM}    Run as Administrator, or pass --force to skip this check.{C.RESET}")
        sys.exit(1)

    # ── Vault ───────────────────────────────────────────────────────────
    vault = PasswordVault(VAULT_PATH)
    vault.load()

    # ── Pre-flight summary ──────────────────────────────────────────────
    _section("Audit Configuration")
    print(f"  {C.DIM}SSID     :{C.RESET}  {config['ssid']}")
    print(f"  {C.DIM}Charset  :{C.RESET}  {config['charset'][:40]}"
          f"{'...' if len(config['charset']) > 40 else ''}  ({len(config['charset'])} chars)")
    print(f"  {C.DIM}Length   :{C.RESET}  {config['minlen']}–{config['maxlen']}")
    if config.get("wordlist"):
        print(f"  {C.DIM}Wordlist :{C.RESET}  {config['wordlist']}")
    print(f"  {C.DIM}Threads  :{C.RESET}  {config['threads']}")
    print(f"  {C.DIM}Timeout  :{C.RESET}  {config['timeout']}s per attempt")

    # ── Run engine ──────────────────────────────────────────────────────
    _section("Initiating Authorized Test Sequence")
    engine = BruteForceEngine(config, vault)

    try:
        # The engine returns a tuple: (password, attempts, elapsed, verified)
        pwd, attempts, elapsed, verified = engine.execute()
        result = AttackResult(pwd, attempts, elapsed, verified)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Authorized test interrupted by user.{C.RESET}")
        print(f"{C.DIM}Progress has been saved for resume.{C.RESET}")
        sys.exit(0)
    except RuntimeError as exc:
        print(f"\n{C.RED}[!] Engine error: {exc}{C.RESET}")
        sys.exit(1)

    # ── Results ─────────────────────────────────────────────────────────
    if result.success:
        display_success(result, config["ssid"])

        _section("Saving Report")
        try:
            ReportGenerator.generate(config, result.password, result.attempts,
                                     result.elapsed, result.verified)
            print(f"  {C.GREEN}[+] Report saved.{C.RESET}")
        except Exception as exc:
            print(f"  {C.YELLOW}[!] Report generation failed: {exc}{C.RESET}")

        # ── Offer network reconnaissance ─────────────────────────────────
        print()
        time.sleep(0.5)   # ← wait for dashboard to fully die
        choice = input(f"{C.CYAN}Run network reconnaissance? [Y/n]: {C.RESET}").strip().lower()
        if choice in ('', 'y'):
            try:
                from .network.recon import run_menu
                run_menu()
            except Exception as e:
                print(f"{C.RED}[!] Reconnaissance failed: {e}{C.RESET}")

    else:
        display_failure(result)
        print(f"  {C.DIM}Tip: try a larger wordlist, extended charset, or different length range.{C.RESET}\n")


if __name__ == "__main__":
    main()
