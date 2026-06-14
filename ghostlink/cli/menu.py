"""
GHOSTLINK Interactive Menu
===========================
Terminal-based interactive configuration menu.
(Now includes manual network scan – option 0)
"""

import sys
import time
from pathlib import Path
from typing import Dict

from ..core.colors import C
from ..core.utils import clear_terminal, is_admin, format_number
from ..core.constants import (DEFAULT_MINLEN, DEFAULT_MAXLEN,
                              DEFAULT_THREADS, DEFAULT_TIMEOUT,
                              DEFAULT_CHARSET, DEFAULT_REPORT,
                              VAULT_PATH, SCRIPT_VERSION)
from ..engine.profiles import PROFILES, get_profile, estimate_search_space
from ..network.scanner import WiFiScanner
from ..storage.vault import PasswordVault
from .spinner import Spinner


class InteractiveMenu:
    """Interactive configuration menu"""
    
    def __init__(self):
        self.config = self._default_config()
        self.vault = PasswordVault(VAULT_PATH)
        self.vault.load()
        self.running = True
        self.scanner = WiFiScanner()
    
    def _default_config(self) -> Dict:
        return {
            "ssid": None,
            "interface": None,
            "minlen": DEFAULT_MINLEN,
            "maxlen": DEFAULT_MAXLEN,
            "charset": DEFAULT_CHARSET,
            "wordlist": None,
            "threads": DEFAULT_THREADS,
            "timeout": DEFAULT_TIMEOUT,
            "skip_cached": True,
            "report": DEFAULT_REPORT,
            "force": False,
            "debug": False,
        }
    
    def run(self) -> Dict:
        """Run interactive menu, return config when ready"""
        while self.running:
            self._display()
            choice = input(f"  {C.GHOST_CYAN}GHOSTLINK > {C.RESET}").strip()
            self._handle(choice)
        return self.config
    
    def _display(self):
        clear_terminal()
        
        # ASCII art banner (same as main.py)
        banner = rf"""
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
        print(banner)
        
        admin = f"{C.GREEN}ADMIN{C.RESET}" if is_admin() else f"{C.RED}USER{C.RESET}"
        cached = self.vault.get_count()
        
        print(f"  Status: {admin} | Cached: {cached}")
        print(f"  " + "-" * 60)
        
        target = self.config['ssid'] if self.config['ssid'] else f"{C.DIM}Not selected{C.RESET}"
        charset_str = self.config['charset']
        if len(charset_str) > 40:
            charset_display = charset_str[:40] + "..."
        else:
            charset_display = charset_str
        
        print(f"  Target:   {target}")
        print(f"  Length:   {self.config['minlen']}-{self.config['maxlen']} | "
              f"Threads: {self.config['threads']} | "
              f"Timeout: {self.config['timeout']}s")
        print(f"  Charset:  {charset_display} ({len(charset_str)} chars)")
        
        wordlist_display = self.config['wordlist'].name if self.config['wordlist'] else 'None'
        print(f"  Wordlist: {wordlist_display}")
        
        menu_text = f"""
  [{C.GHOST_GREEN}0{C.RESET}]  Network Scan (when connected)
  [{C.GHOST_GREEN}1{C.RESET}]  Scan & Select Target
  [{C.GHOST_GREEN}2{C.RESET}]  Choose Audit Profile  
  [{C.GHOST_GREEN}3{C.RESET}]  Set Password Length
  [{C.GHOST_GREEN}4{C.RESET}]  Load Wordlist
  [{C.GHOST_GREEN}5{C.RESET}]  Threads & Timeout
  [{C.GHOST_GREEN}6{C.RESET}]  Vault ({cached} cached passwords)
  [{C.GHOST_GREEN}7{C.RESET}]  {C.GHOST_GREEN}{C.BOLD}START AUTHORIZED TEST{C.RESET}
  [{C.GHOST_GREEN}8{C.RESET}]  Help & Info
  [{C.GHOST_GREEN}9{C.RESET}]  Exit
"""
        print(menu_text)
    
    def _handle(self, choice: str):
        if choice == "0":
            self._network_scan()
        elif choice == "1":
            self._scan_networks()
        elif choice == "2":
            self._choose_profile()
        elif choice == "3":
            self._set_length()
        elif choice == "4":
            self._load_wordlist()
        elif choice == "5":
            self._set_threads_timeout()
        elif choice == "6":
            self._manage_vault()
        elif choice == "7":
            if self._start_attack():
                self.running = False
        elif choice == "8":
            self._show_help()
        elif choice == "9":
            self._exit()
        else:
            print(f"\n{C.YELLOW}[!] Invalid option: {choice}{C.RESET}")
            time.sleep(0.5)
    
    # ------------------------------------------------------------------
    # Option handlers (scan, profiles, etc.) – unchanged except for new _network_scan
    # ------------------------------------------------------------------
    def _network_scan(self):
        """Launch the full interactive reconnaissance menu."""
        print(f"\n{C.CYAN}[*] Launching GHOSTLINK Reconnaissance…{C.RESET}")
        try:
            from ..network.recon import run_menu
            run_menu()          # <-- this shows all 9 modules
        except Exception as e:
            print(f"{C.RED}[!] Reconnaissance failed: {e}{C.RESET}")
        input("\nPress Enter to return to GHOSTLINK main menu…")
    
    def _scan_networks(self):
        spinner = Spinner("Scanning wireless networks...")
        spinner.start()
        try:
            networks = self.scanner.scan()
        finally:
            spinner.stop()
        
        if not networks:
            print(f"\n{C.YELLOW}[!] No networks found.{C.RESET}")
            print(f"{C.DIM}  Make sure Wi-Fi is enabled and you have Administrator privileges.{C.RESET}")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n{C.GREEN}[+] Found {len(networks)} networks:{C.RESET}\n")
        print(f"  {'#':<4} {'SSID':<30} {'Signal':<15} {'Security':<12}")
        print(f"  {'-'*4} {'-'*30} {'-'*15} {'-'*12}")
        
        for i, net in enumerate(networks, 1):
            bars = "#" * (net.signal // 10) + "-" * (10 - net.signal // 10)
            cached = " [C]" if self.vault.get(net.ssid) else ""
            hidden = " [H]" if net.hidden else ""
            signal_color = C.GREEN if net.signal > 70 else C.YELLOW if net.signal > 30 else C.RED
            
            print(f"  {i:<4} {net.ssid:<30} {signal_color}{bars}{C.RESET} {net.signal:>3}%  "
                  f"{net.security:<12}{cached}{hidden}")
        
        try:
            sel = int(input(f"\n{C.CYAN}Select network number (or 0 to cancel): {C.RESET}").strip())
            if 1 <= sel <= len(networks):
                selected = networks[sel - 1]
                self.config["ssid"] = selected.ssid
                self.config["interface"] = selected.interface
                print(f"{C.GREEN}[+] Target set: {C.BOLD}{selected.ssid}{C.RESET}")
                print(f"    Security: {selected.security} | Signal: {selected.signal}%")
            elif sel == 0:
                print(f"{C.DIM}Selection cancelled.{C.RESET}")
            else:
                print(f"{C.YELLOW}[!] Invalid number.{C.RESET}")
        except ValueError:
            print(f"{C.YELLOW}[!] Invalid input.{C.RESET}")
        
        input("\nPress Enter to continue...")
    
    def _choose_profile(self):
        print(f"\n{C.BOLD}Available Audit Profiles:{C.RESET}\n")
        for pid, profile in PROFILES.items():
            desc_text = f"{profile.description} ({profile.size} characters)"
            print(f"  {C.GREEN}[{pid}]{C.RESET} {profile.icon} {C.BOLD}{profile.name}{C.RESET}")
            print(f"      {C.DIM}{desc_text}{C.RESET}")
        
        print(f"\n  {C.GREEN}[C]{C.RESET} Custom charset")
        print(f"  {C.GREEN}[M]{C.RESET} Mask test pattern (e.g., ?d?d?d?d?d?d?d?d)")
        
        ch = input(f"\n{C.CYAN}Choose profile [1-9] or C/M: {C.RESET}").strip().lower()
        
        if ch in PROFILES:
            profile = PROFILES[ch]
            self.config["charset"] = profile.charset
            print(f"{C.GREEN}[+] Profile set: {profile.name}{C.RESET}")
            cs_len = len(profile.charset)
            cs_display = profile.charset[:50]
            if cs_len > 50:
                cs_display += "..."
            print(f"    Charset: {cs_display}")
            print(f"    Size: {cs_len} characters")
        elif ch == 'c':
            custom = input(f"{C.CYAN}Enter custom charset: {C.RESET}").strip()
            if custom:
                self.config["charset"] = custom
                print(f"{C.GREEN}[+] Custom charset set ({len(custom)} characters){C.RESET}")
            else:
                print(f"{C.YELLOW}[!] No charset entered - keeping current.{C.RESET}")
        elif ch == 'm':
            mask = input(f"{C.CYAN}Enter mask (e.g., ?d?d?d?d?d?d?d?d): {C.RESET}").strip()
            if mask and "?" in mask:
                self.config["charset"] = mask
                print(f"{C.GREEN}[+] Mask set: {mask}{C.RESET}")
            else:
                print(f"{C.YELLOW}[!] Must contain at least one ? (e.g., ?d).{C.RESET}")
        else:
            print(f"{C.YELLOW}[!] Invalid choice.{C.RESET}")
        
        input("\nPress Enter to continue...")
    
    def _set_length(self):
        print(f"\n{C.BOLD}Password Length Configuration{C.RESET}\n")
        self.config["minlen"] = self._input_int("Minimum length", self.config["minlen"], 1, 12)
        self.config["maxlen"] = self._input_int("Maximum length", self.config["maxlen"], 1, 12)
        
        if self.config["minlen"] > self.config["maxlen"]:
            self.config["maxlen"] = self.config["minlen"]
            print(f"{C.YELLOW}[!] Adjusted max to match min{C.RESET}")
        
        charset = self.config["charset"]
        if "?" in charset:
            # mask – can't easily estimate
            total = 0
        else:
            total = sum(len(charset) ** i for i in range(self.config["minlen"], self.config["maxlen"] + 1))
        
        if total > 0:
            print(f"\n{C.CYAN}[i] Estimated search space: {C.BOLD}{format_number(total)}{C.RESET} combinations")
            if total > 1_000_000:
                print(f"{C.YELLOW}[!] Large search space - authorized test may take a long time!{C.RESET}")
        
        input("\nPress Enter to continue...")
    
    def _load_wordlist(self):
        print(f"\n{C.BOLD}Wordlist Configuration{C.RESET}\n")
        current = str(self.config['wordlist']) if self.config['wordlist'] else "None"
        print(f"Current wordlist: {current}")
        
        path_input = input(f"{C.CYAN}Enter path (or 'clear' to remove, Enter to keep): {C.RESET}").strip()
        if not path_input:
            print(f"{C.DIM}Keeping current wordlist.{C.RESET}")
        elif path_input.lower() == 'clear':
            self.config["wordlist"] = None
            print(f"{C.GREEN}[+] Wordlist cleared.{C.RESET}")
        else:
            p = Path(path_input)
            if p.exists() and p.is_file():
                self.config["wordlist"] = p
                print(f"{C.GREEN}[+] Wordlist loaded: {p.name}{C.RESET}")
                try:
                    with p.open('r', encoding='utf-8', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
                    print(f"    Contains approximately {format_number(line_count)} passwords")
                except:
                    pass
            else:
                print(f"{C.RED}[!] File not found: {path_input}{C.RESET}")
        
        input("\nPress Enter to continue...")
    
    def _set_threads_timeout(self):
        print(f"\n{C.BOLD}Performance Configuration{C.RESET}\n")
        self.config["threads"] = self._input_int("Number of threads", self.config["threads"], 1, 8)
        self.config["timeout"] = self._input_int("Connection timeout (seconds)", self.config["timeout"], 3, 30)
        
        print(f"\n{C.CYAN}[i] Configuration:{C.RESET}")
        print(f"    Threads: {self.config['threads']} (parallel attempts)")
        print(f"    Timeout: {self.config['timeout']}s (per attempt)")
        
        if self.config["threads"] > 4:
            print(f"{C.YELLOW}[!] High thread count may cause instability{C.RESET}")
        
        input("\nPress Enter to continue...")
    
    def _manage_vault(self):
        cached = self.vault.list_all()
        print(f"\n{C.BOLD}Password Vault{C.RESET}\n")
        
        if not cached:
            print(f"{C.DIM}No cached passwords.{C.RESET}")
            cache_status = "ENABLED" if not self.config["skip_cached"] else "DISABLED"
            color = C.GREEN if not self.config["skip_cached"] else C.YELLOW
            print(f"\nCurrent cache setting: {color}{cache_status}{C.RESET}")
            toggle = input(f"\n{C.CYAN}Toggle cache? [y/N]: {C.RESET}").strip().lower()
            if toggle == 'y':
                self.config["skip_cached"] = not self.config["skip_cached"]
                new_status = "ENABLED" if not self.config["skip_cached"] else "DISABLED"
                print(f"{C.GREEN}[+] Cache: {new_status}{C.RESET}")
            input("\nPress Enter to continue...")
            return
        
        print(f"{C.GHOST_YELLOW}Stored passwords:{C.RESET}\n")
        for ssid, pwd in cached.items():
            print(f"  {C.BOLD}{ssid:<30}{C.RESET} -> {pwd}")
        
        cache_status = "ENABLED" if not self.config["skip_cached"] else "DISABLED"
        color = C.GREEN if not self.config["skip_cached"] else C.YELLOW
        print(f"\nCache status: {color}{cache_status}{C.RESET}")
        
        print(f"\n{C.BOLD}Actions:{C.RESET}")
        print(f"  {C.GREEN}[C]{C.RESET} Clear all cached passwords")
        print(f"  {C.GREEN}[D]{C.RESET} Delete specific password")
        print(f"  {C.GREEN}[U]{C.RESET} Toggle use cache (enable/disable)")
        print(f"  {C.GREEN}[Enter]{C.RESET} Back")
        
        action = input(f"\n{C.CYAN}Action: {C.RESET}").strip().lower()
        if action == 'c':
            confirm = input(f"{C.YELLOW}Clear ALL cached passwords? [y/N]: {C.RESET}").strip().lower()
            if confirm == 'y':
                self.vault.clear_all()
                print(f"{C.GREEN}[+] Vault cleared{C.RESET}")
        elif action == 'd':
            ssid = input(f"{C.CYAN}SSID to delete: {C.RESET}").strip()
            if ssid and ssid in cached:
                self.vault.remove(ssid)
                print(f"{C.GREEN}[+] Removed: {ssid}{C.RESET}")
            else:
                print(f"{C.YELLOW}[!] SSID not found in vault{C.RESET}")
        elif action == 'u':
            self.config["skip_cached"] = not self.config["skip_cached"]
            new_status = "ENABLED" if not self.config["skip_cached"] else "DISABLED"
            print(f"{C.GREEN}[+] Cache: {new_status}{C.RESET}")
        
        input("\nPress Enter to continue...")
    
    def _start_attack(self) -> bool:
        print(f"\n{C.BOLD}Authorized Test Validation{C.RESET}\n")
        
        if not self.config["ssid"]:
            print(f"{C.RED}[!] No network selected!{C.RESET}")
            print(f"{C.DIM}Use option 1 to scan and select a network.{C.RESET}")
            input("\nPress Enter to continue...")
            return False
        
        if not is_admin():
            print(f"{C.RED}[!] Administrator privileges required!{C.RESET}")
            print(f"{C.DIM}Run this tool as Administrator for network access.{C.RESET}")
            input("\nPress Enter to continue...")
            return False
        
        charset = self.config["charset"]
        min_len = self.config["minlen"]
        max_len = self.config["maxlen"]
        
        if "?" in charset:
            total = 0   # mask
        else:
            total = sum(len(charset) ** i for i in range(min_len, max_len + 1))
        
        print(f"{'='*60}")
        print(f"  ATTACK CONFIGURATION SUMMARY")
        print(f"{'='*60}")
        print(f"  Target:      {C.BOLD}{self.config['ssid']}{C.RESET}")
        
        cs_display = charset[:40]
        if len(charset) > 40:
            cs_display += "..."
        print(f"  Charset:     {cs_display}")
        print(f"  Length:      {min_len} - {max_len}")
        
        if total > 0:
            print(f"  Search Space:{C.BOLD} {format_number(total)} {C.RESET}combinations")
        else:
            print(f"  Search Space: Mask-based")
        
        print(f"  Threads:     {self.config['threads']}")
        print(f"  Timeout:     {self.config['timeout']}s per attempt")
        
        wl_display = self.config['wordlist'].name if self.config['wordlist'] else 'None'
        print(f"  Wordlist:    {wl_display}")
        
        cache_display = "Yes" if not self.config['skip_cached'] else "No"
        print(f"  Use Cache:   {cache_display}")
        print(f"{'='*60}")
        
        if total > 0:
            rough_speed = 10 * self.config['threads']
            est_seconds = total / rough_speed
            if est_seconds < 60:
                est_time = f"{est_seconds:.0f} seconds"
            elif est_seconds < 3600:
                est_time = f"{est_seconds/60:.1f} minutes"
            elif est_seconds < 86400:
                est_time = f"{est_seconds/3600:.1f} hours"
            else:
                est_time = f"{est_seconds/86400:.1f} days"
            print(f"  Est. Time:   {est_time} (very rough)")
        
        print(f"{'='*60}")
        print(f"\n{C.YELLOW}WARNING: Only proceed if you have authorization!{C.RESET}\n")
        
        confirm = input(f"{C.GREEN}Start authorized test? Type 'YES' to confirm: {C.RESET}").strip()
        if confirm.upper() == "YES":
            print(f"\n{C.GREEN}[+] Authorized test confirmed. Starting...{C.RESET}")
            time.sleep(0.5)
            return True
        else:
            print(f"\n{C.YELLOW}[!] Authorized test cancelled.{C.RESET}")
            input("Press Enter to continue...")
            return False
    
    def _show_help(self):
        help_text = f"""
{'='*60}
  GHOSTLINK - Help & Information
{'='*60}

Quick Start Guide:
  1. Scan (1) - Find target networks
  2. Profile (2) - Choose audit type
  3. Length (3) - Set password range
  4. Start (7) - Launch authorized test

Other options:
  0 - Network Scan (when connected)
  5 - Threads & Timeout
  6 - Vault management

Audit Profiles:
  - Numeric (0-9) - Fastest, for number-only passwords
  - Lowercase (a-z) - For lowercase letter passwords
  - Alphanumeric - Good all-around coverage
  - Extended - Full coverage but slow
  - Mask - Custom pattern (e.g., ?d?d?d?d)

Tips:
  - Start with small search spaces for testing
  - Use Numeric + length 4-6 for quick results
  - Wordlists speed up common password detection
  - Vault stores found passwords for future use

IMPORTANT:
  - Requires Administrator/root privileges
  - For authorized testing only
  - Respect privacy and laws

{'='*60}
"""
        print(help_text)
        input("Press Enter to continue...")
    
    def _exit(self):
        print(f"\n{C.GHOST_CYAN}{C.BOLD}")
        print(f"    GHOSTLINK - Session Complete")
        print(f"{C.RESET}")
        sys.exit(0)
    
    def _input_int(self, prompt: str, default: int,
                   min_val: int = None, max_val: int = None) -> int:
        while True:
            try:
                val_str = input(f"{C.CYAN}{prompt} [{default}]: {C.RESET}").strip()
                if not val_str:
                    return default
                val = int(val_str)
                if min_val is not None and val < min_val:
                    print(f"{C.YELLOW}[!] Minimum value is {min_val}{C.RESET}")
                    continue
                if max_val is not None and val > max_val:
                    print(f"{C.YELLOW}[!] Maximum value is {max_val}{C.RESET}")
                    continue
                return val
            except ValueError:
                print(f"{C.YELLOW}[!] Please enter a valid number{C.RESET}")
