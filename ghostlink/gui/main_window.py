import sys
import os
import ctypes
import io
import re
import html as html_mod
import csv
import json
from pathlib import Path
from datetime import datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QSpinBox, QLineEdit, QCheckBox,
    QTextEdit, QProgressBar, QGroupBox, QFormLayout, QMessageBox,
    QFileDialog, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QSplitter, QScrollArea, QApplication,
    QDialog, QMenu, QListWidget, QListWidgetItem, QAbstractItemView,
    QGraphicsOpacityEffect,
)
from PySide6.QtCore import Qt, QTimer, QRect, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup, QPoint, QEvent
from PySide6.QtGui import QFont, QTextCursor, QIcon, QKeySequence, QShortcut

from ghostlink.engine.profiles import PROFILES
from ghostlink.core.constants import (
    DEFAULT_MINLEN, DEFAULT_MAXLEN, DEFAULT_THREADS, DEFAULT_TIMEOUT, VAULT_PATH,
)
from ghostlink.core.version import APP_NAME, APP_TAGLINE, APP_VERSION
from ghostlink.core.scoring import score_network
from ghostlink.core.recommendations import recommendations_for_network
from ghostlink.core.settings import SettingsStore, GhostLinkSettings
from ghostlink.core.audit_log import setup_audit_logger, audit
from .workers import ScanWorker, AttackWorker, ReconWorker
from ghostlink.network.scanner import WiFiScanner, ScanResult
from ghostlink.storage.vault import PasswordVault
from ghostlink.storage.report import ReportGenerator
from .scan_logic import (
    channel_to_band,
    vendor_from_bssid,
    risk_label,
    status_label,
    congestion_map,
    calc_scan_summary,
)
from .recon_parser import (
    ReconRecord,
    parse_recon_output,
    classify_line,
    looks_like_table_header,
    split_into_lines,
    strip_ansi,
    split_table_cols,
)
from .attack_estimator import estimate_attack, format_duration


# ---------------------------------------------------------------------------
# Authorization Gate
# ---------------------------------------------------------------------------

class AuthorizationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authorization Confirmation")
        self.setModal(True)
        self.setMinimumWidth(520)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        intro = QLabel(
            "I confirm that I own this network or have written permission to test it."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("font-weight:700;color:#9bd4ff;")
        root.addWidget(intro)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.tester_name = QLineEdit()
        self.owner_org = QLineEdit()
        self.purpose = QLineEdit()
        self.date_time = QLineEdit(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.date_time.setReadOnly(True)
        self.confirm_check = QCheckBox("I confirm authorized use.")
        form.addRow("Tester Name:", self.tester_name)
        form.addRow("Owner / Organization:", self.owner_org)
        form.addRow("Purpose:", self.purpose)
        form.addRow("Date / Time:", self.date_time)
        form.addRow("", self.confirm_check)
        root.addLayout(form)

        warning = QLabel(
            "Only run authorized tests. Unauthorized access attempts are prohibited."
        )
        warning.setWordWrap(True)
        warning.setProperty("role", "meta")
        root.addWidget(warning)

        btns = QHBoxLayout()
        btns.addStretch()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("variant", "secondary")
        self.cancel_btn.clicked.connect(self.reject)
        self.confirm_btn = QPushButton("Confirm Authorization")
        self.confirm_btn.setProperty("variant", "success")
        self.confirm_btn.setEnabled(False)
        self.confirm_btn.clicked.connect(self.accept)
        btns.addWidget(self.cancel_btn)
        btns.addWidget(self.confirm_btn)
        root.addLayout(btns)

        self.confirm_check.toggled.connect(self._refresh_state)
        self.tester_name.textChanged.connect(self._refresh_state)
        self.owner_org.textChanged.connect(self._refresh_state)
        self.purpose.textChanged.connect(self._refresh_state)

    def _refresh_state(self):
        valid = bool(
            self.confirm_check.isChecked()
            and self.tester_name.text().strip()
            and self.owner_org.text().strip()
            and self.purpose.text().strip()
        )
        self.confirm_btn.setEnabled(valid)

    def data(self) -> dict[str, str]:
        return {
            "confirmation_statement": "I confirm that I own this network or have written permission to test it.",
            "tester_name": self.tester_name.text().strip(),
            "network_owner_or_organization": self.owner_org.text().strip(),
            "purpose_of_test": self.purpose.text().strip(),
            "date_time": self.date_time.text().strip(),
            "confirmed": "yes" if self.confirm_check.isChecked() else "no",
        }


# ---------------------------------------------------------------------------
# MainWindow
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1280, 800)
        self.setMinimumSize(800, 560)
        self.setFont(QFont("Segoe UI", 10))
        self.setWindowIcon(QIcon("ghostlink.ico"))

        self.settings_store = SettingsStore()
        self.settings: GhostLinkSettings = self.settings_store.load()
        self.vault = PasswordVault(VAULT_PATH)
        self.vault.load()
        self.authorization_record: dict[str, str] = {}
        self.last_audit_timestamp: str = "-"
        self.last_scan_timestamp: str = "-"
        self.last_report_outputs: dict[str, str] = {}
        self.audit_timeline: list[str] = []
        self.reports_cache: list[Path] = []
        self.current_report_path: Path | None = None
        self.demo_lab_mode = bool(self.settings.demo_lab_mode)
        self.audit_logger = setup_audit_logger()

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ State ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        self.scan_results: list[ScanResult] = []
        self.config = {
            "ssid": None,
            "interface": None,
            "charset": "0123456789",
            "minlen": DEFAULT_MINLEN,
            "maxlen": DEFAULT_MAXLEN,
            "threads": DEFAULT_THREADS,
            "timeout": DEFAULT_TIMEOUT,
            "wordlist": None,
            "skip_cached": True,
        }
        self.attack_worker: AttackWorker | None = None
        self.worker: ScanWorker | ReconWorker | None = None
        self.total_combinations = 0
        self._scan_auto_timer = QTimer(self)
        self._scan_auto_timer.timeout.connect(self._on_auto_rescan_tick)
        self._scan_auto_enabled = False
        self._last_selected_bssid = ""
        self._scan_seen_at: dict = {}
        self._scan_new_bssids: set = set()
        self._scan_cycle = 0
        self._scan_prev_by_bssid: dict = {}
        self._pulse_new_on = False
        self._scan_density_mode = "comfortable"
        self._scan_compare_enabled = True
        self._scan_pulse_timer = QTimer(self)
        self._scan_pulse_timer.timeout.connect(self._tick_new_pulse)
        self._scan_pulse_timer.start(700)
        self._recon_records: list[ReconRecord] = []
        self._recon_filter_mode = "all"
        self._recon_collapse_sections = False
        self.filtered_scan_results: list[ScanResult] = []
        self.active_scan_filter = "all"
        self.page_index: dict[str, int] = {}
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.timeout.connect(self._apply_scan_filters_now)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Build UI ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        shell = QWidget()
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self._create_chrome_bar())

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        self.sidebar = self._create_sidebar_nav()
        body_layout.addWidget(self.sidebar)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(False)
        self.tabs.setElideMode(Qt.ElideNone)
        self.tabs.tabBar().hide()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        body_layout.addWidget(self.tabs, 1)
        shell_layout.addWidget(body, 1)

        self.setCentralWidget(shell)

        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_network_details_tab()
        self.create_attack_tab()
        self.create_progress_tab()
        self.create_recon_tab()
        self.create_reports_tab()
        self.create_vault_tab()
        self.create_settings_tab()
        self.create_help_tab()
        self._build_sidebar_items()
        self.tabs.setCurrentIndex(self.page_index["dashboard"])

        self.apply_theme()
        self.statusBar().showMessage("System ready")

        # Deferred scan hint (after window shown)
        self._scan_hint_shown = False
        QTimer.singleShot(400, self._maybe_show_scan_hints)
        self._install_shortcuts()
        self._apply_settings_to_ui()
        self.refresh_reports_list()
        self.refresh_vault_view()
        self.refresh_log_viewer()
        self.update_dashboard()

    def _install_shortcuts(self):
        find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        find_shortcut.activated.connect(self._focus_scan_search)
        self._find_shortcut = find_shortcut

    def _focus_scan_search(self):
        if hasattr(self, "scan_search_edit"):
            self.tabs.setCurrentIndex(self.page_index.get("scan", 0))
            self.scan_search_edit.setFocus()
            self.scan_search_edit.selectAll()

    # ---------------------------------------------------------------------------
    # Responsive layout system
    # ---------------------------------------------------------------------------

    def resizeEvent(self, event):
        super().resizeEvent(event)
        narrow = self.width() < 950
        if not hasattr(self, "_last_narrow") or self._last_narrow != narrow:
            self._last_narrow = narrow
            self._apply_responsive_layout(narrow)

    def _apply_responsive_layout(self, narrow: bool):
        """Switches layouts between compact (narrow) and wide modes."""
        # --- Scan tab header: stack stats vertically when narrow ---
        if hasattr(self, "_scan_header_row") and hasattr(self, "_scan_stats_row"):
            hdr = self._scan_header_row
            stats = self._scan_stats_row
            if narrow:
                # Remove stats from header row and move to below it if not already
                if stats.parent() == hdr.parent():
                    for i in range(stats.count()):
                        w = stats.itemAt(i)
                        if w and w.widget():
                            w.widget().setMaximumWidth(16777215)
            else:
                for attr in ["scan_total_label", "scan_open_label", "scan_secure_label", "scan_strong_label"]:
                    if hasattr(self, attr):
                        getattr(self, attr).setMaximumWidth(200)

        # --- Scan filter buttons: wrap text when narrow ---
        for key in ["all", "strong", "open", "secure", "band5"]:
            if hasattr(self, "scan_filter_buttons"):
                btn = self.scan_filter_buttons.get(key)
                if btn:
                    btn.setMinimumWidth(40 if narrow else 60)

        # --- Recon splitter orientation ---
        if hasattr(self, "_recon_splitter"):
            orientation = Qt.Vertical if narrow else Qt.Horizontal
            if self._recon_splitter.orientation() != orientation:
                self._recon_splitter.setOrientation(orientation)
                if narrow:
                    self._recon_splitter.setSizes([180, 400])
                else:
                    self._recon_splitter.setSizes([200, 900])

        # --- Recon sidebar width ---
        if hasattr(self, "_recon_sidebar_outer"):
            if narrow:
                self._recon_sidebar_outer.setMinimumWidth(0)
                self._recon_sidebar_outer.setMaximumWidth(16777215)
            else:
                self._recon_sidebar_outer.setFixedWidth(200)

        # --- Attack tab grid: 1 column when narrow ---
        if hasattr(self, "_attack_grid"):
            grid = self._attack_grid
            # Re-arrange: 1 col narrow, 2 col wide
            # widgets in order: pg, wg, eg, xg, checklist_box, estimate_frame
            widgets = []
            for r in range(grid.rowCount()):
                for c in range(grid.columnCount()):
                    item = grid.itemAtPosition(r, c)
                    if item and item.widget() and item.widget() not in [w for w in widgets]:
                        widgets.append((item.widget(), grid.itemAtPosition(r, c)))
            # Only rebuild if needed; avoid repeated rebuilds
            current_cols = grid.columnCount()
            if narrow and current_cols > 1:
                # Remove all and re-add in single column
                items = []
                for r in range(grid.rowCount()):
                    for c in range(grid.columnCount()):
                        item = grid.itemAtPosition(r, c)
                        if item and item.widget():
                            w = item.widget()
                            if w not in items:
                                items.append(w)
                for w in items:
                    grid.removeWidget(w)
                for i, w in enumerate(items):
                    grid.addWidget(w, i, 0, 1, 1)
                grid.setColumnStretch(0, 1)
                grid.setColumnStretch(1, 0)
            elif not narrow and current_cols == 1 and hasattr(self, "_attack_grid_widgets"):
                ws = self._attack_grid_widgets
                for w in ws:
                    grid.removeWidget(w)
                if len(ws) >= 4:
                    grid.addWidget(ws[0], 0, 0); grid.addWidget(ws[1], 0, 1)
                    grid.addWidget(ws[2], 1, 0); grid.addWidget(ws[3], 1, 1)
                    if len(ws) > 4:
                        grid.addWidget(ws[4], 2, 0, 1, 2)
                    if len(ws) > 5:
                        grid.addWidget(ws[5], 3, 0, 1, 2)
                grid.setColumnStretch(0, 1); grid.setColumnStretch(1, 1)

    def _clear_layout(self, layout):
        """Recursively remove all items from a layout without deleting widgets."""
        if layout is None:
            return
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
            elif item.layout() is not None:
                self._clear_layout(item.layout())

    def _create_sidebar_nav(self) -> QWidget:
        panel = QFrame()
        panel.setMinimumWidth(170)
        panel.setMaximumWidth(240)
        panel.setProperty("role", "side_nav_panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        brand = QFrame()
        brand.setObjectName("sidebar_brand")
        bl = QVBoxLayout(brand)
        bl.setContentsMargins(12, 10, 12, 10)
        bl.setSpacing(3)
        title = QLabel(APP_NAME)
        title.setProperty("role", "sidebar_title")
        subtitle = QLabel("Authorized Audit Toolkit")
        subtitle.setProperty("role", "sidebar_sub")
        version = QLabel(f"v{APP_VERSION}")
        version.setProperty("role", "sidebar_badge")
        bl.addWidget(title)
        bl.addWidget(subtitle)
        bl.addWidget(version, 0, Qt.AlignLeft)
        layout.addWidget(brand)

        self.nav_list = QListWidget()
        self.nav_list.setProperty("role", "side_nav")
        self.nav_list.setObjectName("side_nav")
        self.nav_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.nav_list.setMouseTracking(True)
        self.nav_list.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.nav_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav_list.setFrameShape(QFrame.NoFrame)
        self.nav_list.setSpacing(3)
        self.nav_list.currentRowChanged.connect(self._switch_page_from_sidebar)
        self.nav_list.viewport().installEventFilter(self)
        layout.addWidget(self.nav_list, 1)

        self.nav_glow = QFrame(self.nav_list.viewport())
        self.nav_glow.setObjectName("nav_glow")
        self.nav_glow.hide()
        self.nav_glow.lower()
        self._nav_indicator_anim = QPropertyAnimation(self.nav_glow, b"geometry", self)
        self._nav_indicator_anim.setDuration(240)
        self._nav_indicator_anim.setEasingCurve(QEasingCurve.OutCubic)
        return panel

    def _build_sidebar_items(self):
        self.nav_list.blockSignals(True)
        self.nav_list.clear()
        entries = [
            ("dashboard", "[D] Dashboard"),
            ("scan", "[S] Scan Networks"),
            ("network_details", "[N] Network Details"),
            ("audit_config", "[A] Audit Configuration"),
            ("audit_progress", "[P] Audit Progress"),
            ("intelligence", "[I] Network Intelligence"),
            ("reports", "[R] Reports"),
            ("vault", "[V] Vault"),
            ("settings", "[T] Settings"),
            ("help", "[H] Help / Learning"),
        ]
        for idx, (key, label) in enumerate(entries):
            self.page_index[key] = idx
            item = QListWidgetItem(label)
            self.nav_list.addItem(item)
        self.nav_list.setCurrentRow(self.tabs.currentIndex())
        self._animate_sidebar_indicator(self.tabs.currentIndex(), immediate=True)
        self.nav_list.blockSignals(False)

    def _switch_page_from_sidebar(self, row: int):
        if row < 0:
            return
        self._animate_sidebar_indicator(row)
        if row < self.tabs.count():
            self.tabs.setCurrentIndex(row)

    def _sync_sidebar_selection(self, index: int):
        if not hasattr(self, "nav_list"):
            return
        if 0 <= index < self.nav_list.count():
            self.nav_list.blockSignals(True)
            self.nav_list.setCurrentRow(index)
            self.nav_list.blockSignals(False)
            self._animate_sidebar_indicator(index)

    def _on_tab_changed(self, index: int):
        self._sync_sidebar_selection(index)
        self._animate_page_in(index)

    def _animate_page_in(self, index: int):
        if index < 0 or index >= self.tabs.count():
            return
        page = self.tabs.widget(index)
        if page is None:
            return
        effect = page.graphicsEffect()
        if not isinstance(effect, QGraphicsOpacityEffect):
            effect = QGraphicsOpacityEffect(page)
            page.setGraphicsEffect(effect)
        effect.setOpacity(0.0)
        fade = QPropertyAnimation(effect, b"opacity", page)
        fade.setDuration(220)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setEasingCurve(QEasingCurve.OutCubic)
        page._fade_anim = fade
        fade.start()

    def _animate_sidebar_indicator(self, row: int, immediate: bool = False):
        if not hasattr(self, "nav_list") or not hasattr(self, "nav_glow"):
            return
        if row < 0 or row >= self.nav_list.count():
            return
        item = self.nav_list.item(row)
        if item is None:
            return
        rect = self.nav_list.visualItemRect(item)
        if rect.isNull():
            return
        target = QRect(rect.left() + 2, rect.top() + 1, max(40, rect.width() - 4), max(24, rect.height() - 2))
        if not self.nav_glow.isVisible() or immediate:
            self.nav_glow.setGeometry(target)
            self.nav_glow.show()
            return
        self._nav_indicator_anim.stop()
        self._nav_indicator_anim.setStartValue(self.nav_glow.geometry())
        self._nav_indicator_anim.setEndValue(target)
        self._nav_indicator_anim.start()

    def _show_toast(self, message: str, level: str = "info", timeout_ms: int = 2400):
        color_map = {
            "info": ("#0b2742", "#00b8ff"),
            "success": ("#0d2e1b", "#22c55e"),
            "warning": ("#36240a", "#f59e0b"),
            "error": ("#340f17", "#f43f5e"),
        }
        bg, fg = color_map.get(level, color_map["info"])
        toast = QLabel(message, self)
        toast.setStyleSheet(
            f"QLabel{{background:{bg};color:{fg};border:1px solid {fg};"
            "border-radius:8px;padding:8px 12px;font-weight:700;}}"
        )
        toast.adjustSize()
        w = toast.width()
        x = max(16, self.width() - w - 20)
        y = 54
        toast.move(x + 26, y)
        opacity = QGraphicsOpacityEffect(toast)
        opacity.setOpacity(0.0)
        toast.setGraphicsEffect(opacity)
        toast.show()

        in_group = QParallelAnimationGroup(toast)
        pos_in = QPropertyAnimation(toast, b"pos", toast)
        pos_in.setDuration(220)
        pos_in.setStartValue(QPoint(x + 26, y))
        pos_in.setEndValue(QPoint(x, y))
        pos_in.setEasingCurve(QEasingCurve.OutCubic)
        op_in = QPropertyAnimation(opacity, b"opacity", toast)
        op_in.setDuration(220)
        op_in.setStartValue(0.0)
        op_in.setEndValue(1.0)
        op_in.setEasingCurve(QEasingCurve.OutCubic)
        in_group.addAnimation(pos_in)
        in_group.addAnimation(op_in)
        toast._in_group = in_group
        in_group.start()

        def _dismiss():
            out_group = QParallelAnimationGroup(toast)
            pos_out = QPropertyAnimation(toast, b"pos", toast)
            pos_out.setDuration(180)
            pos_out.setStartValue(toast.pos())
            pos_out.setEndValue(toast.pos() + QPoint(0, -10))
            pos_out.setEasingCurve(QEasingCurve.InCubic)
            op_out = QPropertyAnimation(opacity, b"opacity", toast)
            op_out.setDuration(180)
            op_out.setStartValue(1.0)
            op_out.setEndValue(0.0)
            op_out.setEasingCurve(QEasingCurve.InCubic)
            out_group.addAnimation(pos_out)
            out_group.addAnimation(op_out)
            out_group.finished.connect(toast.deleteLater)
            toast._out_group = out_group
            out_group.start()

        QTimer.singleShot(timeout_ms, _dismiss)

    def _log_event(self, level: str, message: str):
        lvl = (level or "INFO").upper()
        if lvl == "AUDIT":
            audit(self.audit_logger, message)
            return
        if lvl == "DEBUG":
            self.audit_logger.debug(message)
            return
        if lvl == "WARNING":
            self.audit_logger.warning(message)
            return
        if lvl == "ERROR":
            self.audit_logger.error(message)
            return
        self.audit_logger.info(message)

    def _apply_settings_to_ui(self):
        if hasattr(self, "auto_rescan_interval"):
            self.auto_rescan_interval.setValue(int(self.settings.default_scan_interval))
        if hasattr(self, "density_combo"):
            idx = self.density_combo.findText(self.settings.table_density, Qt.MatchFixedString)
            if idx >= 0:
                self.density_combo.setCurrentIndex(idx)
        font_size_map = {"Small": 9, "Normal": 10, "Large": 11}
        self.setFont(QFont("Segoe UI", font_size_map.get(self.settings.font_size, 10)))
        self.apply_theme()
        self._apply_table_density()
        self.demo_lab_mode = bool(self.settings.demo_lab_mode)
        if hasattr(self, "demo_mode_check"):
            self.demo_mode_check.setChecked(self.demo_lab_mode)
        if hasattr(self, "demo_mode_badge"):
            self.demo_mode_badge.setVisible(self.demo_lab_mode)
        if hasattr(self, "_load_settings_form_values"):
            self._load_settings_form_values()

    def _collect_dashboard_recommendations(self) -> list[str]:
        if not self.scan_results:
            return [
                "Run a network scan to discover nearby Wi-Fi and generate recommendations.",
                "Select a target network before starting an authorized audit.",
            ]
        congestion = self._congestion_map(self.scan_results)
        seen: set[str] = set()
        recs: list[str] = []
        for net in self.scan_results:
            ch = int(net.channel or 0)
            for item in self._recommendations_for_network(net, congestion.get(ch, "Clear")):
                if item not in seen:
                    seen.add(item)
                    recs.append(item)
        return recs[:10]

    def _dashboard_network_rows(self) -> list[dict[str, Any]]:
        congestion = self._congestion_map(self.scan_results)
        rows: list[dict[str, Any]] = []
        for net in self.scan_results:
            ch = int(net.channel or 0)
            cong = congestion.get(ch, "Clear")
            score_result = self._score_for_network(net, cong)
            risk = self._risk_label(int(net.signal or 0), net.security or "")
            rows.append(
                {
                    "net": net,
                    "score": score_result.score,
                    "label": score_result.label,
                    "risk": risk,
                }
            )
        return rows

    def update_dashboard(self):
        if not hasattr(self, "dash_cards"):
            return
        summary = calc_scan_summary(self.scan_results)
        total = summary["total"]
        open_n = summary["open"]
        secure = summary["secure"]
        strong = summary["strong"]
        reports_n = len(self.reports_cache)
        rows = self._dashboard_network_rows()
        scores = [row["score"] for row in rows]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        threats = sum(
            1 for row in rows if row["risk"] == "HIGH" or int(row["score"]) < 55
        )

        self.dash_cards["networks"].setText(str(total))
        self.dash_cards["open"].setText(str(open_n))
        self.dash_cards["secured"].setText(str(secure))
        self.dash_cards["strong"].setText(str(strong))
        self.dash_cards["last_scan"].setText(self.last_scan_timestamp)
        self.dash_cards["last_audit"].setText(self.last_audit_timestamp)
        self.dash_cards["reports"].setText(str(reports_n))
        self.dash_cards["threats"].setText(str(threats))
        self.dash_cards["score"].setText(f"{avg_score}/100" if scores else "-")

        if hasattr(self, "dash_score_value"):
            self.dash_score_value.setText(f"{avg_score}" if scores else "-")
        if hasattr(self, "dash_score_bar"):
            self.dash_score_bar.setValue(int(round(avg_score)) if scores else 0)
        if hasattr(self, "dash_score_label"):
            if not scores:
                label, tone = "Awaiting scan", "neutral"
            elif avg_score >= 90:
                label, tone = "Excellent posture", "success"
            elif avg_score >= 75:
                label, tone = "Good overall security", "success"
            elif avg_score >= 55:
                label, tone = "Moderate risk detected", "warning"
            elif avg_score >= 35:
                label, tone = "High risk environment", "warning"
            else:
                label, tone = "Critical issues found", "danger"
            self.dash_score_label.setText(label)
            self._set_tone(self.dash_score_label, tone)

        open_pct = int(round(open_n / total * 100)) if total else 0
        secure_pct = int(round(secure / total * 100)) if total else 0
        risk_pct = int(round(threats / total * 100)) if total else 0
        if hasattr(self, "dash_open_bar"):
            self.dash_open_bar.setValue(open_pct)
            self.dash_open_pct.setText(f"{open_pct}%")
        if hasattr(self, "dash_secure_bar"):
            self.dash_secure_bar.setValue(secure_pct)
            self.dash_secure_pct.setText(f"{secure_pct}%")
        if hasattr(self, "dash_risk_bar"):
            self.dash_risk_bar.setValue(risk_pct)
            self.dash_risk_pct.setText(f"{risk_pct}%")

        if hasattr(self, "dash_open_label"):
            open_tone = "warning" if open_n > 0 else "success"
            self._set_tone(self.dash_open_label, open_tone)
        if hasattr(self, "dash_threats_label"):
            self._set_tone(self.dash_threats_label, "danger" if threats > 0 else "success")

        if hasattr(self, "dashboard_recommendations"):
            recs = self._collect_dashboard_recommendations()
            self.dashboard_recommendations.setPlainText("\n".join(f"  {i + 1}. {x}" for i, x in enumerate(recs)))

        if hasattr(self, "dash_risky_table"):
            self.dash_risky_table.setRowCount(0)
            if not rows:
                self.dash_risky_table.setRowCount(1)
                empty = QTableWidgetItem("No networks scanned yet — start a scan to populate this list.")
                empty.setTextAlignment(Qt.AlignCenter)
                self.dash_risky_table.setItem(0, 0, empty)
                self.dash_risky_table.setSpan(0, 0, 1, 5)
            else:
                risky = sorted(rows, key=lambda r: (r["score"], r["risk"] != "HIGH"))[:5]
                self.dash_risky_table.setRowCount(len(risky))
                for idx, row in enumerate(risky):
                    net = row["net"]
                    cells = [
                        net.ssid or "<hidden>",
                        net.security or "Unknown",
                        f"{int(net.signal or 0)}%",
                        row["risk"],
                        f"{row['score']}/100",
                    ]
                    for col, text in enumerate(cells):
                        item = QTableWidgetItem(text)
                        item.setTextAlignment(Qt.AlignCenter if col else (Qt.AlignVCenter | Qt.AlignLeft))
                        self.dash_risky_table.setItem(idx, col, item)
                    risk_item = self.dash_risky_table.item(idx, 3)
                    if risk_item:
                        tone = {"HIGH": "danger", "MED": "warning", "LOW": "success"}.get(row["risk"], "normal")
                        risk_item.setForeground(
                            {"danger": "#f43f5e", "warning": "#f59e0b", "success": "#22c55e"}.get(tone, "#94a3b8")
                        )

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Chrome bar
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def _create_chrome_bar(self) -> QWidget:
        bar = QFrame()
        bar.setProperty("role", "chrome")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(8)

        dot_red    = QLabel("*"); dot_red.setProperty("role", "dot_red")
        dot_yellow = QLabel("*"); dot_yellow.setProperty("role", "dot_yellow")
        dot_green  = QLabel("*"); dot_green.setProperty("role", "dot_green")
        title      = QLabel("G H O S T L I N K"); title.setProperty("role", "chrome_title")
        version    = QLabel(f"{APP_TAGLINE} // v{APP_VERSION}"); version.setProperty("role", "chrome_meta")
        status_dot = QLabel("*"); status_dot.setProperty("role", "dot_green")
        status_txt = QLabel("AUTHORIZED MODE"); status_txt.setProperty("role", "chrome_meta")
        kbd_hint   = QLabel("Ctrl+F"); kbd_hint.setProperty("role", "pill")

        layout.addWidget(dot_red)
        layout.addWidget(dot_yellow)
        layout.addWidget(dot_green)
        layout.addSpacing(10)
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(status_dot)
        layout.addWidget(status_txt)
        layout.addSpacing(8)
        layout.addWidget(kbd_hint)
        layout.addSpacing(8)
        layout.addWidget(version)
        return bar

    def _make_tab_header(self, title: str, subtitle: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 2)
        layout.setSpacing(2)
        t = QLabel(title);    t.setProperty("role", "title")
        s = QLabel(subtitle); s.setProperty("role", "subtitle")
        layout.addWidget(t)
        layout.addWidget(s)
        return container

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Theme
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def _theme_palette(self) -> dict[str, str]:
        palettes: dict[str, dict[str, str]] = {
            "dark": {
                "WIN_A": "#06101b",
                "WIN_B": "#081a2b",
                "WIN_C": "#05101a",
                "CHROME_BG": "#0f2134",
                "PANEL": "#0d1f33",
                "PANEL_ALT": "#122941",
                "PANEL_SOFT": "#142b45",
                "SURFACE": "#0b1828",
                "SURFACE_ALT": "#142b44",
                "BORDER": "rgba(118, 170, 215, 0.24)",
                "BORDER_STRONG": "rgba(125, 194, 255, 0.46)",
                "TEXT": "#eaf5ff",
                "TEXT_SOFT": "#a4bdd7",
                "TEXT_MUTED": "#6e88a4",
                "ACCENT": "#4ea8ff",
                "ACCENT_HI": "#7fc3ff",
                "ACCENT_SOFT": "rgba(78, 168, 255, 0.16)",
                "ON_ACCENT": "#f7fbff",
                "SUCCESS": "#31d799",
                "SUCCESS_SOFT": "rgba(49, 215, 153, 0.14)",
                "WARNING": "#f2ba49",
                "WARNING_SOFT": "rgba(242, 186, 73, 0.16)",
                "DANGER": "#ff6f73",
                "DANGER_SOFT": "rgba(255, 111, 115, 0.16)",
            },
            "light": {
                "WIN_A": "#f4f8fc",
                "WIN_B": "#e7f1fa",
                "WIN_C": "#f7fbff",
                "CHROME_BG": "#d9e9f9",
                "PANEL": "#ffffff",
                "PANEL_ALT": "#f2f7fd",
                "PANEL_SOFT": "#edf4fb",
                "SURFACE": "#ffffff",
                "SURFACE_ALT": "#f2f7fd",
                "BORDER": "rgba(51, 103, 153, 0.24)",
                "BORDER_STRONG": "rgba(33, 106, 182, 0.38)",
                "TEXT": "#10263d",
                "TEXT_SOFT": "#31516f",
                "TEXT_MUTED": "#5d7690",
                "ACCENT": "#0f7dd6",
                "ACCENT_HI": "#1d95f2",
                "ACCENT_SOFT": "rgba(15, 125, 214, 0.12)",
                "ON_ACCENT": "#ffffff",
                "SUCCESS": "#18956a",
                "SUCCESS_SOFT": "rgba(24, 149, 106, 0.12)",
                "WARNING": "#b87508",
                "WARNING_SOFT": "rgba(184, 117, 8, 0.12)",
                "DANGER": "#be2d3d",
                "DANGER_SOFT": "rgba(190, 45, 61, 0.12)",
            },
            "professional": {
                "WIN_A": "#10141a",
                "WIN_B": "#1a212c",
                "WIN_C": "#0e141c",
                "CHROME_BG": "#1b2431",
                "PANEL": "#171f2a",
                "PANEL_ALT": "#202a38",
                "PANEL_SOFT": "#242f3e",
                "SURFACE": "#141c27",
                "SURFACE_ALT": "#222f40",
                "BORDER": "rgba(143, 165, 189, 0.24)",
                "BORDER_STRONG": "rgba(160, 190, 222, 0.42)",
                "TEXT": "#edf3fa",
                "TEXT_SOFT": "#b5c4d5",
                "TEXT_MUTED": "#8094ac",
                "ACCENT": "#48a3e1",
                "ACCENT_HI": "#7ac1f0",
                "ACCENT_SOFT": "rgba(72, 163, 225, 0.14)",
                "ON_ACCENT": "#f8fbff",
                "SUCCESS": "#35c08a",
                "SUCCESS_SOFT": "rgba(53, 192, 138, 0.14)",
                "WARNING": "#d4a453",
                "WARNING_SOFT": "rgba(212, 164, 83, 0.16)",
                "DANGER": "#d86a73",
                "DANGER_SOFT": "rgba(216, 106, 115, 0.16)",
            },
            "cyber": {
                "WIN_A": "#041315",
                "WIN_B": "#072126",
                "WIN_C": "#031014",
                "CHROME_BG": "#0a252c",
                "PANEL": "#082127",
                "PANEL_ALT": "#0d2c34",
                "PANEL_SOFT": "#10333c",
                "SURFACE": "#07191e",
                "SURFACE_ALT": "#10313a",
                "BORDER": "rgba(88, 201, 197, 0.22)",
                "BORDER_STRONG": "rgba(114, 245, 233, 0.42)",
                "TEXT": "#e3fffb",
                "TEXT_SOFT": "#98d8d2",
                "TEXT_MUTED": "#61a6a0",
                "ACCENT": "#22d6c4",
                "ACCENT_HI": "#79ffee",
                "ACCENT_SOFT": "rgba(34, 214, 196, 0.16)",
                "ON_ACCENT": "#00271f",
                "SUCCESS": "#4be88e",
                "SUCCESS_SOFT": "rgba(75, 232, 142, 0.14)",
                "WARNING": "#ffbd4f",
                "WARNING_SOFT": "rgba(255, 189, 79, 0.18)",
                "DANGER": "#ff6f8f",
                "DANGER_SOFT": "rgba(255, 111, 143, 0.16)",
            },
        }
        selected = str(getattr(self.settings, "theme", "Professional") or "Professional").strip().lower()
        return palettes.get(selected, palettes["professional"])

    def apply_theme(self):
        qss_path = Path(__file__).with_name("theme.qss")
        qss_template = qss_path.read_text(encoding="utf-8")
        for token, value in self._theme_palette().items():
            qss_template = qss_template.replace(f"{{{{{token}}}}}", value)
        self.setStyleSheet(qss_template)

    def _dashboard_metric(self, caption: str, tone: str = "accent") -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setProperty("role", "metric_card")
        card.setProperty("tone", tone)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(2)
        cap = QLabel(caption.upper())
        cap.setProperty("role", "metric_caption")
        val = QLabel("-")
        val.setProperty("role", "metric_value")
        val.setProperty("tone", tone)
        lay.addWidget(cap)
        lay.addWidget(val)
        return card, val

    def _dashboard_mix_row(self, caption: str, bar_role: str) -> tuple[QHBoxLayout, QProgressBar, QLabel]:
        row = QHBoxLayout()
        row.setSpacing(8)
        cap = QLabel(caption)
        cap.setProperty("role", "meta")
        cap.setMinimumWidth(110)
        bar = QProgressBar()
        bar.setProperty("role", bar_role)
        bar.setRange(0, 100)
        bar.setValue(0)
        bar.setTextVisible(False)
        bar.setFixedHeight(8)
        pct = QLabel("0%")
        pct.setProperty("role", "stat_mini")
        pct.setFixedWidth(42)
        pct.setAlignment(Qt.AlignCenter)
        row.addWidget(cap)
        row.addWidget(bar, 1)
        row.addWidget(pct)
        return row, bar, pct

    def create_dashboard_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "DASHBOARD")
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll_host = QWidget()
        layout = QVBoxLayout(scroll_host)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        scroll.setWidget(scroll_host)

        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.addWidget(scroll)

        layout.addWidget(
            self._make_tab_header(
                "Dashboard",
                "Authorized Wi-Fi security audit overview and quick actions.",
            )
        )

        self.demo_mode_badge = QLabel("Demo Lab Mode Active")
        self.demo_mode_badge.setProperty("role", "badge_warning")
        self.demo_mode_badge.setVisible(self.demo_lab_mode)
        layout.addWidget(self.demo_mode_badge)

        hero = QFrame()
        hero.setProperty("role", "dashboard_hero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(18, 16, 18, 16)
        hero_layout.setSpacing(18)

        score_panel = QVBoxLayout()
        score_panel.setSpacing(6)
        score_caption = QLabel("OVERALL SECURITY SCORE")
        score_caption.setProperty("role", "metric_caption")
        score_row = QHBoxLayout()
        score_row.setSpacing(8)
        self.dash_score_value = QLabel("-")
        self.dash_score_value.setProperty("role", "dashboard_score_big")
        score_suffix = QLabel("/ 100")
        score_suffix.setProperty("role", "meta")
        score_row.addWidget(self.dash_score_value)
        score_row.addWidget(score_suffix, 0, Qt.AlignBottom)
        score_row.addStretch()
        self.dash_score_label = QLabel("Awaiting scan")
        self.dash_score_label.setProperty("role", "summary_card")
        self.dash_score_label.setProperty("tone", "normal")
        self.dash_score_bar = QProgressBar()
        self.dash_score_bar.setProperty("role", "dashboard_score_bar")
        self.dash_score_bar.setRange(0, 100)
        self.dash_score_bar.setValue(0)
        self.dash_score_bar.setTextVisible(False)
        self.dash_score_bar.setFixedHeight(12)
        score_panel.addWidget(score_caption)
        score_panel.addLayout(score_row)
        score_panel.addWidget(self.dash_score_label, 0, Qt.AlignLeft)
        score_panel.addWidget(self.dash_score_bar)
        hero_layout.addLayout(score_panel, 2)

        self.dash_cards: dict[str, QLabel] = {}
        metrics = QGridLayout()
        metrics.setHorizontalSpacing(10)
        metrics.setVerticalSpacing(10)
        metric_defs = [
            ("networks", "Networks Found", "accent"),
            ("open", "Open Networks", "warning"),
            ("secured", "Secured Networks", "success"),
            ("strong", "Strong Signal", "neutral"),
        ]
        for idx, (key, caption, tone) in enumerate(metric_defs):
            card, label = self._dashboard_metric(caption, tone)
            self.dash_cards[key] = label
            if key == "open":
                self.dash_open_label = label
            metrics.addWidget(card, idx // 2, idx % 2)
        hero_layout.addLayout(metrics, 3)
        layout.addWidget(hero)

        activity = QFrame()
        activity.setProperty("role", "dashboard_activity")
        activity_layout = QHBoxLayout(activity)
        activity_layout.setContentsMargins(12, 8, 12, 8)
        activity_layout.setSpacing(10)
        activity_defs = [
            ("last_scan", "Last Scan"),
            ("last_audit", "Last Audit"),
            ("reports", "Saved Reports"),
            ("threats", "Threats Detected"),
        ]
        for key, caption in activity_defs:
            chip = QFrame()
            chip.setProperty("role", "dashboard_chip")
            chip_layout = QVBoxLayout(chip)
            chip_layout.setContentsMargins(10, 6, 10, 6)
            chip_layout.setSpacing(2)
            cap = QLabel(caption.upper())
            cap.setProperty("role", "metric_caption")
            val = QLabel("-")
            val.setProperty("role", "summary_card")
            val.setProperty("tone", "normal")
            chip_layout.addWidget(cap)
            chip_layout.addWidget(val)
            self.dash_cards[key] = val
            if key == "threats":
                self.dash_threats_label = val
            activity_layout.addWidget(chip, 1)
        layout.addWidget(activity)

        body = QHBoxLayout()
        body.setSpacing(12)

        left_col = QVBoxLayout()
        left_col.setSpacing(12)

        actions_frame = QFrame()
        actions_frame.setProperty("role", "dashboard_panel")
        actions_layout = QVBoxLayout(actions_frame)
        actions_layout.setContentsMargins(14, 14, 14, 14)
        actions_layout.setSpacing(10)
        actions_title = QLabel("QUICK ACTIONS")
        actions_title.setProperty("role", "metric_caption")
        actions_layout.addWidget(actions_title)

        actions_grid = QGridLayout()
        actions_grid.setHorizontalSpacing(8)
        actions_grid.setVerticalSpacing(8)
        self.quick_scan_btn = QPushButton("Start Scan")
        self.quick_scan_btn.setProperty("variant", "success")
        self.quick_scan_btn.setProperty("role", "action_primary")
        self.quick_scan_btn.clicked.connect(self.start_scan)
        self.quick_audit_btn = QPushButton("Audit Configuration")
        self.quick_audit_btn.setProperty("variant", "secondary")
        self.quick_audit_btn.clicked.connect(
            lambda: self.tabs.setCurrentIndex(self.page_index.get("audit_config", 0))
        )
        self.quick_reports_btn = QPushButton("View Reports")
        self.quick_reports_btn.clicked.connect(
            lambda: self.tabs.setCurrentIndex(self.page_index.get("reports", 0))
        )
        self.quick_vault_btn = QPushButton("Open Vault")
        self.quick_vault_btn.clicked.connect(
            lambda: self.tabs.setCurrentIndex(self.page_index.get("vault", 0))
        )
        self.quick_settings_btn = QPushButton("Settings")
        self.quick_settings_btn.clicked.connect(
            lambda: self.tabs.setCurrentIndex(self.page_index.get("settings", 0))
        )
        actions_grid.addWidget(self.quick_scan_btn, 0, 0, 1, 2)
        actions_grid.addWidget(self.quick_audit_btn, 1, 0)
        actions_grid.addWidget(self.quick_reports_btn, 1, 1)
        actions_grid.addWidget(self.quick_vault_btn, 2, 0)
        actions_grid.addWidget(self.quick_settings_btn, 2, 1)
        actions_layout.addLayout(actions_grid)
        left_col.addWidget(actions_frame)

        mix_frame = QFrame()
        mix_frame.setProperty("role", "dashboard_panel")
        mix_layout = QVBoxLayout(mix_frame)
        mix_layout.setContentsMargins(14, 14, 14, 14)
        mix_layout.setSpacing(10)
        mix_title = QLabel("SECURITY MIX")
        mix_title.setProperty("role", "metric_caption")
        mix_layout.addWidget(mix_title)

        open_row, self.dash_open_bar, self.dash_open_pct = self._dashboard_mix_row(
            "Open networks", "dashboard_mix_open"
        )
        mix_layout.addLayout(open_row)
        secure_row, self.dash_secure_bar, self.dash_secure_pct = self._dashboard_mix_row(
            "WPA2 / WPA3", "dashboard_mix_secure"
        )
        mix_layout.addLayout(secure_row)
        risk_row, self.dash_risk_bar, self.dash_risk_pct = self._dashboard_mix_row(
            "At-risk networks", "dashboard_mix_risk"
        )
        mix_layout.addLayout(risk_row)

        score_card, score_label = self._dashboard_metric("Overall Score", "accent")
        self.dash_cards["score"] = score_label
        mix_layout.addWidget(score_card)
        left_col.addWidget(mix_frame)
        left_col.addStretch()
        body.addLayout(left_col, 2)

        right_col = QVBoxLayout()
        right_col.setSpacing(12)

        rec_box = QGroupBox("Priority Recommendations")
        rec_layout = QVBoxLayout(rec_box)
        rec_layout.setContentsMargins(12, 16, 12, 12)
        self.dashboard_recommendations = QTextEdit()
        self.dashboard_recommendations.setReadOnly(True)
        self.dashboard_recommendations.setProperty("role", "dashboard_recommendations")
        self.dashboard_recommendations.setPlaceholderText(
            "Recommendations will appear here after a network scan."
        )
        self.dashboard_recommendations.setMinimumHeight(140)
        rec_layout.addWidget(self.dashboard_recommendations)
        right_col.addWidget(rec_box)

        risk_box = QGroupBox("Networks Needing Attention")
        risk_layout = QVBoxLayout(risk_box)
        risk_layout.setContentsMargins(12, 16, 12, 12)
        self.dash_risky_table = QTableWidget(0, 5)
        self.dash_risky_table.setHorizontalHeaderLabels(["SSID", "Security", "Signal", "Risk", "Score"])
        self.dash_risky_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 5):
            self.dash_risky_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.dash_risky_table.verticalHeader().setVisible(False)
        self.dash_risky_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dash_risky_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dash_risky_table.setAlternatingRowColors(True)
        self.dash_risky_table.setProperty("role", "scan_table")
        self.dash_risky_table.setMinimumHeight(180)
        risk_layout.addWidget(self.dash_risky_table)
        right_col.addWidget(risk_box, 1)

        body.addLayout(right_col, 3)
        layout.addLayout(body, 1)

    def create_network_details_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "NETWORK DETAILS")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        layout.addWidget(
            self._make_tab_header(
                "Network Details",
                "Detailed network profile, risk level, score, congestion, and recommendations.",
            )
        )
        summary_row = QHBoxLayout()
        summary_row.setSpacing(8)
        self.net_kpi_ssid = QLabel("SSID: -")
        self.net_kpi_ssid.setProperty("role", "summary_card")
        self.net_kpi_security = QLabel("Security: -")
        self.net_kpi_security.setProperty("role", "summary_card")
        self.net_kpi_score = QLabel("Score: -")
        self.net_kpi_score.setProperty("role", "summary_card")
        self.net_kpi_risk = QLabel("Risk: -")
        self.net_kpi_risk.setProperty("role", "summary_card")
        self.net_kpi_risk.setProperty("tone", "normal")
        for chip in (self.net_kpi_ssid, self.net_kpi_security, self.net_kpi_score, self.net_kpi_risk):
            summary_row.addWidget(chip)
        summary_row.addStretch()
        layout.addLayout(summary_row)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(1)

        profile_shell = QWidget()
        profile_layout = QVBoxLayout(profile_shell)
        profile_layout.setContentsMargins(0, 0, 0, 0)
        profile_layout.setSpacing(8)

        profile_box = QGroupBox("Network Profile")
        profile_grid = QGridLayout(profile_box)
        profile_grid.setHorizontalSpacing(24)
        profile_grid.setVerticalSpacing(10)
        self.net_details_labels: dict[str, QLabel] = {}
        fields = [
            ("ssid", "SSID"),
            ("bssid", "BSSID"),
            ("vendor", "Vendor"),
            ("interface", "Interface"),
            ("security", "Security"),
            ("signal", "Signal"),
            ("channel", "Channel"),
            ("band", "Band"),
            ("congestion", "Congestion"),
            ("hidden", "Hidden SSID"),
        ]
        for idx, (key, title) in enumerate(fields):
            row = idx
            k = QLabel(title + ":")
            k.setProperty("role", "detail_key")
            v = QLabel("-")
            v.setProperty("role", "detail_value")
            self.net_details_labels[key] = v
            profile_grid.addWidget(k, row, 0)
            profile_grid.addWidget(v, row, 1)
        profile_layout.addWidget(profile_box)

        self.net_last_updated_label = QLabel("Last updated: -")
        self.net_last_updated_label.setProperty("role", "meta")
        profile_layout.addWidget(self.net_last_updated_label)
        profile_layout.addStretch()

        assessment_shell = QWidget()
        assessment_layout = QVBoxLayout(assessment_shell)
        assessment_layout.setContentsMargins(0, 0, 0, 0)
        assessment_layout.setSpacing(8)

        assessment_box = QGroupBox("Security Assessment")
        assessment_box_layout = QVBoxLayout(assessment_box)
        assessment_box_layout.setContentsMargins(12, 16, 12, 12)
        assessment_box_layout.setSpacing(8)
        self.net_risk_badge = QLabel("Risk: -")
        self.net_risk_badge.setProperty("role", "detail_badge")
        self.net_risk_badge.setProperty("tone", "normal")
        self.net_score_value = QLabel("-/100")
        self.net_score_value.setProperty("role", "detail_score_value")
        self.net_score_label = QLabel("Security score unavailable.")
        self.net_score_label.setProperty("role", "subtitle")
        self.net_assessment_hint = QLabel("Select a network from Scan Networks to populate details.")
        self.net_assessment_hint.setProperty("role", "meta")
        assessment_box_layout.addWidget(self.net_risk_badge)
        assessment_box_layout.addWidget(self.net_score_value)
        assessment_box_layout.addWidget(self.net_score_label)
        assessment_box_layout.addWidget(self.net_assessment_hint)
        assessment_layout.addWidget(assessment_box)

        rec_box = QGroupBox("Recommendations")
        rec_layout = QVBoxLayout(rec_box)
        rec_layout.setContentsMargins(12, 16, 12, 12)
        rec_layout.setSpacing(8)
        self.net_recommendations = QTextEdit()
        self.net_recommendations.setReadOnly(True)
        self.net_recommendations.setPlaceholderText(
            "Recommendation: Use WPA2-AES or WPA3, avoid open networks, disable WPS, and use a strong unique password."
        )
        rec_layout.addWidget(self.net_recommendations, 1)
        btn_row = QHBoxLayout()
        copy_profile_btn = QPushButton("Copy Profile")
        copy_profile_btn.setProperty("variant", "secondary")
        copy_profile_btn.clicked.connect(self.copy_network_profile)
        btn_row.addWidget(copy_profile_btn)
        copy_recs_btn = QPushButton("Copy Recommendations")
        copy_recs_btn.setProperty("variant", "secondary")
        copy_recs_btn.clicked.connect(self.copy_network_recommendations)
        btn_row.addWidget(copy_recs_btn)
        btn_row.addStretch()
        rec_layout.addLayout(btn_row)
        assessment_layout.addWidget(rec_box, 1)

        split.addWidget(profile_shell)
        split.addWidget(assessment_shell)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Tab 1 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Scan & Select
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def create_scan_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "SCAN NETWORKS")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Header & Stats ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)
        header_layout.addWidget(self._make_tab_header("Network Discovery", "Scan nearby Wi-Fi networks and choose one for authorized testing."))
        header_layout.addStretch()
        self._scan_header_row = header_layout

        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(6)
        self._scan_stats_row = stats_layout
        for attr, text in [
            ("scan_total_label",  "Total: 0"),
            ("scan_open_label",   "Open: 0"),
            ("scan_secure_label", "WPA2: 0"),
            ("scan_strong_label", "Strong: 0"),
        ]:
            lbl = QLabel(text)
            lbl.setProperty("role", "stat_card")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setMaximumWidth(160)
            setattr(self, attr, lbl)
            stats_layout.addWidget(lbl)
        header_layout.addLayout(stats_layout)
        layout.addLayout(header_layout)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Main Controls ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        controls_frame = QFrame()
        controls_frame.setProperty("role", "scan_controls_frame")
        controls_shell = QVBoxLayout(controls_frame)
        controls_shell.setContentsMargins(10, 8, 10, 8)
        controls_shell.setSpacing(8)

        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)
        
        self.scan_btn = QPushButton("START SCAN")
        self.scan_btn.setProperty("variant", "success")
        self.scan_btn.setProperty("role", "action_primary")
        self.scan_btn.setMinimumHeight(28)
        self.scan_btn.setToolTip("Scan nearby Wi-Fi networks")
        self.scan_btn.clicked.connect(self.start_scan)
        controls_layout.addWidget(self.scan_btn)
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(240)
        controls_layout.addWidget(self.interface_combo, 1)
        
        self.refresh_iface_btn = QPushButton("REFRESH")
        self.refresh_iface_btn.setProperty("variant", "secondary")
        self.refresh_iface_btn.setToolTip("Refresh available Wi-Fi interfaces")
        self.refresh_iface_btn.clicked.connect(self.refresh_interfaces)
        controls_layout.addWidget(self.refresh_iface_btn)

        self.iface_health_label = QLabel("Interface: unknown")
        self.iface_health_label.setProperty("role", "meta")
        controls_layout.addWidget(self.iface_health_label)

        controls_layout.addStretch()
        controls_shell.addLayout(controls_layout)

        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)

        self.auto_rescan_check = QCheckBox("Auto-rescan")
        self.auto_rescan_check.toggled.connect(self.toggle_auto_rescan)
        controls_layout.addWidget(self.auto_rescan_check)
        
        self.auto_rescan_interval = QSpinBox()
        self.auto_rescan_interval.setRange(5, 300)
        self.auto_rescan_interval.setValue(20)
        self.auto_rescan_interval.setSuffix(" s")
        self.auto_rescan_interval.setMinimumWidth(110)
        self.auto_rescan_interval.valueChanged.connect(self.update_auto_rescan_interval)
        controls_layout.addWidget(self.auto_rescan_interval)

        self.last_scan_label = QLabel("Last scan: never")
        self.last_scan_label.setProperty("role", "meta")
        controls_layout.addWidget(self.last_scan_label)

        self.demo_mode_check = QCheckBox("Demo Lab Mode")
        self.demo_mode_check.setChecked(self.demo_lab_mode)
        self.demo_mode_check.toggled.connect(self.toggle_demo_mode)
        controls_layout.addWidget(self.demo_mode_check)
        controls_layout.addStretch()
        controls_shell.addLayout(controls_layout)

        layout.addWidget(controls_frame)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Search & Filters ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        filters_frame = QFrame()
        filters_frame.setProperty("role", "scan_filters_frame")
        filters_shell = QVBoxLayout(filters_frame)
        filters_shell.setContentsMargins(10, 8, 10, 8)
        filters_shell.setSpacing(8)

        filter_top = QHBoxLayout()
        filter_top.setSpacing(8)

        self.scan_search_edit = QLineEdit()
        self.scan_search_edit.setPlaceholderText("Search SSID / BSSID... (Ctrl+F)")
        self.scan_search_edit.setMinimumWidth(160)
        self.scan_search_edit.setMaximumWidth(400)
        self.scan_search_edit.setClearButtonEnabled(True)
        self.scan_search_edit.textChanged.connect(self.apply_scan_filters)
        filter_top.addWidget(self.scan_search_edit, 1)

        self.scan_filter_buttons: dict[str, QPushButton] = {}
        for key, label in [("all", "ALL"), ("strong", "STRONG"), ("open", "OPEN"), ("secure", "WPA2/WPA3"), ("band5", "5 GHZ")]:
            btn = QPushButton(label)
            btn.setProperty("role", "scan_filter")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _checked, k=key: self.set_scan_filter(k))
            self.scan_filter_buttons[key] = btn
            filter_top.addWidget(btn)
        self.scan_filter_buttons["all"].setChecked(True)

        self.security_type_filter = QComboBox()
        self.security_type_filter.addItems(["All Security", "Open", "WPA2", "WPA3", "Unknown"])
        self.security_type_filter.setMinimumWidth(152)
        self.security_type_filter.currentIndexChanged.connect(self.apply_scan_filters)
        filter_top.addWidget(self.security_type_filter)

        self.signal_filter = QComboBox()
        self.signal_filter.addItems(["All Signal", ">= 80%", ">= 60%", ">= 40%", "< 40%"])
        self.signal_filter.setMinimumWidth(125)
        self.signal_filter.currentIndexChanged.connect(self.apply_scan_filters)
        filter_top.addWidget(self.signal_filter)
        filter_top.addStretch()
        filters_shell.addLayout(filter_top)

        filter_bottom = QHBoxLayout()
        filter_bottom.setSpacing(8)

        self.show_hidden_check = QCheckBox("Show hidden")
        self.show_hidden_check.toggled.connect(self.apply_scan_filters)
        filter_bottom.addWidget(self.show_hidden_check)

        self.compare_check = QCheckBox("Compare scans")
        self.compare_check.setChecked(True)
        self.compare_check.toggled.connect(self.toggle_compare_scans)
        filter_bottom.addWidget(self.compare_check)

        self.columns_btn = QPushButton("COLUMNS")
        self.columns_btn.setProperty("variant", "secondary")
        self.columns_btn.clicked.connect(self.open_column_menu)
        filter_bottom.addWidget(self.columns_btn)

        self.filter_preset_combo = QComboBox()
        for label, data in [
            ("Preset: Custom", "custom"),
            ("Preset: Audit mode", "audit"),
            ("Preset: Open only", "open_only"),
            ("Preset: 5GHz strong", "5g_strong"),
        ]:
            self.filter_preset_combo.addItem(label, data)
        self.filter_preset_combo.setMinimumWidth(190)
        self.filter_preset_combo.currentIndexChanged.connect(self.apply_filter_preset)
        filter_bottom.addWidget(self.filter_preset_combo)

        self.density_combo = QComboBox()
        self.density_combo.addItem("Comfortable", "comfortable")
        self.density_combo.addItem("Compact", "compact")
        self.density_combo.setMinimumWidth(140)
        self.density_combo.currentIndexChanged.connect(self.update_scan_density)
        filter_bottom.addWidget(self.density_combo)
        
        self.debug_btn = QPushButton("DEBUG")
        self.debug_btn.setProperty("variant", "secondary")
        self.debug_btn.clicked.connect(self.debug_scanner)
        filter_bottom.addWidget(self.debug_btn)
        filter_bottom.addStretch()
        filters_shell.addLayout(filter_bottom)

        layout.addWidget(filters_frame)

        helper_strip = QFrame()
        helper_strip.setProperty("role", "hint_strip")
        hl = QHBoxLayout(helper_strip)
        hl.setContentsMargins(12, 6, 12, 6)
        hl.setSpacing(8)
        helper_msg = QLabel("NEW - Channel Congestion Radar: Visualizes channel occupancy across 2.4 GHz (ch 1-13) and 5 GHz bands.")
        helper_msg.setProperty("role", "meta")
        hl.addWidget(helper_msg)
        layout.addWidget(helper_strip)

        self.channel_radar_frame = QFrame()
        self.channel_radar_frame.setProperty("role", "recon_summary")
        cr = QVBoxLayout(self.channel_radar_frame)
        cr.setContentsMargins(12, 10, 12, 10)
        cr.setSpacing(6)
        radar_title = QLabel("CHANNEL RADAR - 2.4 GHZ")
        radar_title.setProperty("role", "scan_headline")
        radar_sub = QLabel("Occupancy across all 13 channels - hover for details")
        radar_sub.setProperty("role", "meta")
        cr.addWidget(radar_title)
        cr.addWidget(radar_sub)
        self.channel_radar_bar = QLabel(" 1   2   3   4   5   6   7   8   9  10  11  12  13 ")
        self.channel_radar_bar.setProperty("role", "scan_radar_bar")
        cr.addWidget(self.channel_radar_bar)
        layout.addWidget(self.channel_radar_frame)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Table + side panel ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        table_shell = QHBoxLayout(); table_shell.setSpacing(10)
        self.scan_table = QTableWidget(0, 11)
        self.scan_table.setProperty("role", "scan_table")
        self.scan_table.setHorizontalHeaderLabels(["SSID", "STATUS", "SIGNAL", "SECURITY", "RISK", "SCORE", "BAND", "CH", "CONGESTION", "HISTORY", "BSSID / VENDOR"])
        self.scan_table.verticalHeader().setVisible(False)
        self.scan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scan_table.setSelectionMode(QTableWidget.SingleSelection)
        self.scan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.scan_table.setShowGrid(True)
        self.scan_table.setAlternatingRowColors(True)
        self.scan_table.setWordWrap(False)
        self.scan_table.verticalHeader().setDefaultSectionSize(42)
        self.scan_table.setSortingEnabled(True)
        self.scan_table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.scan_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.scan_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scan_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scan_table.horizontalHeader().setStretchLastSection(False)
        self.scan_table.horizontalHeader().setMinimumSectionSize(58)
        for col, mode in [(0, QHeaderView.Interactive), (1, QHeaderView.Fixed), (2, QHeaderView.Fixed),
                          (3, QHeaderView.Fixed), (4, QHeaderView.Fixed), (5, QHeaderView.Fixed),
                          (6, QHeaderView.Fixed), (7, QHeaderView.Fixed), (8, QHeaderView.Fixed),
                          (9, QHeaderView.Fixed), (10, QHeaderView.Interactive)]:
            self.scan_table.horizontalHeader().setSectionResizeMode(col, mode)
        self.scan_table.setColumnWidth(0, 220)
        for col, w in [(1, 112), (2, 170), (3, 120), (4, 86), (5, 126), (6, 78), (7, 58), (8, 106), (9, 94), (10, 280)]:
            self.scan_table.setColumnWidth(col, w)
        self.scan_table.itemSelectionChanged.connect(self._sync_scan_selection_state)
        self.scan_table.itemDoubleClicked.connect(self.on_scan_row_double_clicked)
        self.scan_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_table.customContextMenuRequested.connect(self.open_scan_context_menu)
        self.scan_table.setMinimumHeight(320)
        table_shell.addWidget(self.scan_table, 4)

        # Side panel
        self.scan_side_panel = QFrame()
        self.scan_side_panel.setProperty("role", "recon_summary")
        self.scan_side_panel.setMinimumWidth(280)
        side_l = QVBoxLayout(self.scan_side_panel)
        side_l.setContentsMargins(10, 10, 10, 10)
        side_l.setSpacing(6)
        hdr = QLabel("Selected Network"); hdr.setProperty("role", "meta")
        side_l.addWidget(hdr)
        for attr, text in [
            ("sel_ssid", "SSID: -"), ("sel_bssid", "BSSID: -"),
            ("sel_vendor", "Vendor: -"), ("sel_security", "Security: -"),
            ("sel_signal", "Signal: -"), ("sel_risk", "Risk: -"),
            ("sel_score", "Score: -"), ("sel_channel", "Channel: -"),
            ("sel_congestion", "Congestion: -"), ("sel_seen", "Last seen: -"),
        ]:
            lbl = QLabel(text); lbl.setProperty("role", "summary_card")
            setattr(self, attr, lbl)
            side_l.addWidget(lbl)
        self.sel_reco = QLabel("Recommendation: -")
        self.sel_reco.setWordWrap(True)
        self.sel_reco.setProperty("role", "summary_card")
        side_l.addWidget(self.sel_reco)
        sa = QHBoxLayout()
        self.side_set_target_btn = QPushButton("SET AUDIT TARGET")
        self.side_set_target_btn.setProperty("variant", "success")
        self.side_set_target_btn.clicked.connect(self.select_target)
        self.side_copy_bssid_btn = QPushButton("COPY BSSID")
        self.side_copy_bssid_btn.setProperty("variant", "secondary")
        self.side_copy_bssid_btn.clicked.connect(self.copy_selected_bssid)
        sa.addWidget(self.side_set_target_btn)
        sa.addWidget(self.side_copy_bssid_btn)
        side_l.addLayout(sa)
        side_l.addStretch()

        side_scroll = QScrollArea()
        side_scroll.setFrameShape(QFrame.NoFrame)
        side_scroll.setWidgetResizable(True)
        side_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        side_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        side_scroll.setMinimumWidth(300)
        side_scroll.setWidget(self.scan_side_panel)
        table_shell.addWidget(side_scroll, 1)
        layout.addLayout(table_shell)

        # Empty state
        self.empty_state_frame = QFrame()
        self.empty_state_frame.setProperty("role", "recon_summary")
        ef = QVBoxLayout(self.empty_state_frame)
        ef.setContentsMargins(18, 14, 18, 14); ef.setSpacing(8)
        et = QLabel("No scan results yet."); et.setProperty("role", "empty_title")
        ex = QLabel("Select your Wi-Fi interface and click Start Scan.\nIf needed: run as Administrator and verify adapter availability.")
        ex.setProperty("role", "meta")
        self.empty_retry_btn = QPushButton("RETRY SCAN")
        self.empty_retry_btn.setProperty("variant", "success")
        self.empty_retry_btn.clicked.connect(self.start_scan)
        ef.addWidget(et); ef.addWidget(ex); ef.addWidget(self.empty_retry_btn, 0, Qt.AlignLeft)
        self.empty_state_frame.hide()
        layout.addWidget(self.empty_state_frame)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Bottom action bar ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        ar = QHBoxLayout(); ar.setSpacing(8)
        self.select_btn = QPushButton("SET AS AUDIT TARGET"); self.select_btn.setProperty("variant", "success")
        self.select_btn.setToolTip("Lock the selected network as audit target")
        self.select_btn.clicked.connect(self.select_target); self.select_btn.setEnabled(False)
        self.rescan_btn = QPushButton("RESCAN"); self.rescan_btn.setProperty("variant", "secondary"); self.rescan_btn.clicked.connect(self.start_scan)
        self.export_scan_btn = QPushButton("EXPORT CSV"); self.export_scan_btn.setProperty("variant", "secondary"); self.export_scan_btn.clicked.connect(self.export_scan_csv)
        self.export_scan_json_btn = QPushButton("EXPORT JSON"); self.export_scan_json_btn.setProperty("variant", "secondary"); self.export_scan_json_btn.clicked.connect(self.export_scan_json)
        self.copy_scan_btn = QPushButton("COPY TABLE"); self.copy_scan_btn.setProperty("variant", "secondary"); self.copy_scan_btn.clicked.connect(self.copy_scan_results)
        for w in [self.select_btn, self.rescan_btn, self.export_scan_btn, self.export_scan_json_btn, self.copy_scan_btn]:
            ar.addWidget(w)
        self.scan_footer_stats = QLabel("Delta: +0 / -0 / ~0"); self.scan_footer_stats.setProperty("role", "meta")
        ar.addWidget(self.scan_footer_stats)
        ar.addSpacing(10)
        self.scan_selection_label = QLabel("Selected: none"); self.scan_selection_label.setProperty("role", "meta")
        ar.addWidget(self.scan_selection_label)
        ar.addStretch()
        layout.addLayout(ar)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Target strip ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        self.target_strip = QFrame()
        self.target_strip.setProperty("role", "target_strip")
        sl = QHBoxLayout(self.target_strip); sl.setContentsMargins(12, 10, 12, 10)
        self.target_state_left  = QLabel("O   NO TARGET SELECTED"); self.target_state_left.setProperty("role", "target_left")
        self.target_state_right = QLabel("None");          self.target_state_right.setProperty("role", "target_right")
        sl.addWidget(self.target_state_left); sl.addStretch(); sl.addWidget(self.target_state_right)
        layout.addWidget(self.target_strip)

        # Init
        self.refresh_interfaces()
        self._sync_scan_selection_state()

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Cell widgets ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def _chip_widget(self, text: str, fg: str, bg: str) -> QWidget:
        chip = QLabel(text)
        chip.setAlignment(Qt.AlignCenter)
        chip.setStyleSheet(
            f"QLabel{{color:{fg};background:{bg};border-radius:4px;"
            "padding:2px 7px;font-size:8pt;font-weight:700;}}"
        )
        holder = QWidget()
        lay = QHBoxLayout(holder)
        lay.setContentsMargins(4, 2, 4, 2)
        lay.setSpacing(0)
        lay.addWidget(chip, 0, Qt.AlignCenter)
        return holder

    def _security_item(self, security: str) -> QTableWidgetItem:
        sec = security.upper()
        if "WPA3" in sec:   label, rank = "WPA3", 4
        elif "WPA2" in sec: label, rank = "WPA2", 3
        elif "OPEN" in sec: label, rank = "OPEN", 1
        else:               label, rank = sec or "UNKNOWN", 2
        item = QTableWidgetItem(label)
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, rank)
        return item

    def _security_cell_widget(self, security: str) -> QWidget:
        sec = (security or "Unknown").upper()
        if "WPA3" in sec:
            text, fg, bg = "WPA3 SECURE", "#4ade80", "#0a2e18"
        elif "WPA2" in sec:
            text, fg, bg = "WPA2 SECURE", "#4ade80", "#0a2e18"
        elif "OPEN" in sec:
            text, fg, bg = "OPEN RISK", "#f87171", "#2e0a0a"
        else:
            text, fg, bg = sec, "#d4d4d8", "#2d2d2d"
        prefix = "SEC " if "SECURE" in text else "WARN "
        return self._chip_widget(f"{prefix}{text}", fg, bg)

    def _status_cell_widget(self, status: str) -> QWidget:
        up = (status or "").upper()
        if up.startswith("NEW"):
            fg, bg = ("#22c55e" if self._pulse_new_on else "#3b82f6"), ("#14532d" if self._pulse_new_on else "#1e3a8a")
        else:
            fg, bg = "#a1a1aa", "#27272a"
        return self._chip_widget(status, fg, bg)

    def _risk_cell_widget(self, risk: str) -> QWidget:
        r = (risk or "").upper()
        if r == "HIGH":
            return self._chip_widget("HIGH", "#ef4444", "#450a0a")
        if r == "MED":
            return self._chip_widget("MED", "#f59e0b", "#451a03")
        return self._chip_widget("LOW", "#22c55e", "#052e16")

    def _congestion_cell_widget(self, congestion: str) -> QWidget:
        c = (congestion or "").upper()
        if c == "CROWDED": return self._chip_widget("CROWDED", "#ef4444", "#450a0a")
        if c == "BUSY":    return self._chip_widget("BUSY",    "#f59e0b", "#451a03")
        return self._chip_widget("CLEAR", "#22c55e", "#052e16")

    def _signal_item(self, signal: int) -> QTableWidgetItem:
        signal = max(0, min(100, int(signal)))
        item = QTableWidgetItem(f"{signal:03d}%")
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, signal)
        return item

    def _signal_cell_widget(self, signal: int) -> QWidget:
        signal = max(0, min(100, int(signal)))
        if signal >= 80:
            tone = ("#4ade80", "#052e16", "EXCELLENT")
        elif signal >= 60:
            tone = ("#60a5fa", "#0c2340", "STRONG")
        elif signal >= 40:
            tone = ("#fbbf24", "#2d1f06", "FAIR")
        else:
            tone = ("#f87171", "#2e0a0a", "WEAK")
        color, bg, tier = tone

        root = QWidget()
        rl = QHBoxLayout(root)
        rl.setContentsMargins(6, 3, 6, 3)
        rl.setSpacing(6)

        track = QFrame()
        track.setFixedHeight(8)
        track.setMinimumWidth(72)
        track.setMaximumWidth(72)
        track.setStyleSheet("QFrame{background:#2d2d2d;border-radius:4px;}")
        fill = QFrame(track)
        fill_w = max(4, int((signal / 100) * 70))
        fill.setGeometry(1, 1, fill_w, 6)
        fill.setStyleSheet(f"QFrame{{background:{color};border-radius:3px;}}")

        pct = QLabel(f"{signal}%")
        pct.setStyleSheet(f"QLabel{{color:{color};font-weight:700;font-size:8pt;}}")
        pct.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        pct.setMinimumWidth(42)

        chip = QLabel(tier)
        chip.setStyleSheet(
            f"QLabel{{background:{bg};border-radius:4px;color:{color};"
            "font-size:6.6pt;font-weight:800;padding:1px 5px;letter-spacing:0.2px;}}"
        )
        chip.setMinimumWidth(52)
        chip.setAlignment(Qt.AlignCenter)

        rl.addWidget(track)
        rl.addWidget(pct)
        rl.addWidget(chip)
        rl.addStretch()
        return root

    def _history_cell_widget(self, signal: int) -> QWidget:
        bars = max(1, min(8, int(max(0, min(100, int(signal))) / 12.5)))
        txt = "[" + ("#" * bars).ljust(8, "-") + "]"
        lbl = QLabel(txt)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("QLabel{color:#00d9ff;font-family:Consolas,monospace;font-size:8pt;font-weight:700;}")
        wrap = QWidget()
        wl = QHBoxLayout(wrap)
        wl.setContentsMargins(4, 2, 4, 2)
        wl.setSpacing(0)
        wl.addWidget(lbl)
        return wrap

    #     # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Scan logic ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def _set_scan_placeholder(self, text: str):
        self.scan_table.setRowCount(1)
        for c in range(11):
            item = QTableWidgetItem(text if c == 0 else "")
            item.setTextAlignment(Qt.AlignCenter if c else (Qt.AlignVCenter | Qt.AlignLeft))
            self.scan_table.setItem(0, c, item)
        self.select_btn.setEnabled(False)
        self.scan_selection_label.setText("Selected: none")

    def _tick_new_pulse(self):
        self._pulse_new_on = not self._pulse_new_on
        if not hasattr(self, "scan_table"):
            return
        for row in range(self.scan_table.rowCount()):
            item = self.scan_table.item(row, 1)
            if item and item.text().upper().startswith("NEW"):
                self.scan_table.setCellWidget(row, 1, self._status_cell_widget(item.text()))

    def _channel_to_band(self, channel: int) -> str:
        return channel_to_band(channel)

    def _vendor_from_bssid(self, bssid: str) -> str:
        return vendor_from_bssid(bssid)

    def _risk_label(self, signal: int, security: str) -> str:
        return risk_label(signal, security)

    def _score_for_network(self, net, congestion: str | None = None):
        return score_network(
            security=net.security or "",
            signal=int(net.signal or 0),
            congestion=congestion or "Clear",
            hidden_ssid=bool(getattr(net, "hidden", False)),
        )

    def _recommendations_for_network(self, net, congestion: str | None = None) -> list[str]:
        return recommendations_for_network(
            security=net.security or "",
            signal=int(net.signal or 0),
            congestion=congestion or "Clear",
            hidden_ssid=bool(getattr(net, "hidden", False)),
        )

    def _score_item(self, score_value: int, label: str) -> QTableWidgetItem:
        item = QTableWidgetItem(f"{score_value} ({label})")
        item.setData(Qt.UserRole, int(score_value))
        item.setTextAlignment(Qt.AlignCenter)
        return item

    def _score_cell_widget(self, score_value: int, label: str) -> QWidget:
        if score_value >= 90:
            fg, bg = "#22c55e", "#052e16"
        elif score_value >= 75:
            fg, bg = "#4ade80", "#14532d"
        elif score_value >= 55:
            fg, bg = "#f59e0b", "#451a03"
        elif score_value >= 35:
            fg, bg = "#fb7185", "#3b0823"
        else:
            fg, bg = "#f43f5e", "#3a0717"
        return self._chip_widget(f"{score_value}/100 {label}", fg, bg)

    def _status_label(self, net) -> str:
        return status_label(
            bssid=net.bssid or "",
            signal=int(net.signal or 0),
            compare_enabled=self._scan_compare_enabled,
            prev_by_bssid=self._scan_prev_by_bssid,
            new_bssids=self._scan_new_bssids,
            seen_at=self._scan_seen_at,
        )

    def _congestion_map(self, networks) -> dict:
        return congestion_map(networks)

    def set_scan_filter(self, filter_key: str):
        self.active_scan_filter = filter_key
        for key, btn in self.scan_filter_buttons.items():
            btn.setChecked(key == filter_key)
        self.apply_scan_filters()

    def apply_scan_filters(self):
        self._filter_timer.start(80)

    def _apply_scan_filters_now(self):
        query = self.scan_search_edit.text().strip().lower() if hasattr(self, "scan_search_edit") else ""
        security_filter = self.security_type_filter.currentText() if hasattr(self, "security_type_filter") else "All Security"
        signal_filter = self.signal_filter.currentText() if hasattr(self, "signal_filter") else "All Signal"
        filtered = []
        for net in self.scan_results:
            sec  = (net.security or "").upper()
            band = self._channel_to_band(int(net.channel or 0))
            if self.active_scan_filter == "strong" and int(net.signal or 0) <= 70: continue
            if self.active_scan_filter == "open"   and "OPEN" not in sec:           continue
            if self.active_scan_filter == "secure" and "WPA2" not in sec and "WPA3" not in sec: continue
            if self.active_scan_filter == "band5"  and band != "5 GHz":             continue
            if security_filter == "Open" and "OPEN" not in sec: continue
            if security_filter == "WPA2" and "WPA2" not in sec: continue
            if security_filter == "WPA3" and "WPA3" not in sec: continue
            if security_filter == "Unknown" and "OPEN" in sec: continue
            if security_filter == "Unknown" and ("WPA2" in sec or "WPA3" in sec): continue
            sig = int(net.signal or 0)
            if signal_filter == ">= 80%" and sig < 80: continue
            if signal_filter == ">= 60%" and sig < 60: continue
            if signal_filter == ">= 40%" and sig < 40: continue
            if signal_filter == "< 40%" and sig >= 40: continue
            if not self.show_hidden_check.isChecked() and (net.hidden or not (net.ssid or "").strip()): continue
            if query and query not in (net.ssid or "").lower() and query not in (net.bssid or "").lower(): continue
            filtered.append(net)
        self.filtered_scan_results = filtered
        self._render_scan_table(filtered)
        self._sync_scan_selection_state()

    def _render_scan_table(self, networks):
        self.scan_table.setSortingEnabled(False)
        self.scan_table.setRowCount(0)
        if not networks:
            self._set_scan_placeholder("No networks match current filters.")
            self.empty_state_frame.show()
            self.scan_table.setSortingEnabled(True)
            return
        self.empty_state_frame.hide()
        congestion = self._congestion_map(networks)
        self.scan_table.setRowCount(len(networks))
        for row, net in enumerate(networks):
            ssid = net.ssid or "<hidden>"
            ssid_item = QTableWidgetItem(ssid)
            ssid_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if net.hidden or ssid == "<hidden>":
                ssid_item.setForeground(Qt.yellow)
            self.scan_table.setItem(row, 0, ssid_item)

            status_text = self._status_label(net)
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(Qt.transparent)
            self.scan_table.setItem(row, 1, status_item)
            self.scan_table.setCellWidget(row, 1, self._status_cell_widget(status_text))

            self.scan_table.setItem(row, 2, self._signal_item(net.signal))
            self.scan_table.setCellWidget(row, 2, self._signal_cell_widget(net.signal))

            self.scan_table.setItem(row, 3, self._security_item(net.security))
            self.scan_table.setCellWidget(row, 3, self._security_cell_widget(net.security))

            risk = self._risk_label(int(net.signal or 0), net.security or "")
            risk_item = QTableWidgetItem(risk)
            risk_item.setTextAlignment(Qt.AlignCenter)
            risk_item.setForeground(Qt.transparent)
            self.scan_table.setItem(row, 4, risk_item)
            self.scan_table.setCellWidget(row, 4, self._risk_cell_widget(risk))

            score_result = self._score_for_network(net, congestion.get(int(net.channel or 0), "Clear"))
            self.scan_table.setItem(row, 5, self._score_item(score_result.score, score_result.label))
            self.scan_table.setCellWidget(row, 5, self._score_cell_widget(score_result.score, score_result.label))

            band_item = QTableWidgetItem(self._channel_to_band(int(net.channel or 0)))
            band_item.setTextAlignment(Qt.AlignCenter)
            self.scan_table.setItem(row, 6, band_item)

            ch_item = QTableWidgetItem(str(int(net.channel or 0)))
            ch_item.setTextAlignment(Qt.AlignCenter)
            self.scan_table.setItem(row, 7, ch_item)

            congest_text = congestion.get(int(net.channel or 0), "-")
            congest_item = QTableWidgetItem(congest_text)
            congest_item.setTextAlignment(Qt.AlignCenter)
            congest_item.setForeground(Qt.transparent)
            self.scan_table.setItem(row, 8, congest_item)
            self.scan_table.setCellWidget(row, 8, self._congestion_cell_widget(congest_text))

            vendor = self._vendor_from_bssid(net.bssid or "")
            bssid_item = QTableWidgetItem(f"{net.bssid or '-'}  |  {vendor}")
            bssid_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            bssid_item.setData(Qt.UserRole, (net.bssid or "").strip().lower())
            self.scan_table.setItem(row, 9, QTableWidgetItem(""))
            self.scan_table.setCellWidget(row, 9, self._history_cell_widget(net.signal))
            self.scan_table.setItem(row, 10, bssid_item)

        self.scan_table.sortItems(2, Qt.DescendingOrder)
        self.scan_table.setSortingEnabled(True)

    def _sync_scan_selection_state(self):
        row = self.scan_table.currentRow() if hasattr(self, "scan_table") else -1
        net = self._network_from_row(row)
        valid = net is not None
        self.select_btn.setEnabled(valid)
        if not valid:
            self.scan_selection_label.setText("Selected: none")
            self.sel_ssid.setText("SSID: -"); self.sel_bssid.setText("BSSID: -")
            self.sel_vendor.setText("Vendor: -"); self.sel_security.setText("Security: -")
            self.sel_signal.setText("Signal: -"); self.sel_risk.setText("Risk: -")
            self.sel_score.setText("Score: -")
            self.sel_channel.setText("Channel: -"); self.sel_congestion.setText("Congestion: -")
            self.sel_seen.setText("Last seen: -")
            self.sel_reco.setText("Recommendation: -")
            self._update_network_details(None)
            return
        self.scan_selection_label.setText(f"Selected: {net.ssid or '<hidden>'} ({net.signal}%)")
        self._last_selected_bssid = (net.bssid or "").strip().lower()
        channel = int(net.channel or 0)
        congestion = self._congestion_map(self.filtered_scan_results).get(channel, "Clear")
        score_result = self._score_for_network(net, congestion)
        recs = self._recommendations_for_network(net, congestion)
        self.sel_ssid.setText(f"SSID: {net.ssid or '<hidden>'}")
        self.sel_bssid.setText(f"BSSID: {net.bssid or '-'}")
        self.sel_vendor.setText(f"Vendor: {self._vendor_from_bssid(net.bssid or '')}")
        self.sel_security.setText(f"Security: {net.security or 'Unknown'}")
        self.sel_signal.setText(f"Signal: {int(net.signal or 0)}%")
        self.sel_risk.setText(f"Risk: {self._risk_label(int(net.signal or 0), net.security or '')}")
        self.sel_score.setText(f"Score: {score_result.score}/100 ({score_result.label})")
        self.sel_channel.setText(f"Channel: {channel} ({self._channel_to_band(channel)})")
        self.sel_congestion.setText(f"Congestion: {congestion}")
        seen = self._scan_seen_at.get((net.bssid or "").strip().lower())
        self.sel_seen.setText(f"Last seen: {seen.strftime('%H:%M:%S') if seen else '-'}")
        self.sel_reco.setText(f"Recommendation: {recs[0] if recs else '-'}")
        self._update_network_details(net)

    def _update_scan_summary(self, networks):
        summary = calc_scan_summary(networks)
        total = summary["total"]
        open_n = summary["open"]
        secure = summary["secure"]
        strong = summary["strong"]
        self.scan_total_label.setText(f"Total: {total}")
        self.scan_open_label.setText(f"Open: {open_n}")
        self.scan_secure_label.setText(f"WPA2/WPA3: {secure}")
        self.scan_strong_label.setText(f"Strong (>70%): {strong}")
        self.scan_open_label.setProperty("tone", "danger" if open_n > 0 else "normal")
        self.scan_open_label.style().unpolish(self.scan_open_label)
        self.scan_open_label.style().polish(self.scan_open_label)
        self.update_dashboard()

    def _network_from_row(self, row: int):
        if row < 0:
            return None
        bssid_item = self.scan_table.item(row, 10)
        if not bssid_item:
            return None
        bssid = (bssid_item.data(Qt.UserRole) or "").strip().lower()
        if not bssid or bssid == "-":
            ssid_item = self.scan_table.item(row, 0)
            ssid = (ssid_item.text() if ssid_item else "").strip()
            for net in self.filtered_scan_results:
                if (net.ssid or "<hidden>") == ssid:
                    return net
            return None
        for net in self.filtered_scan_results:
            if (net.bssid or "").strip().lower() == bssid:
                return net
        return None

    def _restore_scan_selection(self):
        target = (self.config.get("target_bssid") or self._last_selected_bssid or "").strip().lower()
        if not target:
            return
        for row in range(self.scan_table.rowCount()):
            item = self.scan_table.item(row, 10)
            if item and (item.data(Qt.UserRole) or "").strip().lower() == target:
                self.scan_table.selectRow(row)
                self.scan_table.scrollToItem(item)
                break

    def on_scan_row_double_clicked(self, *_args):
        if self.select_btn.isEnabled():
            self.select_target()
            self.tabs.setCurrentIndex(self.page_index.get("audit_config", 0))

    def open_scan_context_menu(self, pos):
        row = self.scan_table.rowAt(pos.y())
        if row < 0:
            return
        self.scan_table.selectRow(row)
        net = self._network_from_row(row)
        if not net:
            return
        menu = QMenu(self)
        set_target_action  = menu.addAction("Set as Audit Target")
        view_details_action = menu.addAction("View Details")
        menu.addSeparator()
        copy_ssid_action   = menu.addAction("Copy SSID")
        copy_bssid_action  = menu.addAction("Copy BSSID")
        save_snapshot_action = menu.addAction("Save Scan Snapshot")
        recommendation_action = menu.addAction("Generate Recommendation")
        copy_row_action    = menu.addAction("Copy Row")
        chosen = menu.exec(self.scan_table.viewport().mapToGlobal(pos))
        if chosen == set_target_action:
            self.select_target()
        elif chosen == view_details_action:
            self._update_network_details(net)
            self.tabs.setCurrentIndex(self.page_index.get("network_details", 0))
        elif chosen == copy_ssid_action:
            QApplication.clipboard().setText(net.ssid or "<hidden>")
            self.statusBar().showMessage("SSID copied to clipboard")
        elif chosen == copy_bssid_action:
            QApplication.clipboard().setText(net.bssid or "")
            self.statusBar().showMessage("BSSID copied to clipboard")
        elif chosen == save_snapshot_action:
            self.save_scan_snapshot()
        elif chosen == recommendation_action:
            congestion = self._congestion_map(self.filtered_scan_results).get(int(net.channel or 0), "Clear")
            recs = self._recommendations_for_network(net, congestion)
            QMessageBox.information(self, "Recommendation", "\n".join(f"- {r}" for r in recs))
        elif chosen == copy_row_action:
            row_text = f"{net.ssid or '<hidden>'}, {net.signal}%, {net.security}, {self._channel_to_band(int(net.channel or 0))}, ch {int(net.channel or 0)}, {net.bssid or ''}"
            QApplication.clipboard().setText(row_text)
            self.statusBar().showMessage("Row copied to clipboard")

    def copy_selected_bssid(self):
        row = self.scan_table.currentRow()
        net = self._network_from_row(row)
        if not net:
            return
        QApplication.clipboard().setText(net.bssid or "")
        self.statusBar().showMessage("BSSID copied to clipboard")

    def toggle_demo_mode(self, enabled: bool):
        self.demo_lab_mode = bool(enabled)
        self.settings.demo_lab_mode = self.demo_lab_mode
        self.settings_store.save(self.settings)
        if hasattr(self, "demo_mode_badge"):
            self.demo_mode_badge.setVisible(self.demo_lab_mode)
        if hasattr(self, "demo_mode_settings_check"):
            self.demo_mode_settings_check.setChecked(self.demo_lab_mode)
        self._show_toast(
            "Demo Lab Mode enabled." if self.demo_lab_mode else "Demo Lab Mode disabled.",
            "info",
        )
        self.update_dashboard()

    def _demo_scan_networks(self) -> list[ScanResult]:
        return [
            ScanResult("Home_Network_WPA2", "00:1A:11:5A:BC:01", 86, "WPA2-Personal", False, "DemoAdapter", 6),
            ScanResult("Campus_Guest_Open", "3C:84:6A:9D:EF:02", 74, "Open", False, "DemoAdapter", 11),
            ScanResult("Office_WPA3", "FC:FB:FB:6D:AA:03", 80, "WPA3-Personal", False, "DemoAdapter", 44),
            ScanResult("Cafe_Free_WiFi", "50:C7:BF:11:22:04", 58, "Open", False, "DemoAdapter", 1),
            ScanResult("Router_Test_Lab", "D8:0D:17:AA:BB:05", 67, "WPA2-Personal", False, "DemoAdapter", 9),
        ]

    def save_scan_snapshot(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Scan Snapshot", "No scan results to snapshot.")
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path("reports") / f"scan_snapshot_{stamp}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = []
        congestion = self._congestion_map(self.filtered_scan_results)
        for net in self.filtered_scan_results:
            congestion_text = congestion.get(int(net.channel or 0), "-")
            score_result = self._score_for_network(net, congestion_text)
            payload.append({
                "ssid": net.ssid,
                "bssid": net.bssid,
                "signal": int(net.signal or 0),
                "security": net.security,
                "channel": int(net.channel or 0),
                "band": self._channel_to_band(int(net.channel or 0)),
                "congestion": congestion_text,
                "score": score_result.score,
                "score_label": score_result.label,
            })
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.statusBar().showMessage(f"Scan snapshot saved: {out}")
        self._show_toast("Scan snapshot saved.", "success")

    def _update_network_details(self, net):
        if not hasattr(self, "net_details_labels"):
            return

        def _risk_tone(risk_text: str) -> str:
            upper = (risk_text or "").upper()
            if upper == "HIGH":
                return "danger"
            if upper == "MED":
                return "warning"
            if upper == "LOW":
                return "success"
            return "normal"

        def _apply_tone(label: QLabel, tone: str):
            label.setProperty("tone", tone)
            label.style().unpolish(label)
            label.style().polish(label)

        if net is None:
            for label in self.net_details_labels.values():
                label.setText("-")
            self.net_recommendations.clear()
            if hasattr(self, "net_score_value"):
                self.net_score_value.setText("-/100")
            if hasattr(self, "net_score_label"):
                self.net_score_label.setText("Security score unavailable.")
            if hasattr(self, "net_assessment_hint"):
                self.net_assessment_hint.setText("Select a network from Scan Networks to populate details.")
            if hasattr(self, "net_kpi_ssid"):
                self.net_kpi_ssid.setText("SSID: -")
            if hasattr(self, "net_kpi_security"):
                self.net_kpi_security.setText("Security: -")
            if hasattr(self, "net_kpi_score"):
                self.net_kpi_score.setText("Score: -")
            if hasattr(self, "net_kpi_risk"):
                self.net_kpi_risk.setText("Risk: -")
                _apply_tone(self.net_kpi_risk, "normal")
            if hasattr(self, "net_risk_badge"):
                self.net_risk_badge.setText("Risk: -")
                _apply_tone(self.net_risk_badge, "normal")
            if hasattr(self, "net_last_updated_label"):
                self.net_last_updated_label.setText("Last updated: -")
            return
        channel = int(net.channel or 0)
        band = self._channel_to_band(channel)
        congestion = self._congestion_map(self.filtered_scan_results).get(channel, "Clear")
        score_result = self._score_for_network(net, congestion)
        recs = self._recommendations_for_network(net, congestion)
        risk = self._risk_label(int(net.signal or 0), net.security or "")
        tone = _risk_tone(risk)
        ssid_text = net.ssid or "<hidden>"
        security_text = net.security or "Unknown"
        signal_value = int(net.signal or 0)

        self.net_details_labels["ssid"].setText(ssid_text)
        self.net_details_labels["bssid"].setText(net.bssid or "-")
        self.net_details_labels["vendor"].setText(self._vendor_from_bssid(net.bssid or ""))
        self.net_details_labels["interface"].setText(net.interface or "-")
        self.net_details_labels["security"].setText(security_text)
        self.net_details_labels["signal"].setText(f"{signal_value}%")
        self.net_details_labels["channel"].setText(str(channel))
        self.net_details_labels["band"].setText(band)
        self.net_details_labels["congestion"].setText(congestion)
        self.net_details_labels["hidden"].setText("Yes" if bool(net.hidden) else "No")

        self.net_kpi_ssid.setText(f"SSID: {ssid_text}")
        self.net_kpi_security.setText(f"Security: {security_text}")
        self.net_kpi_score.setText(f"Score: {score_result.score}/100")
        self.net_kpi_risk.setText(f"Risk: {risk}")
        _apply_tone(self.net_kpi_risk, tone)

        self.net_risk_badge.setText(f"Risk: {risk}")
        _apply_tone(self.net_risk_badge, tone)
        self.net_score_value.setText(f"{score_result.score}/100")
        self.net_score_label.setText(score_result.label)
        self.net_assessment_hint.setText(
            f"Signal {signal_value}% on {band} (ch {channel}) with {congestion.lower()} congestion."
        )
        self.net_last_updated_label.setText(
            f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.net_recommendations.setPlainText("\n".join(f"- {x}" for x in recs))

    def copy_network_profile(self):
        if not hasattr(self, "net_details_labels"):
            return

        def _value(key: str) -> str:
            item = self.net_details_labels.get(key)
            return item.text() if item else "-"

        rows = [
            ("SSID", _value("ssid")),
            ("BSSID", _value("bssid")),
            ("Vendor", _value("vendor")),
            ("Interface", _value("interface")),
            ("Security", _value("security")),
            ("Signal", _value("signal")),
            ("Channel", _value("channel")),
            ("Band", _value("band")),
            ("Congestion", _value("congestion")),
            ("Hidden SSID", _value("hidden")),
            ("Risk", self.net_risk_badge.text().replace("Risk: ", "")),
            ("Score", self.net_score_value.text()),
            ("Score Label", self.net_score_label.text()),
        ]
        QApplication.clipboard().setText("\n".join(f"{k}: {v}" for k, v in rows))
        self._show_toast("Network profile copied.", "success")

    def copy_network_recommendations(self):
        text = self.net_recommendations.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Network Details", "No recommendations available yet.")
            return
        QApplication.clipboard().setText(text)
        self._show_toast("Recommendations copied.", "success")

    def toggle_auto_rescan(self, enabled: bool):
        self._scan_auto_enabled = bool(enabled)
        if enabled:
            self.update_auto_rescan_interval()
            self.statusBar().showMessage("Auto-rescan enabled")
        else:
            self._scan_auto_timer.stop()
            self.statusBar().showMessage("Auto-rescan disabled")

    def update_auto_rescan_interval(self):
        if self._scan_auto_enabled:
            self._scan_auto_timer.start(int(self.auto_rescan_interval.value()) * 1000)

    def _on_auto_rescan_tick(self):
        if self.scan_btn.isEnabled():
            self.start_scan()

    def toggle_compare_scans(self, enabled: bool):
        self._scan_compare_enabled = bool(enabled)
        self.apply_scan_filters()

    def update_scan_density(self):
        mode = self.density_combo.currentData()
        self._scan_density_mode = mode or "comfortable"
        self.scan_table.verticalHeader().setDefaultSectionSize(44 if self._scan_density_mode == "compact" else 52)
        self._render_scan_table(self.filtered_scan_results)

    def _apply_table_density(self):
        compact = str(getattr(self.settings, "table_density", "Comfortable")).strip().lower() == "compact"
        scan_row_h = 44 if compact else 52
        data_row_h = 32 if compact else 38
        if hasattr(self, "scan_table"):
            self.scan_table.verticalHeader().setDefaultSectionSize(scan_row_h)
        if hasattr(self, "reports_table"):
            self.reports_table.verticalHeader().setDefaultSectionSize(data_row_h)
        if hasattr(self, "vault_table"):
            self.vault_table.verticalHeader().setDefaultSectionSize(data_row_h)

    def apply_filter_preset(self):
        preset = self.filter_preset_combo.currentData()
        if preset == "audit":
            self.show_hidden_check.setChecked(True); self.set_scan_filter("all")
        elif preset == "open_only":
            self.show_hidden_check.setChecked(True); self.set_scan_filter("open")
        elif preset == "5g_strong":
            self.show_hidden_check.setChecked(False); self.set_scan_filter("band5"); self.scan_search_edit.setText("")
        elif preset == "custom":
            return
        self.apply_scan_filters()

    def open_column_menu(self):
        menu = QMenu(self)
        for col, label in [(1, "Status"), (4, "Risk"), (5, "Score"), (6, "Band"), (7, "Channel"), (8, "Congestion"), (9, "History"), (10, "BSSID/Vendor")]:
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(not self.scan_table.isColumnHidden(col))
            action.toggled.connect(lambda checked, c=col: self.scan_table.setColumnHidden(c, not checked))
        menu.exec(self.columns_btn.mapToGlobal(self.columns_btn.rect().bottomLeft()))

    def refresh_interfaces(self):
        current = self.interface_combo.currentText().strip() if hasattr(self, "interface_combo") else ""
        if not hasattr(self, "interface_combo"):
            return
        self.interface_combo.clear()
        self.interface_combo.addItem("Auto (default)", "")
        ifaces = WiFiScanner.list_interfaces()
        for iface in ifaces:
            self.interface_combo.addItem(iface, iface)
        self.iface_health_label.setText("Interface: ready" if ifaces else "Interface: no adapter detected")
        if current:
            idx = self.interface_combo.findText(current)
            if idx >= 0:
                self.interface_combo.setCurrentIndex(idx)

    def start_scan(self):
        if self.demo_lab_mode:
            self.statusBar().showMessage("Demo Lab Mode scan loaded")
            self.on_scan_finished(self._demo_scan_networks())
            self._show_toast("Demo Lab Mode scan completed.", "info")
            self._log_event("INFO", "Demo Lab Mode scan completed.")
            return
        try:    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except: is_admin = False
        if not is_admin:
            QMessageBox.critical(self, "Administrator Required",
                "GHOSTLINK must be run as Administrator to scan Wi-Fi networks.\n\n"
                "Please restart as Administrator (right-click -> Run as administrator).")
            self.iface_health_label.setText("Interface: admin required")
            self._log_event("WARNING", "Scan blocked: administrator privileges required.")
            return
        self.statusBar().showMessage("Scanning for Wi-Fi networks...")
        self.last_scan_label.setText("Last scan: scanning...")
        self.scan_btn.setEnabled(False)
        self._set_scan_placeholder("Scanning...")
        if self.worker and self.worker.isRunning():
            self.worker.quit()
            self.worker.wait(800)
        selected_iface = self.interface_combo.currentData() if hasattr(self, "interface_combo") else None
        self.worker = ScanWorker(selected_iface or None)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_finished(self, networks):
        self._scan_cycle += 1
        previous_bssids = set(self._scan_seen_at.keys())
        self._scan_prev_by_bssid = {
            (n.bssid or "").strip().lower(): {"signal": int(n.signal or 0)}
            for n in self.scan_results if (n.bssid or "").strip()
        }
        current_bssids = {(n.bssid or "").strip().lower() for n in networks if (n.bssid or "").strip()}
        self._scan_new_bssids = current_bssids - previous_bssids
        disappeared = previous_bssids - current_bssids
        changed = sum(
            1 for n in networks
            if (n.bssid or "").strip().lower() in self._scan_prev_by_bssid
            and abs(int(n.signal or 0) - self._scan_prev_by_bssid[(n.bssid or "").strip().lower()]["signal"]) >= 3
        )
        self.scan_footer_stats.setText(f"Delta: +{len(self._scan_new_bssids)} / -{len(disappeared)} / ~{changed}")
        now = datetime.now()
        for bssid in current_bssids:
            self._scan_seen_at[bssid] = now
        self.scan_results = sorted(networks, key=lambda n: int(n.signal or 0), reverse=True)
        self._update_scan_summary(self.scan_results)
        if self.scan_results:
            self.apply_scan_filters()
            self._restore_scan_selection()
            self.statusBar().showMessage(f"Scan complete: {len(self.scan_results)} network(s) found")
            self._show_toast(f"Scan completed: {len(self.scan_results)} networks found.", "success")
            self._log_event("INFO", f"Scan completed with {len(self.scan_results)} networks.")
            self.iface_health_label.setText("Interface: ready")
        else:
            self.filtered_scan_results = []
            self._set_scan_placeholder("No networks found. Check adapter and permissions, then click RESCAN.")
            self.statusBar().showMessage("Scan complete: no networks found")
            self.iface_health_label.setText("Interface: no networks")
            self._log_event("WARNING", "Scan completed with no networks found.")
        self.last_scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_scan_label.setText(f"Last scan: {datetime.now().strftime('%H:%M:%S')}")
        self.scan_btn.setEnabled(True)
        self.update_dashboard()

    def on_scan_error(self, message):
        self.scan_btn.setEnabled(True)
        self._set_scan_placeholder("Scan failed. Run as Admin, ensure adapter is enabled, then retry.")
        self.statusBar().showMessage("Scan failed")
        self.last_scan_label.setText("Last scan: failed")
        self.iface_health_label.setText("Interface: scan error")
        self._show_toast("Scan failed. Check adapter permissions.", "error")
        self._log_event("ERROR", f"Scan failed: {message}")
        QMessageBox.critical(self, "Scan Error", message)

    def select_target(self):
        row = self.scan_table.currentRow()
        net = self._network_from_row(row)
        if net is None:
            return
        ssid = net.ssid or "<hidden>"
        self.config["ssid"]         = ssid
        self.config["interface"]    = net.interface
        self.config["target_bssid"] = net.bssid or ""
        self.config["security"]     = net.security or "Unknown"
        self.config["channel"]      = int(net.channel or 0)
        self.config["band"]         = self._channel_to_band(int(net.channel or 0))
        self.config["signal"]       = int(net.signal or 0)
        # Update attack tab label
        self.attack_target_label.setText(
            f"  *  {ssid} | {net.security} | {self._channel_to_band(int(net.channel or 0))} | ch {int(net.channel or 0)} | {int(net.signal or 0)}%"
        )
        self.attack_target_label.setProperty("role", "target_alert_ready")
        self.attack_target_label.style().unpolish(self.attack_target_label)
        self.attack_target_label.style().polish(self.attack_target_label)
        # Update target strip (scan tab)
        self.target_strip.setProperty("role", "target_strip_locked")
        self.target_strip.style().unpolish(self.target_strip)
        self.target_strip.style().polish(self.target_strip)
        self.target_state_left.setText("*   AUDIT TARGET LOCKED")
        self.target_state_left.setProperty("role", "target_left_ready")
        self.target_state_left.style().unpolish(self.target_state_left)
        self.target_state_left.style().polish(self.target_state_left)
        self.target_state_right.setText(f"{ssid} - {net.security}")
        self.statusBar().showMessage(f"Audit target selected: {ssid}")
        self._show_toast("Audit target selected.", "success")
        self._log_event("AUDIT", f"Audit target selected: {ssid}")
        # Refresh estimate and details
        self._update_attack_estimate()
        self._update_network_details(net)

    def _maybe_show_scan_hints(self):
        if self._scan_hint_shown:
            return
        self._scan_hint_shown = True
        QMessageBox.information(
            self, "Scan Tips",
            "Tips:\n- Double-click a row to set it as audit target.\n"
            "- Right-click for quick actions.\n"
            "- Press Ctrl+F to focus the search box.",
        )

    def export_scan_csv(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Export Scan", "No scan results to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export Scan Results", "ghostlink_scan.csv", "CSV files (*.csv)")
        if not path: return
        congestion = self._congestion_map(self.filtered_scan_results)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["SSID","Status","Signal","Security","Risk","Score","Score Label","Band","Channel","Congestion","BSSID","Vendor","Interface","Recommendation"])
            for net in self.filtered_scan_results:
                congestion_text = congestion.get(int(net.channel or 0), "-")
                score_result = self._score_for_network(net, congestion_text)
                rec = self._recommendations_for_network(net, congestion_text)[0]
                w.writerow([
                    net.ssid or "<hidden>", self._status_label(net), int(net.signal or 0),
                    net.security or "Unknown", self._risk_label(int(net.signal or 0), net.security or ""),
                    score_result.score, score_result.label,
                    self._channel_to_band(int(net.channel or 0)), int(net.channel or 0),
                    congestion_text, net.bssid or "",
                    self._vendor_from_bssid(net.bssid or ""), net.interface or "", rec,
                ])
        self.statusBar().showMessage(f"CSV exported: {path}")

    def export_scan_json(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Export Scan", "No scan results to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export Scan Results (JSON)", "ghostlink_scan.json", "JSON files (*.json)")
        if not path: return
        congestion = self._congestion_map(self.filtered_scan_results)
        data = []
        for net in self.filtered_scan_results:
            congestion_text = congestion.get(int(net.channel or 0), "-")
            score_result = self._score_for_network(net, congestion_text)
            data.append({
                "ssid": net.ssid or "<hidden>",
                "bssid": net.bssid or "",
                "signal": int(net.signal or 0),
                "security": net.security or "Unknown",
                "risk": self._risk_label(int(net.signal or 0), net.security or ""),
                "score": score_result.score,
                "score_label": score_result.label,
                "band": self._channel_to_band(int(net.channel or 0)),
                "channel": int(net.channel or 0),
                "congestion": congestion_text,
                "vendor": self._vendor_from_bssid(net.bssid or ""),
                "status": self._status_label(net),
                "interface": net.interface or "",
                "recommendations": self._recommendations_for_network(net, congestion_text),
            })
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.statusBar().showMessage(f"JSON exported: {path}")

    def copy_scan_results(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Copy Scan", "No scan results to copy."); return
        congestion = self._congestion_map(self.filtered_scan_results)
        lines = ["SSID\tStatus\tSignal\tSecurity\tRisk\tScore\tBand\tChannel\tCongestion\tBSSID\tVendor"]
        for net in self.filtered_scan_results:
            congestion_text = congestion.get(int(net.channel or 0), "-")
            score_result = self._score_for_network(net, congestion_text)
            lines.append("\t".join([
                net.ssid or "<hidden>", self._status_label(net), f"{int(net.signal or 0)}%",
                net.security or "Unknown", self._risk_label(int(net.signal or 0), net.security or ""),
                f"{score_result.score}/100",
                self._channel_to_band(int(net.channel or 0)), str(int(net.channel or 0)),
                congestion_text, net.bssid or "",
                self._vendor_from_bssid(net.bssid or ""),
            ]))
        QApplication.clipboard().setText("\n".join(lines))
        self.statusBar().showMessage("Scan table copied to clipboard")

    def debug_scanner(self):
        try:    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except: is_admin = False
        if not is_admin:
            QMessageBox.critical(self, "Admin Required", "Run as Administrator."); return
        import traceback
        try:
            networks = WiFiScanner.scan()
            if networks:
                info = "\n".join(f"{n.ssid:<25} {n.signal}%  {n.security}" for n in networks)
                QMessageBox.information(self, "Scanner Diagnostics", f"Found {len(networks)} networks:\n\n{info}")
            else:
                QMessageBox.warning(self, "Scanner Diagnostics", "Scanner returned an empty list.\n\nTry: netsh wlan show networks mode=Bssid")
        except Exception as e:
            QMessageBox.critical(self, "Scanner Error", f"{e}\n\n{traceback.format_exc()}")

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Tab 2 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Attack Config
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def create_attack_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "AUDIT CONFIGURATION")
        outer_layout = QVBoxLayout(tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Wrap in scroll area for small windows
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        inner = QWidget()
        scroll.setWidget(inner)
        outer_layout.addWidget(scroll)

        layout = QVBoxLayout(inner)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        layout.addWidget(self._make_tab_header("Audit Configuration", "Define authorized test strategy, performance limits, and optional wordlist source."))

        # Target banner
        self.attack_target_label = QLabel("  [ ]  No network selected - go to SCAN NETWORKS first")
        self.attack_target_label.setProperty("role", "target_alert_idle")
        layout.addWidget(self.attack_target_label)
        self.authorization_status_label = QLabel("Authorization: Not confirmed")
        self.authorization_status_label.setProperty("role", "meta")
        layout.addWidget(self.authorization_status_label)

        grid = QGridLayout(); grid.setHorizontalSpacing(16); grid.setVerticalSpacing(16)

        # Search Strategy
        pg = QGroupBox("Search Strategy"); pf = QFormLayout(pg)
        pf.setContentsMargins(12, 16, 12, 12)
        pf.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        pf.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        pf.setSpacing(12)
        self.profile_combo = QComboBox()
        for pid, prof in PROFILES.items():
            self.profile_combo.addItem(f"{prof.icon} {prof.name}", pid)
        self.profile_combo.setMaxVisibleItems(9)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        pf.addRow("Profile:", self.profile_combo)
        self.charset_edit = QLineEdit(self.config["charset"])
        self.charset_edit.setPlaceholderText("Characters to test")
        self.charset_edit.textChanged.connect(self._update_attack_estimate)
        pf.addRow("Charset:", self.charset_edit)
        self.minlen_spin = QSpinBox(); self.minlen_spin.setRange(1, 12); self.minlen_spin.setValue(self.config["minlen"])
        self.minlen_spin.valueChanged.connect(self._update_attack_estimate)
        pf.addRow("Min Length:", self.minlen_spin)
        self.maxlen_spin = QSpinBox(); self.maxlen_spin.setRange(1, 12); self.maxlen_spin.setValue(self.config["maxlen"])
        self.maxlen_spin.valueChanged.connect(self._update_attack_estimate)
        pf.addRow("Max Length:", self.maxlen_spin)

        # Execution Limits
        eg = QGroupBox("Execution Limits"); ef = QFormLayout(eg)
        ef.setContentsMargins(12, 16, 12, 12)
        ef.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        ef.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        ef.setSpacing(12)
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1, 32); self.threads_spin.setValue(self.config["threads"])
        self.threads_spin.valueChanged.connect(self._update_attack_estimate)
        ef.addRow("Threads:", self.threads_spin)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(3, 60); self.timeout_spin.setValue(self.config["timeout"])
        ef.addRow("Timeout (s):", self.timeout_spin)

        # Wordlist Source
        wg = QGroupBox("Wordlist Source"); wl = QVBoxLayout(wg)
        wl.setContentsMargins(12, 16, 12, 12)
        wl.setSpacing(10)
        self.wordlist_edit = QTextEdit()
        self.wordlist_edit.setPlaceholderText("Paste/type passwords here (one per line), or paste a full wordlist file path.")
        self.wordlist_edit.setFixedHeight(88)
        self.wordlist_edit.textChanged.connect(self.update_wordlist_mode_hint)
        wl.addWidget(self.wordlist_edit)
        self.wordlist_mode_hint = QLabel("Mode: none (optional)")
        self.wordlist_mode_hint.setProperty("role", "meta")
        wl.addWidget(self.wordlist_mode_hint)
        wb = QHBoxLayout(); wb.setSpacing(8)
        self.browse_btn   = QPushButton("BROWSE");   self.browse_btn.setProperty("variant", "secondary");   self.browse_btn.clicked.connect(self.browse_wordlist);               wb.addWidget(self.browse_btn)
        self.template_btn = QPushButton("TEMPLATE"); self.template_btn.setProperty("variant", "secondary"); self.template_btn.clicked.connect(self.download_wordlist_template); wb.addWidget(self.template_btn)
        self.clear_wl_btn = QPushButton("CLEAR");    self.clear_wl_btn.setProperty("variant", "secondary"); self.clear_wl_btn.clicked.connect(lambda: self.wordlist_edit.clear()); wb.addWidget(self.clear_wl_btn)
        wb.addStretch(); wl.addLayout(wb)

        # Execution
        xg = QGroupBox("Execution"); xl = QVBoxLayout(xg)
        xl.setContentsMargins(12, 16, 12, 12)
        xl.setSpacing(12)
        self.cache_check = QCheckBox("Include previously cached passwords")
        self.cache_check.setChecked(not self.config["skip_cached"])
        xl.addWidget(self.cache_check)
        pl = QLabel("Start Authorized Test will switch to Audit Progress and begin worker execution.")
        pl.setProperty("role", "meta"); xl.addWidget(pl)
        xl.addStretch()
        self.start_attack_btn = QPushButton("START AUTHORIZED TEST")
        self.start_attack_btn.setProperty("variant", "critical")
        self.start_attack_btn.setProperty("role", "action_primary")
        self.start_attack_btn.clicked.connect(self.start_attack)
        xl.addWidget(self.start_attack_btn)

        checklist_box = QGroupBox("Audit Checklist")
        checklist_form = QFormLayout(checklist_box)
        checklist_form.setContentsMargins(12, 16, 12, 12)
        self.audit_checklist_controls: dict[str, QComboBox] = {}
        for item in [
            "WPA2/WPA3 enabled",
            "Default router password changed",
            "Strong Wi-Fi password used",
            "WPS disabled",
            "Router firmware updated",
            "Guest network enabled if needed",
            "Admin panel secured",
            "Unknown devices checked",
        ]:
            combo = QComboBox()
            combo.addItems(["Not checked", "Pass", "Fail"])
            checklist_form.addRow(item + ":", combo)
            self.audit_checklist_controls[item] = combo

        # Attack Estimate box (Spans across bottom of grid)
        self.estimate_frame = QFrame()
        self.estimate_frame.setProperty("role", "estimate_frame")
        est_layout = QHBoxLayout(self.estimate_frame)
        est_layout.setContentsMargins(16, 14, 16, 14)
        est_layout.setSpacing(24)
        
        est_hdr = QLabel("AUDIT ESTIMATE:")
        est_hdr.setProperty("role", "estimate_heading")
        est_layout.addWidget(est_hdr)
        
        self.est_candidates_lbl = QLabel("Candidates: Ã¢â‚¬â€")
        self.est_candidates_lbl.setProperty("role", "estimate_candidates")
        est_layout.addWidget(self.est_candidates_lbl)
        
        self.est_time_lbl = QLabel("Est. time: Ã¢â‚¬â€")
        self.est_time_lbl.setProperty("role", "estimate_time")
        est_layout.addWidget(self.est_time_lbl)
        
        est_layout.addStretch()

        grid.addWidget(pg, 0, 0); grid.addWidget(wg, 0, 1)
        grid.addWidget(eg, 1, 0); grid.addWidget(xg, 1, 1)
        grid.addWidget(checklist_box, 2, 0, 1, 2)
        grid.addWidget(self.estimate_frame, 3, 0, 1, 2)
        grid.setColumnStretch(0, 1); grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        layout.addStretch()
        # Store refs for dynamic responsive switching
        self._attack_grid = grid
        self._attack_grid_widgets = [pg, wg, eg, xg, checklist_box, self.estimate_frame]

        self._update_attack_estimate()

    def _update_attack_estimate(self):
        if not hasattr(self, "est_candidates_lbl"):
            return
        charset = self.charset_edit.text() if hasattr(self, "charset_edit") else self.config["charset"]
        minlen  = self.minlen_spin.value()  if hasattr(self, "minlen_spin")  else self.config["minlen"]
        maxlen  = self.maxlen_spin.value()  if hasattr(self, "maxlen_spin")  else self.config["maxlen"]
        threads = self.threads_spin.value() if hasattr(self, "threads_spin") else self.config["threads"]

        if minlen > maxlen:
            self.est_candidates_lbl.setText("Candidates: invalid range")
            self.est_time_lbl.setText("Est. time: Ã¢â‚¬â€")
            return

        estimate = estimate_attack(charset, minlen, maxlen, threads)
        self.est_candidates_lbl.setText(f"Candidates: {estimate.candidates:,}")
        self.est_time_lbl.setText(f"Est. time @ {threads}t: ~{format_duration(estimate.est_seconds)}")

    def on_profile_changed(self):
        pid = self.profile_combo.currentData()
        if pid and pid in PROFILES:
            self.charset_edit.setText(PROFILES[pid].charset)
        self._update_attack_estimate()

    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text files (*.txt *.lst *.dic);;All files (*.*)")
        if path:
            self.wordlist_edit.setPlainText(path)

    def download_wordlist_template(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Wordlist Template", "ghostlink_wordlist_template.txt", "Text files (*.txt)")
        if not path: return
        sample = [
            "# GHOSTLINK Wordlist Template", "# One candidate per line.",
            "password123", "welcome123", "letmein2026", "qwerty123",
            "admin@123", "wifi@home", "company2026", "summer2026!",
        ]
        Path(path).write_text("\n".join(sample) + "\n", encoding="utf-8")
        self.statusBar().showMessage(f"Template saved: {path}")

    def update_wordlist_mode_hint(self):
        wl_raw = self.wordlist_edit.toPlainText().strip()
        if not wl_raw:
            self.wordlist_mode_hint.setText("Mode: none (optional)"); return
        if "\n" not in wl_raw and Path(wl_raw).exists():
            self.wordlist_mode_hint.setText("Mode: file path detected"); return
        count = len([w for w in re.split(r"[\r\n,]+", wl_raw) if w.strip() and not w.strip().startswith("#")])
        self.wordlist_mode_hint.setText(f"Mode: inline list ({count} candidates)")

    def update_config_from_gui(self):
        self.config["charset"]  = self.charset_edit.text()
        self.config["minlen"]   = self.minlen_spin.value()
        self.config["maxlen"]   = self.maxlen_spin.value()
        self.config["threads"]  = self.threads_spin.value()
        self.config["timeout"]  = self.timeout_spin.value()
        wl_raw = self.wordlist_edit.toPlainText().strip()
        self.config["wordlist"] = self.config["wordlist_inline"] = None
        if wl_raw:
            if "\n" not in wl_raw and Path(wl_raw).exists():
                self.config["wordlist"] = Path(wl_raw)
            else:
                words = [w.strip() for w in re.split(r"[\r\n,]+", wl_raw) if w.strip() and not w.strip().startswith("#")]
                self.config["wordlist_inline"] = words or None
        self.config["skip_cached"] = not self.cache_check.isChecked()

    def _ensure_authorization_gate(self) -> bool:
        dlg = AuthorizationDialog(self)
        if dlg.exec() != QDialog.Accepted:
            self._log_event("WARNING", "Authorization gate cancelled.")
            return False
        self.authorization_record = dlg.data()
        self.authorization_status_label.setText(
            f"Authorization: Confirmed by {self.authorization_record.get('tester_name', 'tester')}"
        )
        self._show_toast("Authorization confirmed.", "success")
        self._log_event("AUDIT", f"Authorization confirmed by {self.authorization_record.get('tester_name', 'tester')}.")
        return True

    def _append_audit_timeline(self, message: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        entry = f"{stamp} - {message}"
        self.audit_timeline.append(entry)
        if hasattr(self, "timeline_text"):
            self.timeline_text.append(entry)
            self.timeline_text.moveCursor(QTextCursor.End)
        if hasattr(self, "audit_last_event_label"):
            self.audit_last_event_label.setText(f"Last event: {entry}")

    def _set_tone(self, widget: QWidget, tone: str):
        widget.setProperty("tone", tone)
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def _set_audit_phase(self, phase_text: str, tone: str = "normal"):
        if hasattr(self, "phase_label"):
            self.phase_label.setText(f"Phase: {phase_text}")
            self._set_tone(self.phase_label, tone)
        if hasattr(self, "audit_phase_badge"):
            self.audit_phase_badge.setText(phase_text.upper())
            self._set_tone(self.audit_phase_badge, tone)

    def _collect_audit_checklist(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for item, combo in getattr(self, "audit_checklist_controls", {}).items():
            rows.append({"item": item, "status": combo.currentText()})
        return rows

    def start_attack(self):
        if not self.config.get("ssid"):
            QMessageBox.warning(self, "No Network Selected", "Please scan and select a network first.")
            return
        if self.settings.require_authorization_before_audit and not self._ensure_authorization_gate():
            self.authorization_status_label.setText("Authorization: Not confirmed")
            return

        self.update_config_from_gui()
        self.tabs.setCurrentIndex(self.page_index.get("audit_progress", 0))
        self.progress_text.clear()
        if hasattr(self, "timeline_text"):
            self.timeline_text.clear()

        self.audit_timeline = []
        self._append_audit_timeline("Audit initialized")
        if self.authorization_record:
            self._append_audit_timeline("Authorization confirmed")
        if self.config.get("wordlist") or self.config.get("wordlist_inline"):
            self._append_audit_timeline("Wordlist loaded")

        self.progress_text.append("Starting authorized test...\n")
        self.progress_bar.setValue(0)
        self.progress_percent_label.setText("0%")
        self.speed_label.setText("0 pwd/s")
        self.attempts_label.setText("0")
        self.current_pwd_label.setText("-")
        self.eta_label.setText("-")

        if hasattr(self, "audit_progress_detail_label"):
            self.audit_progress_detail_label.setText("0 / 0 candidates checked")
        if hasattr(self, "elapsed_label"):
            self.elapsed_label.setText("Elapsed: 0s")
        if hasattr(self, "remaining_label"):
            self.remaining_label.setText("Remaining: -")
        if hasattr(self, "audit_status_note"):
            self.audit_status_note.setText("Worker startup in progress. Preparing candidate space and throughput telemetry.")
        self._set_audit_phase("Starting", "warning")

        self.attack_worker = AttackWorker(self.config)
        self.attack_worker.attack_started.connect(self.on_attack_started)
        self.attack_worker.progress_update.connect(self.on_progress_update)
        self.attack_worker.finished.connect(self.on_attack_finished)
        self.attack_worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
        self.attack_worker.start()

        self.start_attack_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.statusBar().showMessage(f"Authorized test running against {self.config['ssid']}")
        self._show_toast("Authorized test started.", "info")
        self._log_event("AUDIT", f"Authorized test started for {self.config.get('ssid', 'unknown')}.")
        self._attack_start_time = datetime.now()

    def create_progress_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "AUDIT PROGRESS")
        outer_layout = QVBoxLayout(tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Scroll area for small windows
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        inner = QWidget()
        scroll.setWidget(inner)
        outer_layout.addWidget(scroll)

        layout = QVBoxLayout(inner)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        layout.addWidget(
            self._make_tab_header(
                "Audit Progress",
                "Track authorized verification throughput, attempts, timeline, and live candidate activity.",
            )
        )

        status_strip = QFrame()
        status_strip.setProperty("role", "audit_status_strip")
        status_layout = QHBoxLayout(status_strip)
        status_layout.setContentsMargins(12, 10, 12, 10)
        status_layout.setSpacing(10)

        badge_col = QVBoxLayout()
        badge_col.setSpacing(6)
        self.audit_phase_badge = QLabel("IDLE")
        self.audit_phase_badge.setProperty("role", "detail_badge")
        self.audit_phase_badge.setProperty("kind", "phase")
        self.audit_phase_badge.setProperty("tone", "normal")
        badge_col.addWidget(self.audit_phase_badge, 0, Qt.AlignLeft)

        self.phase_label = QLabel("Phase: Idle")
        self.phase_label.setProperty("role", "summary_card")
        self.phase_label.setProperty("tone", "normal")
        badge_col.addWidget(self.phase_label, 0, Qt.AlignLeft)
        status_layout.addLayout(badge_col)

        status_text_col = QVBoxLayout()
        status_text_col.setSpacing(4)
        self._progress_target_info = QLabel("Audit target: -")
        self._progress_target_info.setProperty("role", "audit_target")
        self.audit_status_note = QLabel(
            "Ready. Start an authorized test to initialize search space and live telemetry."
        )
        self.audit_status_note.setProperty("role", "audit_status_note")
        self.audit_status_note.setWordWrap(True)
        status_text_col.addWidget(self._progress_target_info)
        status_text_col.addWidget(self.audit_status_note)
        status_layout.addLayout(status_text_col, 1)

        action_col = QVBoxLayout()
        action_col.setSpacing(6)
        copy_timeline_btn = QPushButton("Copy Timeline")
        copy_timeline_btn.setProperty("variant", "secondary")
        copy_timeline_btn.clicked.connect(self.copy_audit_timeline)
        action_col.addWidget(copy_timeline_btn, 0, Qt.AlignRight)
        self.stop_btn = QPushButton("[ STOP SAFELY ]")
        self.stop_btn.setProperty("variant", "danger")
        self.stop_btn.setProperty("role", "action_primary")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        action_col.addWidget(self.stop_btn, 0, Qt.AlignRight)
        action_col.addStretch()
        status_layout.addLayout(action_col)
        layout.addWidget(status_strip)

        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(12)
        self.progress_percent_label = QLabel("0%")
        self.speed_label = QLabel("0 pwd/s")
        self.attempts_label = QLabel("0")
        self.eta_label = QLabel("-")

        cards_data = [
            (self.progress_percent_label, "Progress", "accent"),
            (self.speed_label, "Speed", "success"),
            (self.attempts_label, "Attempts Checked", "warning"),
            (self.eta_label, "ETA", "neutral"),
        ]
        for lbl, caption, tone in cards_data:
            card = QFrame()
            card.setProperty("role", "metric_card")
            card.setProperty("tone", tone)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 12, 16, 12)
            card_layout.setSpacing(4)
            cap = QLabel(caption.upper())
            cap.setProperty("role", "metric_caption")
            lbl.setProperty("role", "metric_value")
            lbl.setProperty("tone", tone)
            card_layout.addWidget(cap)
            card_layout.addWidget(lbl)
            metrics_row.addWidget(card)
        layout.addLayout(metrics_row)

        progress_box = QGroupBox("Overall Progress")
        progress_layout = QVBoxLayout(progress_box)
        progress_layout.setContentsMargins(12, 16, 12, 12)
        progress_layout.setSpacing(8)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%  -  %v / %m candidates")
        self.progress_bar.setMinimumHeight(32)
        self.progress_bar.setProperty("role", "progress_bar")
        progress_layout.addWidget(self.progress_bar)

        self.audit_progress_detail_label = QLabel("0 / 0 candidates checked")
        self.audit_progress_detail_label.setProperty("role", "audit_progress_detail")
        progress_layout.addWidget(self.audit_progress_detail_label)

        phase_row = QHBoxLayout()
        phase_row.setSpacing(8)
        self.elapsed_label = QLabel("Elapsed: 0s")
        self.elapsed_label.setProperty("role", "summary_card")
        self.elapsed_label.setProperty("tone", "normal")
        self.remaining_label = QLabel("Remaining: -")
        self.remaining_label.setProperty("role", "summary_card")
        self.remaining_label.setProperty("tone", "normal")
        phase_row.addWidget(self.elapsed_label)
        phase_row.addWidget(self.remaining_label)
        phase_row.addStretch()
        progress_layout.addLayout(phase_row)

        self.audit_last_event_label = QLabel("Last event: -")
        self.audit_last_event_label.setProperty("role", "meta")
        progress_layout.addWidget(self.audit_last_event_label)
        layout.addWidget(progress_box)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(1)

        live_panel = QWidget()
        live_layout = QVBoxLayout(live_panel)
        live_layout.setContentsMargins(0, 0, 0, 0)
        live_layout.setSpacing(8)

        cand_frame = QFrame()
        cand_frame.setProperty("role", "candidate_frame")
        cand_layout = QHBoxLayout(cand_frame)
        cand_layout.setContentsMargins(16, 12, 16, 12)
        cand_layout.setSpacing(8)
        cap2 = QLabel("CURRENT CANDIDATE")
        cap2.setProperty("role", "candidate_caption")
        self.current_pwd_label = QLabel("-")
        self.current_pwd_label.setProperty("role", "candidate_value")
        cand_layout.addWidget(cap2)
        cand_layout.addWidget(self.current_pwd_label, 1)
        live_layout.addWidget(cand_frame)

        worker_log_box = QGroupBox("Worker Output")
        worker_log_layout = QVBoxLayout(worker_log_box)
        worker_log_layout.setContentsMargins(12, 16, 12, 12)
        self.progress_text = QTextEdit()
        self.progress_text.setReadOnly(True)
        self.progress_text.setFont(QFont("Consolas", 10))
        self.progress_text.setProperty("role", "audit_log")
        self.progress_text.setProperty("kind", "live")
        self.progress_text.setPlaceholderText(
            "Worker output appears here after the authorized test starts."
        )
        worker_log_layout.addWidget(self.progress_text)
        live_layout.addWidget(worker_log_box, 1)

        timeline_panel = QWidget()
        timeline_layout = QVBoxLayout(timeline_panel)
        timeline_layout.setContentsMargins(0, 0, 0, 0)
        timeline_layout.setSpacing(8)
        timeline_box = QGroupBox("Audit Timeline")
        timeline_box_layout = QVBoxLayout(timeline_box)
        timeline_box_layout.setContentsMargins(12, 16, 12, 12)
        self.timeline_text = QTextEdit()
        self.timeline_text.setReadOnly(True)
        self.timeline_text.setFont(QFont("Consolas", 9))
        self.timeline_text.setProperty("role", "audit_log")
        self.timeline_text.setProperty("kind", "timeline")
        self.timeline_text.setPlaceholderText("Audit timeline events will appear here.")
        timeline_box_layout.addWidget(self.timeline_text)
        timeline_layout.addWidget(timeline_box, 1)

        split.addWidget(live_panel)
        split.addWidget(timeline_panel)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)

    def on_attack_started(self, total: int):
        self.total_combinations = total
        self.progress_bar.setRange(0, max(total, 1))
        self.progress_bar.setValue(0)
        if total > 0:
            self.progress_text.append(f"Search space: {total:,} candidates\n")
        self._progress_target_info.setText(
            f"Audit target: {self.config.get('ssid', '-')}  |  {self.config.get('threads', 1)} threads"
        )
        if hasattr(self, "audit_status_note"):
            if total > 0:
                self.audit_status_note.setText(
                    f"Worker active. Evaluating {total:,} candidates with live throughput telemetry."
                )
            else:
                self.audit_status_note.setText(
                    "Worker active. Candidate count unavailable, monitoring live throughput only."
                )
        if hasattr(self, "audit_progress_detail_label"):
            if total > 0:
                self.audit_progress_detail_label.setText(f"0 / {total:,} candidates checked")
            else:
                self.audit_progress_detail_label.setText("0 / unknown candidates checked")
        self._set_audit_phase("Running", "success")
        self._append_audit_timeline("Verification started")

    def on_progress_update(self, current_password: str, attempts: int, speed: float):
        attempts = max(0, int(attempts))
        speed = max(0.0, float(speed))
        self.attempts_label.setText(f"{attempts:,}")
        self.speed_label.setText(f"{speed:.0f} pwd/s")
        self.current_pwd_label.setText(current_password[:52] if current_password else "-")

        elapsed_s = 0.0
        if hasattr(self, "_attack_start_time"):
            elapsed_s = max(0.0, (datetime.now() - self._attack_start_time).total_seconds())
        if hasattr(self, "elapsed_label"):
            self.elapsed_label.setText(f"Elapsed: {format_duration(elapsed_s)}")

        if self.total_combinations > 0:
            pct = min(int((attempts / self.total_combinations) * 100), 100)
            self.progress_bar.setValue(min(attempts, self.total_combinations))
            self.progress_percent_label.setText(f"{pct}%")
            remaining = max(0, self.total_combinations - attempts)
            eta_s = (remaining / speed) if speed > 0 else 0.0
            eta_text = format_duration(eta_s) if eta_s > 0 else "-"
            self.eta_label.setText(eta_text)
            if hasattr(self, "remaining_label"):
                self.remaining_label.setText(f"Remaining: {eta_text}")
            if hasattr(self, "audit_progress_detail_label"):
                self.audit_progress_detail_label.setText(
                    f"{min(attempts, self.total_combinations):,} / {self.total_combinations:,} candidates checked"
                )
        else:
            self.progress_bar.setValue(min(attempts, self.progress_bar.maximum()))
            self.progress_percent_label.setText("-")
            self.eta_label.setText("-")
            if hasattr(self, "remaining_label"):
                self.remaining_label.setText("Remaining: -")
            if hasattr(self, "audit_progress_detail_label"):
                self.audit_progress_detail_label.setText(f"{attempts:,} candidates checked")

        # Log every 100 attempts to avoid flooding the QTextEdit.
        if attempts % 100 == 0:
            self.progress_text.append(f"[{attempts:>8,}]  {current_password:<30}  @ {speed:.0f}/s")
            self.progress_text.moveCursor(QTextCursor.End)

    def stop_attack(self):
        if self.attack_worker:
            self.attack_worker.stop()
            self.stop_btn.setEnabled(False)
            self._set_audit_phase("Stopping", "warning")
            if hasattr(self, "audit_status_note"):
                self.audit_status_note.setText(
                    "Safe stop requested. Waiting for worker to complete current checkpoint."
                )
            self.statusBar().showMessage("Stopping authorized test safely...")
            self._append_audit_timeline("Test stop requested")
            self._show_toast("Authorized test stop requested.", "warning")
            self._log_event("AUDIT", "Authorized test stop requested.")

    def copy_audit_timeline(self):
        text = self.timeline_text.toPlainText().strip() if hasattr(self, "timeline_text") else ""
        if not text:
            QMessageBox.information(self, "Audit Timeline", "No timeline events available yet.")
            return
        QApplication.clipboard().setText(text)
        self._show_toast("Audit timeline copied.", "success")

    def on_attack_finished(self, password, attempts, elapsed, verified):
        attempts_count = int(attempts or 0)
        self.start_attack_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        was_stopped = bool(self.attack_worker and self.attack_worker.stop_requested)

        if self.total_combinations > 0 and hasattr(self, "audit_progress_detail_label"):
            self.audit_progress_detail_label.setText(
                f"{min(attempts_count, self.total_combinations):,} / {self.total_combinations:,} candidates checked"
            )
        elif hasattr(self, "audit_progress_detail_label"):
            self.audit_progress_detail_label.setText(f"{attempts_count:,} candidates checked")

        if not was_stopped:
            self.eta_label.setText("0s")
            if hasattr(self, "remaining_label"):
                self.remaining_label.setText("Remaining: 0s")

        if password:
            self.progress_bar.setValue(self.total_combinations or self.progress_bar.maximum())
            self.progress_percent_label.setText("100%")
            self.eta_label.setText("0s")
            if hasattr(self, "remaining_label"):
                self.remaining_label.setText("Remaining: 0s")

        if password and verified:
            self.show_compromised_dialog(password, attempts, elapsed)
            self.statusBar().showMessage("Authorized test complete: weak credential verified")
            self._append_audit_timeline("Weak credential verified")
            self._set_audit_phase("Compromised", "danger")
            if hasattr(self, "audit_status_note"):
                self.audit_status_note.setText(
                    "Authorized test completed with a verified weak credential. Review and remediate immediately."
                )
            self._log_event("AUDIT", "Weak credential verified.")
        elif was_stopped:
            QMessageBox.information(self, "Audit Stopped", "Authorized test was stopped safely.")
            self.statusBar().showMessage("Authorized test stopped by user")
            self._set_audit_phase("Stopped", "warning")
            if hasattr(self, "audit_status_note"):
                self.audit_status_note.setText(
                    "Authorized test stopped safely by user request."
                )
            self._log_event("WARNING", "Authorized test stopped by user.")
        else:
            QMessageBox.information(self, "Audit Complete", "No credential match found within current search space.")
            self.statusBar().showMessage("Authorized test complete: no credential match")
            self._set_audit_phase("Completed", "success")
            if hasattr(self, "audit_status_note"):
                self.audit_status_note.setText(
                    "Authorized test completed with no credential match in the current search space."
                )
            self._log_event("INFO", "Authorized test completed with no credential match.")

        self._append_audit_timeline("Report generated")
        self._finalize_audit_report(password, attempts, elapsed, verified)

    def show_compromised_dialog(self, password: str, attempts: int, elapsed: float):
        dlg = QDialog(self)
        dlg.setWindowTitle("Weak Credential Verified")
        dlg.setModal(True)
        dlg.setMinimumWidth(430)
        dlg.setStyleSheet("""
            QDialog { background:#060f1f; border:1px solid #1d5c8f; border-radius:14px; }
            QLabel[role="tag"] { color:#8ecfff; font-size:9pt; font-weight:700; letter-spacing:1px; }
            QLabel[role="headline"] { color:#f4fbff; font-size:19px; font-weight:900; }
            QFrame[role="card"] { background:#07152b; border:1px solid #1f507d; border-radius:10px; }
            QLabel[role="key"]   { color:#57b7ff; font-size:9pt; font-weight:700; }
            QLabel[role="value"] { color:#f2f9ff; font-size:10.5pt; font-weight:700; }
            QPushButton {
                background:#008dd8; color:#01182b; border:none; border-radius:10px;
                min-height:38px; padding:0 20px; font-size:10pt; font-weight:900;
            }
            QPushButton:hover { background:#00a0f2; }
        """)
        root = QVBoxLayout(dlg); root.setContentsMargins(18, 14, 18, 14); root.setSpacing(12)
        tag = QLabel("VERIFIED ACCESS"); tag.setProperty("role", "tag"); root.addWidget(tag)
        hl = QLabel("Credential Match Detected"); hl.setProperty("role", "headline"); root.addWidget(hl)
        sub = QLabel("Weak credential verified during authorized test."); sub.setStyleSheet("color:#8ab0cf;"); root.addWidget(sub)
        card = QFrame(); card.setProperty("role", "card")
        cl = QGridLayout(card); cl.setContentsMargins(12, 12, 12, 12); cl.setSpacing(8)
        for row, (key, value) in enumerate([
            ("SSID", str(self.config.get("ssid") or "-")),
            ("Credential", str(password)),
            ("Attempts", f"{attempts:,}"),
            ("Time", f"{elapsed:.1f}s"),
        ]):
            kl = QLabel(key.upper()); kl.setProperty("role", "key")
            vl = QLabel(value);       vl.setProperty("role", "value")
            vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            cl.addWidget(kl, row, 0); cl.addWidget(vl, row, 1)
        root.addWidget(card)
        br = QHBoxLayout(); br.addStretch()
        ok_btn = QPushButton("CONTINUE"); ok_btn.clicked.connect(dlg.accept)
        br.addWidget(ok_btn); root.addLayout(br)
        dlg.exec()

    def _selected_network_for_report(self):
        target_bssid = (self.config.get("target_bssid") or "").strip().lower()
        for net in self.scan_results:
            if (net.bssid or "").strip().lower() == target_bssid:
                return net
        if self.scan_results:
            return self.scan_results[0]
        return None

    def _finalize_audit_report(self, password: str, attempts: int, elapsed: float, verified: bool):
        net = self._selected_network_for_report()
        congestion_map = self._congestion_map(self.scan_results)
        selected_network: dict[str, Any] = {}
        findings: list[str] = []
        recs: list[str] = []
        score_payload: dict[str, Any] = {}
        if net is not None:
            channel = int(net.channel or 0)
            congestion = congestion_map.get(channel, "Clear")
            score_result = self._score_for_network(net, congestion)
            selected_network = {
                "ssid": net.ssid or "<hidden>",
                "bssid": net.bssid or "",
                "vendor": self._vendor_from_bssid(net.bssid or ""),
                "security": net.security or "Unknown",
                "signal": int(net.signal or 0),
                "channel": channel,
                "band": self._channel_to_band(channel),
                "congestion": congestion,
                "risk": self._risk_label(int(net.signal or 0), net.security or ""),
            }
            score_payload = {"score": score_result.score, "label": score_result.label}
            findings.extend(score_result.findings)
            recs.extend(self._recommendations_for_network(net, congestion))

        if password and verified:
            findings.append("Credential match detected and verified during authorized test.")
        elif not password:
            findings.append("No credential match detected in current test scope.")

        checklist = self._collect_audit_checklist()
        try:
            result = ReportGenerator.generate(
                config=self.config,
                password=password or "",
                attempts=attempts,
                elapsed=elapsed,
                verified=verified,
                authorization=self.authorization_record,
                scan_summary=calc_scan_summary(self.scan_results),
                selected_network=selected_network,
                security_score=score_payload,
                findings=findings,
                recommendations=recs,
                timeline=self.audit_timeline,
                checklist=checklist,
            )
            self.last_report_outputs = result.get("outputs", {})
            self.last_audit_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.refresh_reports_list()
            self.update_dashboard()
            self._show_toast("Report generated.", "success")
            self._log_event("AUDIT", "Audit report generated.")
        except Exception as exc:
            self._show_toast("Report generation failed.", "error")
            self._log_event("ERROR", f"Report generation failed: {exc}")
            QMessageBox.warning(self, "Report Error", f"Report export failed: {exc}")

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Tab 4 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Recon
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def create_recon_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "NETWORK INTELLIGENCE")
        root = QHBoxLayout(tab)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ LEFT SIDEBAR ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        sidebar_outer = QWidget()
        sidebar_outer.setProperty("role", "recon_sidebar")
        sidebar_outer.setFixedWidth(200)
        sb = QVBoxLayout(sidebar_outer)
        sb.setContentsMargins(12, 14, 8, 14)
        sb.setSpacing(0)

        title_lbl = QLabel("Network Intelligence")
        title_lbl.setProperty("role", "recon_title")
        sub_lbl = QLabel("Network intelligence")
        sub_lbl.setProperty("role", "recon_subtitle")
        sb.addWidget(title_lbl); sb.addWidget(sub_lbl); sb.addSpacing(14)

        mod_section = QLabel("MODULES")
        mod_section.setProperty("role", "recon_section_title")
        sb.addWidget(mod_section); sb.addSpacing(6)

        modules = [
            ("1 Full Intelligence Scan", "full"),
            ("2 My Device",           "my_device"),
            ("3 Infrastructure",      "infrastructure"),
            ("4 Wireless Analysis",   "wireless"),
            ("5 Internet Identity",   "internet"),
            ("6 Performance",         "performance"),
            ("7 Resources & Sharing", "resources"),
            ("8 Security Insights",   "security"),
            ("9 Traffic Analysis",    "traffic"),
        ]
        self._mod_buttons: dict[str, QPushButton] = {}
        self._mod_status: dict[str, str] = {}  # "idle" | "running" | "done" | "error"
        for label, mid in modules:
            btn = QPushButton(f"  {label}")
            btn.setProperty("role", "mod_btn")
            btn.setFixedHeight(34)
            btn.clicked.connect(lambda _checked, m=mid: self._run_recon_module(m))
            sb.addWidget(btn); sb.addSpacing(6)
            self._mod_buttons[mid] = btn
            self._mod_status[mid] = "idle"

        sb.addSpacing(8)
        run_all_btn = QPushButton(">  RUN ALL MODULES")
        run_all_btn.setProperty("role", "run_all_btn")
        run_all_btn.setFixedHeight(34)
        run_all_btn.clicked.connect(lambda: self._run_recon_module("all"))
        sb.addWidget(run_all_btn)
        sb.addStretch()

        # Running indicator
        self.recon_status_strip = QFrame()
        self.recon_status_strip.setProperty("role", "recon_running")
        self.recon_status_strip.setVisible(False)
        self.recon_status_strip.setFixedHeight(52)
        ss = QVBoxLayout(self.recon_status_strip)
        ss.setContentsMargins(10, 6, 10, 6); ss.setSpacing(4)
        ss_top = QHBoxLayout(); ss_top.setSpacing(6)
        self.recon_spinner_label = QLabel("ÃƒÂ¢Ã¢â‚¬â€Ã‚Â")
        self.recon_spinner_label.setProperty("role", "recon_spinner")
        self._spinner_frames = ["ÃƒÂ¢Ã¢â‚¬â€Ã‚Â", "ÃƒÂ¢Ã¢â‚¬â€Ã¢â‚¬Å“", "ÃƒÂ¢Ã¢â‚¬â€Ã¢â‚¬Ëœ", "ÃƒÂ¢Ã¢â‚¬â€Ã¢â‚¬â„¢"]
        self._spinner_idx = 0
        self.recon_running_label = QLabel("RunningÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
        self.recon_running_label.setProperty("role", "recon_running_label")
        ss_top.addWidget(self.recon_spinner_label); ss_top.addWidget(self.recon_running_label); ss_top.addStretch()
        self.recon_pulse_bar = QProgressBar()
        self.recon_pulse_bar.setRange(0, 0); self.recon_pulse_bar.setFixedHeight(4); self.recon_pulse_bar.setTextVisible(False)
        self.recon_pulse_bar.setProperty("role", "recon_pulse")
        ss.addLayout(ss_top); ss.addWidget(self.recon_pulse_bar)
        sb.addWidget(self.recon_status_strip)

        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(120)
        self._spinner_timer.timeout.connect(self._tick_spinner)

        splitter.addWidget(sidebar_outer)

        # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ RIGHT OUTPUT PANEL ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(8, 14, 14, 14)
        right_layout.setSpacing(8)

        # Toolbar
        toolbar_frame = QFrame()
        toolbar_frame.setProperty("role", "recon_toolbar_frame")
        tbl = QHBoxLayout(toolbar_frame)
        tbl.setContentsMargins(8, 5, 8, 5); tbl.setSpacing(5)

        self._pill_counts = {"info": 0, "data": 0, "warn": 0, "error": 0}
        self._recon_pill_all   = self._make_filter_pill("All", active=True)
        self._recon_pill_info  = self._make_filter_pill("Info 0")
        self._recon_pill_data  = self._make_filter_pill("Data 0")
        self._recon_pill_warn  = self._make_filter_pill("Warn 0")
        self._recon_pill_error = self._make_filter_pill("Error 0")
        for pill in (self._recon_pill_all, self._recon_pill_info, self._recon_pill_data, self._recon_pill_warn, self._recon_pill_error):
            tbl.addWidget(pill)
        tbl.addStretch()

        for label, slot in [("COPY", self._recon_copy_log), ("CSV", self._recon_export_csv), ("JSON", self._recon_export_json)]:
            btn = QPushButton(label); btn.setProperty("role", "toolbar_btn"); btn.setFixedHeight(28); btn.clicked.connect(slot); tbl.addWidget(btn)
        clr = QPushButton("CLEAR"); clr.setProperty("role", "clear_btn"); clr.setFixedHeight(28); clr.clicked.connect(self._recon_clear); tbl.addWidget(clr)

        sep = QFrame(); sep.setFrameShape(QFrame.VLine); sep.setProperty("role", "recon_separator"); tbl.addWidget(sep)

        self._severity_combo = QComboBox()
        self._severity_combo.addItems(["All", "Alerts (Warn + Error)", "Info", "Data", "Warn", "Error"])
        self._severity_combo.setFixedHeight(28)
        self._severity_combo.setFixedWidth(140)
        self._severity_combo.currentIndexChanged.connect(self._on_recon_view_changed)
        tbl.addWidget(self._severity_combo)

        tbl.addSpacing(6)
        
        self._autoscroll_check = QCheckBox("Auto-scroll"); self._autoscroll_check.setChecked(True)
        self._autoscroll_check.setProperty("role", "recon_toggle")
        tbl.addWidget(self._autoscroll_check)

        self._collapse_sections_check = QCheckBox("Collapse sections")
        self._collapse_sections_check.setChecked(False)
        self._collapse_sections_check.setProperty("role", "recon_toggle")
        self._collapse_sections_check.toggled.connect(self._on_recon_view_changed)
        tbl.addWidget(self._collapse_sections_check)
        right_layout.addWidget(toolbar_frame)

        # Summary strip
        summary_frame = QFrame(); summary_frame.setProperty("role", "recon_summary")
        sl2 = QHBoxLayout(summary_frame); sl2.setContentsMargins(8, 6, 8, 6); sl2.setSpacing(6)
        self._summary_sections = QLabel("Sections 0"); self._summary_sections.setProperty("role", "summary_card")
        self._summary_entries  = QLabel("Entries 0");  self._summary_entries.setProperty("role", "summary_card")
        self._summary_alerts   = QLabel("Alerts 0");   self._summary_alerts.setProperty("role", "summary_card")
        self._summary_view     = QLabel("View ALL");   self._summary_view.setProperty("role", "summary_card")
        for w in [self._summary_sections, self._summary_entries, self._summary_alerts, self._summary_view]:
            sl2.addWidget(w)
        sl2.addStretch()
        right_layout.addWidget(summary_frame)

        # Output QTextEdit
        output_frame = QFrame(); output_frame.setProperty("role", "recon_output_frame")
        ofl = QVBoxLayout(output_frame); ofl.setContentsMargins(0, 0, 0, 0); ofl.setSpacing(0)
        self.recon_output = QTextEdit()
        self.recon_output.setReadOnly(True)
        self.recon_output.setFont(QFont("Consolas", 10))
        self.recon_output.setPlaceholderText("Select an intelligence module from the sidebar and click Run, or press > RUN ALL MODULES.")
        self.recon_output.setProperty("role", "recon_output")
        ofl.addWidget(self.recon_output)
        right_layout.addWidget(output_frame, 1)

        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([200, 900])
        self._update_recon_summary()

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Recon helpers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def _make_filter_pill(self, text: str, active: bool = False) -> QLabel:
        pill = QLabel(text)
        pill.setFixedHeight(24)
        pill.setProperty("role", "recon_pill")
        pill.setProperty("state", "active" if active else "idle")
        return pill

    def _recon_copy_log(self):
        QApplication.clipboard().setText(self.recon_output.toPlainText())
        self.statusBar().showMessage("Log copied to clipboard")

    def _recon_export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "recon_data.csv", "CSV Files (*.csv)")
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Tag", "Kind", "Label", "Value", "Content"])
            rows = self._recon_records or [{"tag": "LOG", "kind": "line", "content": ln.strip()}
                                            for ln in self.recon_output.toPlainText().splitlines() if ln.strip()]
            for row in rows:
                w.writerow([row.get("tag",""), row.get("kind",""), row.get("label",""), row.get("value",""), row.get("content","")])
        self.statusBar().showMessage(f"CSV exported ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ {path}")

    def _recon_export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "recon_data.json", "JSON Files (*.json)")
        if not path: return
        rows = self._recon_records or [{"tag": "LOG", "kind": "line", "content": ln.strip()}
                                        for ln in self.recon_output.toPlainText().splitlines() if ln.strip()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        self.statusBar().showMessage(f"JSON exported ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ {path}")

    def _recon_clear(self):
        self.recon_output.clear()
        self._reset_recon_metrics()
        self._recon_records = []
        self._update_recon_summary()
        self.statusBar().showMessage("Network intelligence output cleared")

    def _reset_recon_metrics(self):
        self._pill_counts = {"info": 0, "data": 0, "warn": 0, "error": 0}
        self._recon_pill_info.setText("Info 0")
        self._recon_pill_data.setText("Data 0")
        self._recon_pill_warn.setText("Warn 0")
        self._recon_pill_error.setText("Error 0")

    def _on_recon_view_changed(self):
        combo_text = self._severity_combo.currentText().lower()
        if "alerts"  in combo_text: self._recon_filter_mode = "alerts"
        elif "info"  in combo_text: self._recon_filter_mode = "info"
        elif "data"  in combo_text: self._recon_filter_mode = "data"
        elif "warn"  in combo_text: self._recon_filter_mode = "warn"
        elif "error" in combo_text: self._recon_filter_mode = "error"
        else:                       self._recon_filter_mode = "all"
        self._recon_collapse_sections = self._collapse_sections_check.isChecked()
        self._refresh_recon_view()

    def _passes_recon_filter(self, rec: dict) -> bool:
        mode = self._recon_filter_mode
        if mode == "all": return True
        kind = rec.get("kind", "")
        tag  = str(rec.get("tag", "")).upper()
        if kind in ("section",): return True
        if kind in ("divider", "table_header", "table_row", "kv", "meter"): return mode == "all"
        if mode == "alerts": return tag in ("WARN", "ERROR")
        return tag == mode.upper()

    def _update_recon_summary(self):
        sections = sum(1 for r in self._recon_records if r.get("kind") == "section")
        entries  = sum(1 for r in self._recon_records if r.get("kind") not in ("section", "divider"))
        alerts   = sum(1 for r in self._recon_records if str(r.get("tag", "")).upper() in ("WARN", "ERROR"))
        view = self._recon_filter_mode.upper() if self._recon_filter_mode != "alerts" else "ALERTS"
        if self._recon_collapse_sections: view += " + COLLAPSED"
        self._summary_sections.setText(f"Sections {sections}")
        self._summary_entries.setText(f"Entries {entries}")
        self._summary_alerts.setText(f"Alerts {alerts}")
        self._summary_view.setText(f"View {view}")

    def _tick_spinner(self):
        self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_frames)
        self.recon_spinner_label.setText(self._spinner_frames[self._spinner_idx])

    def _set_mod_button_role(self, mid: str, role: str):
        btn = self._mod_buttons.get(mid)
        if not btn: return
        self._mod_status[mid] = role
        prefix_map = {"running": "ÃƒÂ¢Ã…Â¸Ã‚Â³ ", "done": "ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ ", "error": "ÃƒÂ¢Ã…â€œÃ¢â‚¬â€ ", "idle": "  "}
        prefix = prefix_map.get(role, "  ")
        # Find the original label text (strip any existing prefix)
        base = btn.text().strip().lstrip("ÃƒÂ¢Ã…Â¸Ã‚Â³ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ÃƒÂ¢Ã…â€œÃ¢â‚¬â€").strip()
        btn.setText(f"{prefix}{base}")
        btn.setProperty("role", f"mod_btn_{role}" if role != "idle" else "mod_btn")
        btn.style().unpolish(btn); btn.style().polish(btn)

    def _set_recon_running(self, module_name: str):
        self.recon_running_label.setText(f"{module_name.upper().replace('_', ' ')}ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
        self.recon_status_strip.setVisible(True)
        self._spinner_timer.start()
        for mid in self._mod_buttons:
            if mid == module_name:
                self._set_mod_button_role(mid, "running")

    def _set_recon_idle(self, module_name: str = "", success: bool = True):
        self._spinner_timer.stop()
        self.recon_status_strip.setVisible(False)
        if module_name:
            self._set_mod_button_role(module_name, "done" if success else "error")

    def _run_recon_module(self, module_id: str):
        self.recon_output.clear()
        self._reset_recon_metrics()
        self._recon_records = []
        self._update_recon_summary()
        self._set_recon_running(module_id)
        self.statusBar().showMessage(f"Running network intelligence module: {module_id}")
        if self.worker and self.worker.isRunning():
            self.worker.quit()
            self.worker.wait(800)

        import ghostlink.network.recon as recon_mod
        func_map = {
            "full":           lambda: recon_mod.print_recon_result(recon_mod.full_network_recon()),
            "my_device":      recon_mod.scan_my_device,
            "infrastructure": recon_mod.scan_infrastructure,
            "wireless":       recon_mod.scan_wireless,
            "internet":       recon_mod.scan_internet_identity,
            "performance":    recon_mod.scan_performance,
            "resources":      recon_mod.scan_resources,
            "security":       recon_mod.scan_security,
            "traffic":        recon_mod.scan_traffic,
            "all":            self._run_all_modules,
        }
        func = func_map.get(module_id)
        if not func:
            self._set_recon_idle(module_id, success=False)
            self._append_recon_card("ERROR", f"Unknown module: {module_id}", "#ff5f6d")
            return

        self._current_recon_module = module_id
        self.worker = ReconWorker(func)
        self.worker.output.connect(self._render_recon_output)
        self.worker.finished.connect(self._on_recon_module_done)
        self.worker.error.connect(self._on_recon_module_error)
        self.worker.start()

    def _on_recon_module_done(self):
        mid = getattr(self, "_current_recon_module", "")
        self._set_recon_idle(mid, success=True)
        self.statusBar().showMessage("Network intelligence module complete")

    def _on_recon_module_error(self, e: str):
        mid = getattr(self, "_current_recon_module", "")
        self._set_recon_idle(mid, success=False)
        self._append_recon_card("ERROR", str(e), "#ff5f6d")
        self.statusBar().showMessage("Network intelligence module failed")

    def _run_all_modules(self):
        import ghostlink.network.recon as recon_mod
        for m in [recon_mod.scan_my_device, recon_mod.scan_infrastructure, recon_mod.scan_wireless,
                  recon_mod.scan_internet_identity, recon_mod.scan_performance, recon_mod.scan_resources,
                  recon_mod.scan_security, recon_mod.scan_traffic]:
            m()

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Recon rendering
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    _TAG_CFG: dict[str, tuple] = {
        "DATA":  ("#061e10", "#22c55e", "#22c55e", "#0a2e18"),
        "INFO":  ("#051a28", "#38bdf8", "#38bdf8", "#062233"),
        "WARN":  ("#1e1505", "#f59e0b", "#f59e0b", "#2a1c06"),
        "ERROR": ("#1e0509", "#ff5f6d", "#ff5f6d", "#2a070c"),
        "DONE":  ("#031a0a", "#22c55e", "#22c55e", "#0a2e18"),
        "LOG":   ("#06111e", "#1e4d7a", "#4a8ab5", "#071525"),
    }

    @staticmethod
    def _hl_addresses(safe: str) -> str:
        safe = re.sub(r"(\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)",
                      r"<span style='color:#c084fc;font-weight:700;'>\1</span>", safe)
        safe = re.sub(r"(\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d+)?\b)",
                      r"<span style='color:#67e8f9;font-weight:600;'>\1</span>", safe)
        safe = re.sub(r"(\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b)",
                      r"<span style='color:#2dd4bf;font-weight:700;'>\1</span>", safe)
        safe = re.sub(r"(?<![=#\w\-])(\b\d+\b)(?![;%\w\-])",
                      r"<span style='color:#fbbf24;'>\1</span>", safe)
        return safe

    @staticmethod
    def _hl_semantic(safe: str) -> str:
        safe = re.sub(r"\b(enabled|on|active|responsive|connected|listening|established|secure|good|excellent)\b",
                      r"<span style='color:#22c55e;font-weight:700;'>\1</span>", safe, flags=re.IGNORECASE)
        safe = re.sub(r"\b(warn|warning|degraded|unknown|limited|congested)\b",
                      r"<span style='color:#f59e0b;font-weight:700;'>\1</span>", safe, flags=re.IGNORECASE)
        safe = re.sub(r"\b(error|failed|disabled|off|blocked|critical|vulnerable|open network)\b",
                      r"<span style='color:#ff6b7a;font-weight:700;'>\1</span>", safe, flags=re.IGNORECASE)
        return safe

    def _strip_ansi(self, text: str) -> str:
        return strip_ansi(text)

    def _split_into_lines(self, raw: str) -> list[str]:
        return split_into_lines(raw)

    _SECTION_KW = [
        "route table","ipv4","ipv6","persistent routes","active routes","active tcp","active udp",
        "connections","system identity","network interfaces","dns servers","internet identity",
        "my device","infrastructure","performance","resources","security","traffic analysis",
        "recon result","wireless","ghostlink",
    ]

    @staticmethod
    def _is_meter_line(line: str) -> bool:
        compact = line.strip()
        if len(compact) < 8: return False
        return bool(re.fullmatch(r"[#=\[\]\(\)\|/\\+\-_.:;%\sÃƒÂ¢Ã¢â‚¬â€Ã¢â‚¬Â ÃƒÂ¢Ã¢â‚¬â€Ã¢â‚¬Â¡ÃƒÂ¢Ã¢â‚¬â€œÃ¢â‚¬Å“ÃƒÂ¢Ã¢â‚¬â€œÃ¢â‚¬â„¢ÃƒÂ¢Ã¢â‚¬â€œÃ¢â‚¬ËœÃƒÂ¢Ã¢â‚¬â€œÃ‹â€ ÃƒÂ¢Ã¢â‚¬â€œÃ…â€™ÃƒÂ¢Ã¢â‚¬ÂÃ‚Â¼ÃƒÂ¢Ã¢â‚¬ÂÃ‚Â¤ÃƒÂ¢Ã¢â‚¬ÂÃ…â€œÃƒÂ¢Ã¢â‚¬ÂÃ‚Â¬ÃƒÂ¢Ã¢â‚¬ÂÃ‚Â´ÃƒÂ¢Ã¢â‚¬Â¢Ã‚ÂªÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â«]+", compact))

    def _classify_line(self, line: str) -> tuple[str, str]:
        return classify_line(line)

    def _divider_html(self) -> str:
        return "<div style='height:1px;margin:8px 2px;background:#0f2d4a;'></div>"

    def _section_html(self, body: str) -> str:
        display = html_mod.escape(body).rstrip(":")
        is_major = bool(re.match(r"^\[\d+\]", body.strip())) or "ghostlink" in body.lower()
        if is_major:
            margin, pad, bg, border, left, size = "16px 0 6px 0", "10px 16px", "#0a2442", "1px solid #245489", "5px solid #60a5fa", "9.5pt"
        else:
            margin, pad, bg, border, left, size = "10px 0 4px 0", "7px 12px", "#081a2f", "1px solid #17395f", "3px solid #2e88d8", "9pt"
        return (
            f"<div style='margin:{margin};padding:{pad};background:{bg};border:{border};"
            f"border-left:{left};border-radius:7px;'>"
            f"<span style='color:#dbeafe;font-family:Consolas,monospace;font-size:{size};"
            f"font-weight:800;letter-spacing:1.2px;text-transform:uppercase;'>{display}</span></div>"
        )

    @staticmethod
    def _split_table_cols(body: str) -> list[str]:
        return split_table_cols(body)

    def _kv_html(self, body: str) -> str:
        if "\t" not in body:
            return self._tagged_card_html("LOG", body)
        label, value = body.split("\t", 1)
        safe_label = html_mod.escape(label.strip())
        safe_value = self._hl_semantic(self._hl_addresses(html_mod.escape(value.strip())))
        return (
            f"<table width='100%' cellspacing='0' cellpadding='0' style='margin:3px 0;"
            "background:#061a2f;border:1px solid #113253;border-left:3px solid #1d8ee0;border-radius:5px;'>"
            "<tr>"
            f"<td width='250' style='padding:6px 10px;color:#8dbce1;font-family:Consolas,monospace;font-size:8.5pt;font-weight:700;'>{safe_label}</td>"
            f"<td style='padding:6px 10px;color:#d6ecff;font-family:Consolas,monospace;font-size:9.5pt;word-break:break-word;'>{safe_value}</td>"
            "</tr></table>"
        )

    def _table_header_html(self, body: str) -> str:
        cols = self._split_table_cols(body)
        cells = "".join(
            f"<th style='padding:7px 10px;text-align:left;color:#7eb5e6;"
            f"font-family:Consolas,monospace;font-size:8pt;font-weight:800;"
            f"letter-spacing:0.8px;text-transform:uppercase;border-bottom:1px solid #2e6ba7;'>"
            f"{html_mod.escape(col)}</th>" for col in cols
        )
        return (
            "<table width='100%' cellspacing='0' cellpadding='0' style='margin:6px 0 0 0;"
            "border-collapse:collapse;border:1px solid #12385e;border-radius:6px;"
            "overflow:hidden;background:#091b31;'>"
            f"<thead><tr style='background:#0b2240;'>{cells}</tr></thead><tbody>"
        )

    def _meter_html(self, body: str) -> str:
        return (
            "<table width='100%' cellspacing='0' cellpadding='0' style='margin:4px 0 8px 0;"
            "background:#06111f;border:1px solid #143a62;border-left:3px solid #38bdf8;border-radius:6px;'>"
            "<tr>"
            "<td width='64' style='padding:5px 8px;text-align:center;color:#7ec3f6;"
            "font-family:Consolas,monospace;font-size:7pt;font-weight:900;letter-spacing:1px;"
            "border-right:1px solid #1f4f7f;'>METER</td>"
            f"<td style='padding:6px 10px;color:#cde8ff;font-family:Consolas,monospace;"
            f"font-size:8.5pt;white-space:pre;'>{html_mod.escape(body)}</td>"
            "</tr></table>"
        )

    def _table_row_html(self, body: str, idx: int, col_count: int = 0) -> str:
        cols = self._split_table_cols(body)
        target = max(col_count, len(cols))
        cols.extend([""] * (target - len(cols)))
        bg = "#071627" if idx % 2 == 0 else "#0a1e35"
        cells = "".join(
            f"<td style='padding:6px 10px;color:#b8ddf8;font-family:Consolas,monospace;"
            f"font-size:9pt;border-bottom:1px solid #0d2d4a;white-space:nowrap;'>"
            f"{self._hl_addresses(html_mod.escape(col))}</td>" for col in cols
        )
        return f"<tr style='background:{bg};'>{cells}</tr>"

    def _tagged_card_html(self, tag: str, body: str) -> str:
        bg, accent, badge_text, badge_bg = self._TAG_CFG.get(tag, self._TAG_CFG["LOG"])
        is_placeholder = body == "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â"
        safe = html_mod.escape(body)
        if not is_placeholder:
            safe = self._hl_semantic(self._hl_addresses(safe))
        body_color = "#597894" if is_placeholder else "#d9eeff"
        body_size  = "8.5pt"   if is_placeholder else "9.5pt"
        body_style = "font-style:italic;" if is_placeholder else ""

        # Increment pill counts ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â only once per actual record insertion
        tag_lower = tag.lower()
        if tag_lower in self._pill_counts and not is_placeholder:
            self._pill_counts[tag_lower] += 1
            count = self._pill_counts[tag_lower]
            pill_map = {"info": self._recon_pill_info, "data": self._recon_pill_data,
                        "warn": self._recon_pill_warn, "error": self._recon_pill_error}
            if tag_lower in pill_map:
                pill_map[tag_lower].setText(f"{tag.capitalize()} {count}")

        return (
            f"<table width='100%' cellspacing='0' cellpadding='0' style='margin:3px 0;"
            f"background:{bg};border:1px solid #0d2d4e;border-left:3px solid {accent};border-radius:5px;'>"
            "<tr>"
            f"<td width='64' style='padding:5px 8px;background:{badge_bg};color:{badge_text};"
            f"font-family:Consolas,monospace;font-size:7pt;font-weight:900;letter-spacing:1px;"
            f"text-align:center;border-right:1px solid {accent}33;'>{tag}</td>"
            f"<td style='padding:6px 10px;color:{body_color};font-family:Consolas,monospace;"
            f"font-size:{body_size};line-height:1.72;word-break:break-word;{body_style}'>{safe}</td>"
            "</tr></table>"
        )

    def _render_recon_output(self, raw: str) -> None:
        self._recon_records.extend(parse_recon_output(raw))
        self._refresh_recon_view()

    def _looks_like_table_header(self, body: str) -> bool:
        return looks_like_table_header(body)

    def _append_recon_card(self, tag: str, body: str, _color: str = "") -> None:
        self._recon_records.append({"tag": tag, "kind": "line", "content": body})
        self._refresh_recon_view()

    def _refresh_recon_view(self):
        """
        Rebuild the HTML view from _recon_records.
        Pill counts are re-tallied here so they always reflect the filtered view accurately.
        """
        self._reset_recon_metrics()
        self._update_recon_summary()
        self.recon_output.clear()
        if not self._recon_records:
            return

        parts: list[str] = []
        prev_kind = None
        in_table  = False

        for rec in self._recon_records:
            if not self._passes_recon_filter(rec):
                continue

            kind    = rec.get("kind", "")
            tag     = str(rec.get("tag", "LOG")).upper()
            content = str(rec.get("content", ""))

            if self._recon_collapse_sections and kind not in ("section", "divider"):
                if tag not in ("WARN", "ERROR"):
                    continue

            if kind == "divider":
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._divider_html())

            elif kind == "section":
                if in_table: parts.append("</tbody></table>"); in_table = False
                if prev_kind not in (None, "section", "divider"):
                    parts.append("<div style='height:4px;'></div>")
                parts.append(self._section_html(content))

            elif kind == "kv":
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._kv_html(f"{rec.get('label','').strip()}\t{rec.get('value','').strip()}"))

            elif kind == "meter":
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._meter_html(content))

            elif kind == "table_header":
                if in_table: parts.append("</tbody></table>")
                parts.append(self._table_header_html(content))
                in_table = True

            elif kind == "table_row":
                if not in_table:
                    parts.append(
                        "<table width='100%' cellspacing='0' cellpadding='0' style='margin:6px 0 0 0;"
                        "border-collapse:collapse;border:1px solid #12385e;border-radius:6px;"
                        "overflow:hidden;background:#091b31;'><tbody>"
                    )
                    in_table = True
                cols = rec.get("columns", [])
                row_text = "  ".join(str(c) for c in cols) if isinstance(cols, list) and cols else content
                parts.append(self._table_row_html(row_text, int(rec.get("index", 0)), int(rec.get("col_count", 0))))

            else:
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._tagged_card_html(tag, content))

            prev_kind = kind

        if in_table:
            parts.append("</tbody></table>")

        if parts:
            self.recon_output.insertHtml("\n".join(parts))
            self.recon_output.insertHtml("<br>")
            if self._autoscroll_check.isChecked():
                self.recon_output.moveCursor(QTextCursor.End)

    def create_reports_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "REPORTS")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(
            self._make_tab_header(
                "Reports",
                "Review and export authorized audit reports (JSON, HTML, CSV, PDF).",
            )
        )

        filter_row = QHBoxLayout()
        self.report_search_edit = QLineEdit()
        self.report_search_edit.setPlaceholderText("Search reports by SSID or status...")
        self.report_search_edit.textChanged.connect(self.refresh_reports_list)
        filter_row.addWidget(self.report_search_edit)
        self.report_date_filter = QComboBox()
        self.report_date_filter.addItems(["All Dates", "Today", "Last 7 Days"])
        self.report_date_filter.currentIndexChanged.connect(self.refresh_reports_list)
        filter_row.addWidget(self.report_date_filter)
        layout.addLayout(filter_row)

        self.reports_table = QTableWidget(0, 5)
        self.reports_table.setHorizontalHeaderLabels(
            ["Date", "Network SSID", "Security Score", "Result/Status", "Export Format"]
        )
        self.reports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.reports_table.setSelectionMode(QTableWidget.SingleSelection)
        self.reports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.reports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.reports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.reports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.reports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.reports_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        layout.addWidget(self.reports_table, 1)

        btns = QHBoxLayout()
        self.refresh_reports_btn = QPushButton("Refresh")
        self.refresh_reports_btn.setProperty("variant", "secondary")
        self.refresh_reports_btn.clicked.connect(self.refresh_reports_list)
        btns.addWidget(self.refresh_reports_btn)
        self.open_report_btn = QPushButton("Open Report File")
        self.open_report_btn.clicked.connect(self.open_selected_report)
        btns.addWidget(self.open_report_btn)
        self.export_report_pdf_btn = QPushButton("Export PDF")
        self.export_report_pdf_btn.clicked.connect(lambda: self.export_selected_report("pdf"))
        btns.addWidget(self.export_report_pdf_btn)
        self.export_report_html_btn = QPushButton("Export HTML")
        self.export_report_html_btn.clicked.connect(lambda: self.export_selected_report("html"))
        btns.addWidget(self.export_report_html_btn)
        self.export_report_json_btn = QPushButton("Export JSON")
        self.export_report_json_btn.clicked.connect(lambda: self.export_selected_report("json"))
        btns.addWidget(self.export_report_json_btn)
        self.delete_report_btn = QPushButton("Delete Report")
        self.delete_report_btn.setProperty("variant", "danger")
        self.delete_report_btn.clicked.connect(self.delete_selected_report)
        btns.addWidget(self.delete_report_btn)
        btns.addStretch()
        layout.addLayout(btns)

        self.reports_empty_label = QLabel(
            "No reports generated yet. Run an authorized audit to create your first report."
        )
        self.reports_empty_label.setProperty("role", "meta")
        layout.addWidget(self.reports_empty_label)

    def _report_path_for_row(self, row: int) -> Path | None:
        if row < 0 or row >= self.reports_table.rowCount():
            return None
        item = self.reports_table.item(row, 0)
        if not item:
            return None
        raw = item.data(Qt.UserRole)
        if not raw:
            return None
        path = Path(str(raw))
        return path if path.exists() else None

    def refresh_reports_list(self):
        self.reports_cache = ReportGenerator.list_reports()
        if not hasattr(self, "reports_table"):
            return
        query = self.report_search_edit.text().strip().lower() if hasattr(self, "report_search_edit") else ""
        date_mode = self.report_date_filter.currentText() if hasattr(self, "report_date_filter") else "All Dates"
        now = datetime.now()
        rows: list[tuple[Path, dict[str, Any]]] = []
        for path in self.reports_cache:
            try:
                data = ReportGenerator.load_report(path)
            except Exception:
                continue
            ssid = str(data.get("selected_network", {}).get("ssid", "Unknown"))
            status = "Credential Match Detected" if data.get("result", {}).get("credential_match_detected") else "No Match"
            text_blob = f"{ssid} {status} {path.name}".lower()
            if query and query not in text_blob:
                continue
            stamp_text = str(data.get("cover", {}).get("generated_at", ""))
            try:
                dt = datetime.fromisoformat(stamp_text.replace("Z", ""))
            except Exception:
                dt = datetime.fromtimestamp(path.stat().st_mtime)
            if date_mode == "Today" and dt.date() != now.date():
                continue
            if date_mode == "Last 7 Days" and (now - dt).days > 7:
                continue
            rows.append((path, data))

        self.reports_table.setRowCount(len(rows))
        for row, (path, data) in enumerate(rows):
            stamp_text = str(data.get("cover", {}).get("generated_at", ""))
            ssid = str(data.get("selected_network", {}).get("ssid", "Unknown"))
            score = data.get("security_score", {}).get("score", "-")
            status = "Credential Match Detected" if data.get("result", {}).get("credential_match_detected") else "No Match"
            sibling_formats = []
            for ext in ("json", "html", "csv", "pdf"):
                if path.with_suffix(f".{ext}").exists():
                    sibling_formats.append(ext.upper())
            formats = ", ".join(sibling_formats) if sibling_formats else "JSON"
            date_item = QTableWidgetItem(stamp_text)
            date_item.setData(Qt.UserRole, str(path))
            self.reports_table.setItem(row, 0, date_item)
            self.reports_table.setItem(row, 1, QTableWidgetItem(ssid))
            self.reports_table.setItem(row, 2, QTableWidgetItem(str(score)))
            self.reports_table.setItem(row, 3, QTableWidgetItem(status))
            self.reports_table.setItem(row, 4, QTableWidgetItem(formats))

        self.reports_empty_label.setVisible(self.reports_table.rowCount() == 0)
        self.update_dashboard()

    def open_selected_report(self):
        row = self.reports_table.currentRow() if hasattr(self, "reports_table") else -1
        path = self._report_path_for_row(row)
        if not path:
            QMessageBox.information(self, "Reports", "Select a report first.")
            return
        try:
            os.startfile(str(path))  # type: ignore[attr-defined]
        except Exception as exc:
            QMessageBox.warning(self, "Reports", f"Unable to open file: {exc}")

    def export_selected_report(self, fmt: str):
        row = self.reports_table.currentRow() if hasattr(self, "reports_table") else -1
        path = self._report_path_for_row(row)
        if not path:
            QMessageBox.information(self, "Reports", "Select a report first.")
            return
        fmt = fmt.lower().strip()
        sibling = path.with_suffix(f".{fmt}")
        if not sibling.exists():
            data = ReportGenerator.load_report(path)
            if fmt == "html":
                sibling.write_text(ReportGenerator._to_html(data), encoding="utf-8")
            elif fmt == "csv":
                with sibling.open("w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerows(ReportGenerator._to_csv_rows(data))
            elif fmt == "pdf":
                if not ReportGenerator._write_pdf_if_available(data, sibling):
                    QMessageBox.warning(self, "Reports", "PDF export requires reportlab. Install reportlab and retry.")
                    return
            elif fmt == "json":
                sibling.write_text(json.dumps(data, indent=2), encoding="utf-8")
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {fmt.upper()}",
            sibling.name,
            f"{fmt.upper()} files (*.{fmt})",
        )
        if not save_path:
            return
        Path(save_path).write_bytes(sibling.read_bytes())
        self._show_toast(f"Report exported as {fmt.upper()}.", "success")

    def delete_selected_report(self):
        row = self.reports_table.currentRow() if hasattr(self, "reports_table") else -1
        path = self._report_path_for_row(row)
        if not path:
            QMessageBox.information(self, "Reports", "Select a report first.")
            return
        if QMessageBox.question(self, "Delete Report", "Delete selected report and related exports?") != QMessageBox.Yes:
            return
        for ext in ("json", "html", "csv", "pdf"):
            p = path.with_suffix(f".{ext}")
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass
        self._show_toast("Report deleted.", "warning")
        self.refresh_reports_list()

    def create_vault_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "VAULT")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(
            self._make_tab_header(
                "Vault Manager",
                "Stored credential records for authorized testing sessions.",
            )
        )

        self.vault_status_label = QLabel()
        self.vault_status_label.setProperty("role", "meta")
        layout.addWidget(self.vault_status_label)

        search_row = QHBoxLayout()
        self.vault_search_edit = QLineEdit()
        self.vault_search_edit.setPlaceholderText("Search vault entries...")
        self.vault_search_edit.textChanged.connect(self.refresh_vault_view)
        search_row.addWidget(self.vault_search_edit)
        self.vault_lock_btn = QPushButton("Lock")
        self.vault_lock_btn.setProperty("variant", "secondary")
        self.vault_lock_btn.clicked.connect(self.lock_or_unlock_vault)
        search_row.addWidget(self.vault_lock_btn)
        layout.addLayout(search_row)

        self.vault_table = QTableWidget(0, 4)
        self.vault_table.setHorizontalHeaderLabels(["SSID", "Credential", "Verified", "Saved At"])
        self.vault_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vault_table.setSelectionMode(QTableWidget.SingleSelection)
        self.vault_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.vault_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.vault_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.vault_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.vault_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.vault_table, 1)

        buttons = QHBoxLayout()
        reveal_btn = QPushButton("Reveal Selected")
        reveal_btn.clicked.connect(self.reveal_selected_vault_entry)
        buttons.addWidget(reveal_btn)
        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self.copy_selected_vault_entry)
        buttons.addWidget(copy_btn)
        delete_btn = QPushButton("Delete Entry")
        delete_btn.clicked.connect(self.delete_selected_vault_entry)
        buttons.addWidget(delete_btn)
        clear_btn = QPushButton("Clear Vault")
        clear_btn.setProperty("variant", "danger")
        clear_btn.clicked.connect(self.clear_vault_entries)
        buttons.addWidget(clear_btn)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setProperty("variant", "secondary")
        refresh_btn.clicked.connect(self.refresh_vault_view)
        buttons.addWidget(refresh_btn)
        buttons.addStretch()
        layout.addLayout(buttons)

    def _selected_vault_ssid(self) -> str | None:
        row = self.vault_table.currentRow() if hasattr(self, "vault_table") else -1
        if row < 0:
            return None
        item = self.vault_table.item(row, 0)
        return item.text().strip() if item else None

    def lock_or_unlock_vault(self):
        if self.vault.is_unlocked:
            self.vault.lock()
            self._show_toast("Vault locked.", "info")
        else:
            self.vault.unlock("")
            self._show_toast("Vault unlocked.", "success")
        self.refresh_vault_view()

    def refresh_vault_view(self):
        if not hasattr(self, "vault_table"):
            return
        self.vault.load()
        query = self.vault_search_edit.text().strip().lower() if hasattr(self, "vault_search_edit") else ""
        rows = [r for r in self.vault.list_entries() if not query or query in r["ssid"].lower()]
        self.vault_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            self.vault_table.setItem(i, 0, QTableWidgetItem(row["ssid"]))
            masked = "ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢" if not self.vault.is_unlocked else row["password"]
            self.vault_table.setItem(i, 1, QTableWidgetItem(masked))
            self.vault_table.setItem(i, 2, QTableWidgetItem("Yes" if row["verified"] else "No"))
            self.vault_table.setItem(i, 3, QTableWidgetItem(row["timestamp"]))
        enc_text = "Enabled" if self.vault.encryption_enabled else "Not enabled"
        state_text = "Unlocked" if self.vault.is_unlocked else "Locked"
        self.vault_status_label.setText(f"Vault encryption: {enc_text} | State: {state_text}")
        if not self.vault.encryption_enabled:
            self.vault_status_label.setText(self.vault_status_label.text() + " | Vault encryption is not currently enabled.")
        self.vault_lock_btn.setText("Lock" if self.vault.is_unlocked else "Unlock")

    def reveal_selected_vault_entry(self):
        ssid = self._selected_vault_ssid()
        if not ssid:
            QMessageBox.information(self, "Vault", "Select an entry first.")
            return
        if not self.vault.is_unlocked:
            QMessageBox.warning(self, "Vault", "Vault is locked.")
            return
        pwd = self.vault.data.get(ssid, {}).get("password", "")
        QMessageBox.information(self, "Credential", f"{ssid}\n\nCredential: {pwd}")

    def copy_selected_vault_entry(self):
        ssid = self._selected_vault_ssid()
        if not ssid:
            QMessageBox.information(self, "Vault", "Select an entry first.")
            return
        if not self.vault.is_unlocked:
            QMessageBox.warning(self, "Vault", "Unlock vault before copying values.")
            return
        pwd = self.vault.data.get(ssid, {}).get("password", "")
        QApplication.clipboard().setText(pwd)
        self._show_toast("Credential copied.", "success")

    def delete_selected_vault_entry(self):
        ssid = self._selected_vault_ssid()
        if not ssid:
            QMessageBox.information(self, "Vault", "Select an entry first.")
            return
        self.vault.remove(ssid)
        self.refresh_vault_view()
        self._show_toast("Vault entry deleted.", "warning")

    def clear_vault_entries(self):
        if QMessageBox.question(self, "Clear Vault", "Remove all vault entries?") != QMessageBox.Yes:
            return
        self.vault.clear_all()
        self.refresh_vault_view()
        self._show_toast("Vault cleared.", "warning")

    def create_settings_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "SETTINGS")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(
            self._make_tab_header(
                "Settings",
                "Preferences for scan, reporting, safety checks, and presentation style.",
            )
        )

        form_box = QGroupBox("Application Settings")
        form = QFormLayout(form_box)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "Professional", "Cyber"])
        form.addRow("Theme:", self.theme_combo)
        self.default_scan_interval_spin = QSpinBox()
        self.default_scan_interval_spin.setRange(5, 300)
        form.addRow("Default scan interval:", self.default_scan_interval_spin)
        self.default_report_format_combo = QComboBox()
        self.default_report_format_combo.addItems(["HTML", "PDF", "JSON", "CSV"])
        form.addRow("Default report format:", self.default_report_format_combo)
        self.default_export_folder_edit = QLineEdit()
        form.addRow("Default export folder:", self.default_export_folder_edit)
        self.safe_mode_check = QCheckBox("Enable safe mode")
        form.addRow("", self.safe_mode_check)
        self.require_auth_check = QCheckBox("Require authorization before audit")
        form.addRow("", self.require_auth_check)
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["Minimal", "Normal", "Debug"])
        form.addRow("Log level:", self.log_level_combo)
        self.table_density_combo = QComboBox()
        self.table_density_combo.addItems(["Comfortable", "Compact"])
        form.addRow("Table density:", self.table_density_combo)
        self.font_size_combo = QComboBox()
        self.font_size_combo.addItems(["Small", "Normal", "Large"])
        form.addRow("Font size:", self.font_size_combo)
        self.demo_mode_settings_check = QCheckBox("Enable Demo Lab Mode")
        form.addRow("", self.demo_mode_settings_check)
        layout.addWidget(form_box)

        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.setProperty("variant", "success")
        save_btn.clicked.connect(self.save_settings_from_ui)
        btn_row.addWidget(save_btn)
        reset_btn = QPushButton("Reset Settings")
        reset_btn.setProperty("variant", "danger")
        reset_btn.clicked.connect(self.reset_settings_to_defaults)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setFont(QFont("Consolas", 9))
        self.log_viewer.setPlaceholderText("Structured logs will appear here.")
        layout.addWidget(self.log_viewer, 1)
        log_btns = QHBoxLayout()
        refresh_log_btn = QPushButton("Refresh Logs")
        refresh_log_btn.setProperty("variant", "secondary")
        refresh_log_btn.clicked.connect(self.refresh_log_viewer)
        log_btns.addWidget(refresh_log_btn)
        log_btns.addStretch()
        layout.addLayout(log_btns)
        self._load_settings_form_values()

    def save_settings_from_ui(self):
        self.settings.theme = self.theme_combo.currentText()
        self.settings.default_scan_interval = int(self.default_scan_interval_spin.value())
        self.settings.default_report_format = self.default_report_format_combo.currentText()
        self.settings.default_export_folder = self.default_export_folder_edit.text().strip() or "reports"
        self.settings.safe_mode = self.safe_mode_check.isChecked()
        self.settings.require_authorization_before_audit = self.require_auth_check.isChecked()
        self.settings.log_level = self.log_level_combo.currentText()
        self.settings.table_density = self.table_density_combo.currentText()
        self.settings.font_size = self.font_size_combo.currentText()
        self.settings.demo_lab_mode = self.demo_mode_settings_check.isChecked()
        self.settings_store.save(self.settings)
        self._apply_settings_to_ui()
        self._show_toast("Settings saved.", "success")
        self.statusBar().showMessage("Settings saved")
        self._log_event("INFO", "Settings saved.")

    def reset_settings_to_defaults(self):
        self.settings = self.settings_store.reset()
        self._apply_settings_to_ui()
        self._load_settings_form_values()
        self._show_toast("Settings reset.", "warning")
        self._log_event("WARNING", "Settings reset to defaults.")

    def _load_settings_form_values(self):
        if not hasattr(self, "theme_combo"):
            return
        self.theme_combo.setCurrentText(self.settings.theme)
        self.default_scan_interval_spin.setValue(int(self.settings.default_scan_interval))
        self.default_report_format_combo.setCurrentText(self.settings.default_report_format)
        self.default_export_folder_edit.setText(self.settings.default_export_folder)
        self.safe_mode_check.setChecked(bool(self.settings.safe_mode))
        self.require_auth_check.setChecked(bool(self.settings.require_authorization_before_audit))
        self.log_level_combo.setCurrentText(self.settings.log_level)
        self.table_density_combo.setCurrentText(self.settings.table_density)
        self.font_size_combo.setCurrentText(self.settings.font_size)
        self.demo_mode_settings_check.setChecked(bool(self.settings.demo_lab_mode))

    def refresh_log_viewer(self):
        log_path = Path("logs/ghostlink_audit.log")
        if not log_path.exists():
            self.log_viewer.setPlainText("No logs available yet.")
            return
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        self.log_viewer.setPlainText("\n".join(lines[-400:]))

    def create_help_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "HELP")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(
            self._make_tab_header(
                "Help / Learning",
                "Quick Wi-Fi security concepts and ethical-use guidance.",
            )
        )
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setPlainText(
            "What is WPA2?\n"
            "WPA2 is a widely used Wi-Fi security standard that uses strong encryption.\n\n"
            "What is WPA3?\n"
            "WPA3 is the newer Wi-Fi security standard with stronger protections.\n\n"
            "What is SSID?\n"
            "SSID is the visible network name broadcast by a wireless router.\n\n"
            "What is BSSID?\n"
            "BSSID is the unique MAC address identifier of a wireless access point.\n\n"
            "What is channel congestion?\n"
            "Channel congestion means many networks are sharing the same channel, reducing performance.\n\n"
            "Why are open networks risky?\n"
            "Open networks do not require encryption and are vulnerable to unauthorized access.\n\n"
            "How to secure a home Wi-Fi network\n"
            "- Enable WPA2-AES or WPA3\n"
            "- Use a long unique passphrase\n"
            "- Disable WPS\n"
            "- Keep router firmware updated\n"
            "- Secure admin panel credentials\n\n"
            "Ethical use and authorization\n"
            "Use GhostLink only on networks you own or are authorized to test in writing."
        )
        layout.addWidget(help_text, 1)

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Keyboard shortcuts
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def eventFilter(self, obj, event):
        if hasattr(self, "nav_list") and obj is self.nav_list.viewport():
            if event.type() in (QEvent.Resize, QEvent.Wheel, QEvent.Show, QEvent.LayoutRequest):
                row = self.nav_list.currentRow()
                if row >= 0:
                    QTimer.singleShot(0, lambda r=row: self._animate_sidebar_indicator(r, immediate=True))
        return super().eventFilter(obj, event)

    def keyPressEvent(self, event):
        if event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_F:
            self._focus_scan_search()
            event.accept(); return
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if self.tabs.currentIndex() == self.page_index.get("scan", 1) and hasattr(self, "scan_table") and self.scan_table.hasFocus():
                if self.select_btn.isEnabled():
                    self.select_target(); event.accept(); return
        super().keyPressEvent(event)

    def closeEvent(self, event):
        self._scan_auto_timer.stop()
        self._scan_pulse_timer.stop()
        if hasattr(self, "_spinner_timer"):
            self._spinner_timer.stop()
        if self.attack_worker and self.attack_worker.isRunning():
            self.attack_worker.stop()
            self.attack_worker.wait(1500)
        if self.worker and self.worker.isRunning():
            self.worker.quit()
            self.worker.wait(1000)
        super().closeEvent(event)

    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
    # Legacy compat stubs
    # ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

    def _normalize_recon_stream(self, text: str) -> str: return text
    def _parse_recon_line(self, line: str): return self._classify_line(line)
    def _is_divider_line(self, text: str) -> bool: return len(text) >= 6 and bool(re.fullmatch(r"[=\-_.\s]{6,}", text.strip()))
    def _is_section_title(self, text: str) -> bool: tag, _ = self._classify_line(text); return tag == "SECTION"





