#!/usr/bin/env python3
"""
GHOSTLINK GUI Launcher — run from GhostLink project root.
"""
import signal
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from ghostlink.gui.main_window import MainWindow

def _load_app_icon() -> QIcon:
    candidates = []

    # PyInstaller onefile/onedir extraction path
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, "ghostlink.ico"))

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        candidates.append(os.path.join(exe_dir, "ghostlink.ico"))
        # Fallback: use the executable's embedded icon
        candidates.append(sys.executable)
    else:
        project_root = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(project_root, "ghostlink.ico"))

    for icon_path in candidates:
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
            if not icon.isNull():
                return icon
    return QIcon()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app_icon = _load_app_icon()
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)
    window = MainWindow()
    if not app_icon.isNull():
        window.setWindowIcon(app_icon)
    window.show()

    shutdown_requested = {"active": False}

    def request_shutdown(*_):
        if shutdown_requested["active"]:
            return
        shutdown_requested["active"] = True
        window.close()
        app.quit()

    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, request_shutdown)

    signal_timer = QTimer()
    signal_timer.timeout.connect(lambda: None)
    signal_timer.start(250)
    app.aboutToQuit.connect(signal_timer.stop)

    try:
        exit_code = app.exec()
    except KeyboardInterrupt:
        request_shutdown()
        exit_code = 0
    finally:
        signal.signal(signal.SIGINT, previous_sigint)

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
