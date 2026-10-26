"""
app_desktop.py - Native Windows Desktop Application for FileSentinel DLP
Combines:
  - pywebview: Native Chromium/Edge desktop window for the SPLUNK dashboard
  - pystray: System tray icon with right-click menu
  - Native toast notifications for WARNING and CRITICAL policy violations
  - Background watchdog filesystem monitoring
  - Instant and clean shutdown on window close [X] or Ctrl+C
"""

import os
import sys
import time
import signal
import threading
from PIL import Image
import webview

# Ensure project root is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from config import DASHBOARD_HOST, DASHBOARD_PORT, BASE_DIR, RESOURCE_DIR
from monitor import FileMonitor
import alerter
import reporter
from dashboard.app import app as flask_app

ICON_PATH = os.path.join(RESOURCE_DIR, "assets", "icon.png")

# Global state handles
_monitor = None
_tray_icon = None
_main_window = None
_is_monitoring = True
_is_shutting_down = False


def _quit_app(icon=None, item=None):
    """Shuts down all threads, monitor, tray icon, and exits immediately."""
    global _monitor, _tray_icon, _main_window, _is_shutting_down
    if _is_shutting_down:
        return
    _is_shutting_down = True

    print("\n  [+] FileSentinel shutting down...")

    if _monitor:
        try:
            _monitor.stop()
        except Exception:
            pass

    if _tray_icon:
        try:
            _tray_icon.stop()
        except Exception:
            pass

    if _main_window:
        try:
            _main_window.destroy()
        except Exception:
            pass

    # Hard exit guarantees no background threads (Flask, Watchdog) linger in memory
    os._exit(0)


def _handle_exit_signal(sig=None, frame=None):
    """Signal handler for Ctrl+C (SIGINT) and termination (SIGTERM)."""
    _quit_app()


# Register signal handlers
try:
    signal.signal(signal.SIGINT, _handle_exit_signal)
    signal.signal(signal.SIGTERM, _handle_exit_signal)
except Exception:
    pass

# Windows console control handler (handles Ctrl+C even if Python thread is blocked in C loop)
try:
    import win32api

    def _console_ctrl_handler(ctrl_type):
        _quit_app()
        return True

    win32api.SetConsoleCtrlHandler(_console_ctrl_handler, True)
except Exception:
    pass


def _run_flask_server():
    """Runs the local Flask backend server in a background thread."""
    flask_app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, use_reloader=False)


def _show_toast_notification(level: str, message: str, event_data: dict):
    """Dispatches a native Windows toast notification via the system tray icon."""
    global _tray_icon
    if _tray_icon:
        src = event_data.get("source", "")
        file_name = os.path.basename(src) if src else ""
        title = f"FileSentinel [{level}]"
        body = f"{message}\nFile: {file_name}" if file_name else message
        try:
            _tray_icon.notify(body[:120], title)
        except Exception:
            pass


def _on_generate_report(icon=None, item=None):
    """Menu action: generates an audit report and displays notification."""
    report_file = reporter.generate_report()
    if _tray_icon:
        _tray_icon.notify(f"Audit report saved to:\n{os.path.basename(report_file)}", "Report Generated")


def _toggle_monitoring(icon=None, item=None):
    """Menu action: pauses or resumes the filesystem monitor."""
    global _monitor, _is_monitoring
    if _monitor:
        if _is_monitoring:
            _monitor.stop()
            _is_monitoring = False
            if _tray_icon:
                _tray_icon.notify("File transfer monitoring is paused.", "Monitoring Paused")
        else:
            _monitor = FileMonitor()
            _monitor.start()
            _is_monitoring = True
            if _tray_icon:
                _tray_icon.notify("File transfer monitoring has resumed.", "Monitoring Active")


def _show_window(icon=None, item=None):
    """Brings the dashboard desktop window to the front."""
    global _main_window
    if _main_window:
        try:
            _main_window.show()
            _main_window.restore()
        except Exception:
            pass


def _setup_system_tray():
    """Initializes and runs the system tray icon with context menu."""
    global _tray_icon
    import pystray
    from pystray import MenuItem as item

    if os.path.exists(ICON_PATH):
        tray_img = Image.open(ICON_PATH)
    else:
        tray_img = Image.new("RGB", (64, 64), (13, 27, 42))

    menu = pystray.Menu(
        item("Open Dashboard", _show_window, default=True),
        item("Generate Report", _on_generate_report),
        pystray.Menu.SEPARATOR,
        item(lambda text: "Pause Monitoring" if _is_monitoring else "Resume Monitoring", _toggle_monitoring),
        pystray.Menu.SEPARATOR,
        item("Exit FileSentinel", _quit_app),
    )

    _tray_icon = pystray.Icon("FileSentinel", tray_img, "FileSentinel DLP", menu)
    _tray_icon.run()


def _on_window_closing():
    """When the user closes the window with [X], cleanly exit the entire application."""
    _quit_app()


def launch_desktop_app():
    """Main entry point for the desktop application."""
    global _monitor, _main_window

    # 1. Register native toast notification callback (only for security alerts)
    alerter.register_desktop_notifier(_show_toast_notification)

    # 2. Start Flask Web Server thread
    flask_thread = threading.Thread(target=_run_flask_server, daemon=True)
    flask_thread.start()
    time.sleep(0.8)

    # 3. Start File Monitor thread
    _monitor = FileMonitor()
    _monitor.start()

    # 4. Start System Tray icon in background thread
    tray_thread = threading.Thread(target=_setup_system_tray, daemon=True)
    tray_thread.start()

    # 5. Create Native pywebview desktop window
    dashboard_url = f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"
    _main_window = webview.create_window(
        title="FileSentinel DLP - Secure File Transfer System",
        url=dashboard_url,
        width=1240,
        height=820,
        min_size=(920, 600),
        background_color="#0d1117",
    )

    # When the user closes the window with [X], shut down the application cleanly
    _main_window.events.closing += _on_window_closing

    print("\n  [+] FileSentinel Desktop App launched.")
    print("  [+] Native window active. Close the window or press Ctrl+C to exit.\n")

    # Start pywebview main GUI loop (blocking call on main thread)
    try:
        webview.start(gui="edgechromium")
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        _quit_app()


if __name__ == "__main__":
    launch_desktop_app()
