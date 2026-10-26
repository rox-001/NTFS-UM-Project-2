"""
main.py - Secure File Transfer Monitoring System — Entry Point
Usage:
  python main.py --desktop              # Launch full native Windows Desktop App (Window + Tray + Alerts)
  python main.py --monitor              # Monitor + colorama console (no dashboard)
  python main.py --monitor --dashboard  # Monitor + console + web dashboard in browser
  python main.py --dashboard-only       # Dashboard only (view existing logs in browser)
  python main.py --report               # Generate text audit report
  python main.py --test-hash <file>     # Compute and print hash of a file
"""

import argparse
import sys
import os
import threading
import time

# Ensure parent directory is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logger import print_banner
from monitor import FileMonitor
from hasher import compute_hash
from reporter import generate_report
from config import DASHBOARD_HOST, DASHBOARD_PORT, HASH_ALGORITHM


def cmd_desktop():
    """Launch the native desktop window application."""
    print_banner()
    try:
        from app_desktop import launch_desktop_app
        launch_desktop_app()
    except ImportError as e:
        print(f"  [ERROR] Desktop GUI dependency missing: {e}")
        print("  Install desktop dependencies with: pip install pywebview pystray Pillow")
        sys.exit(1)


def cmd_monitor(with_dashboard: bool):
    """Start filesystem monitoring with optional dashboard."""
    print_banner()
    monitor = FileMonitor()

    if with_dashboard:
        _launch_dashboard_thread()

    try:
        monitor.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\n  Logs saved. Run 'python main.py --report' for a full audit report.")


def cmd_dashboard_only():
    """Launch dashboard without starting the file monitor."""
    print_banner()
    print("  [Dashboard-only mode] File monitoring is NOT active.\n")
    _launch_dashboard_blocking()


def cmd_report():
    """Generate and print a text audit report."""
    print_banner()
    generate_report()


def cmd_test_hash(filepath: str):
    """Compute and display the hash of a single file."""
    if not os.path.isfile(filepath):
        print(f"  [ERROR] File not found: {filepath}")
        sys.exit(1)

    digest = compute_hash(filepath, HASH_ALGORITHM)
    size   = os.path.getsize(filepath)
    print(f"\n  File      : {filepath}")
    print(f"  Size      : {size:,} bytes")
    print(f"  Algorithm : {HASH_ALGORITHM.upper()}")
    print(f"  Hash      : {digest}\n")


def _launch_dashboard_thread():
    """Start the Flask dashboard in a background daemon thread."""
    try:
        from dashboard.app import run_dashboard
        thread = threading.Thread(
            target=run_dashboard,
            kwargs={"host": DASHBOARD_HOST, "port": DASHBOARD_PORT},
            daemon=True,
        )
        thread.start()
        time.sleep(1)  # Brief pause to let Flask bind before monitor prints
    except ImportError as e:
        print(f"  [WARNING] Dashboard skipped: {e}")
        print("  Run 'pip install flask' to enable the dashboard.")


def _launch_dashboard_blocking():
    """Start the Flask dashboard (blocking — main thread)."""
    try:
        from dashboard.app import run_dashboard
        run_dashboard(host=DASHBOARD_HOST, port=DASHBOARD_PORT)
    except ImportError:
        print("  [ERROR] Flask is not installed. Run 'pip install flask' first.")
        sys.exit(1)


# ── CLI Argument Parser ───────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="FileSentinel",
        description="Secure File Transfer Monitoring & DLP System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --desktop                  # Launch native Windows Desktop App
  python main.py --monitor                  # Console monitoring only
  python main.py --monitor --dashboard      # Monitor + web dashboard in browser
  python main.py --dashboard-only           # View logs in browser
  python main.py --report                   # Generate audit report
  python main.py --test-hash secret.docx   # Hash a specific file
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--desktop", "--gui", action="store_true", help="Launch native Windows desktop application")
    group.add_argument("--monitor",          action="store_true", help="Start filesystem monitoring")
    group.add_argument("--dashboard-only",   action="store_true", help="Launch dashboard without monitoring")
    group.add_argument("--report",           action="store_true", help="Generate audit report")
    group.add_argument("--test-hash",        metavar="FILE",      help="Compute SHA256 hash of a file")

    parser.add_argument("--dashboard", action="store_true",
                        help="[with --monitor] Also launch the web dashboard in browser")

    args = parser.parse_args()

    if args.desktop:
        cmd_desktop()
    elif args.monitor:
        cmd_monitor(with_dashboard=args.dashboard)
    elif args.dashboard_only:
        cmd_dashboard_only()
    elif args.report:
        cmd_report()
    elif args.test_hash:
        cmd_test_hash(args.test_hash)


if __name__ == "__main__":
    main()
