"""
alerter.py - Alert Generation & Policy Violation Notification
Writes alerts to logs/alerts.log and prints to console (colorama).
Supports desktop toast notification callbacks when running in Desktop App mode.
Entirely local — no network dependency. Safe on Windows cp1252.
"""

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Back, Style, init as colorama_init

from config import ALERT_LOG_PATH, LOG_DIR

colorama_init(autoreset=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Console display prefix per level (pure ASCII safe)
_LEVEL_STYLE = {
    "INFO":     (Fore.CYAN,   "[INFO] "),
    "WARNING":  (Fore.YELLOW, "[WARN] "),
    "CRITICAL": (Fore.RED,    "[CRIT] "),
}

# Optional desktop notification callback (registered by desktop app)
_desktop_notifier = None


def register_desktop_notifier(callback):
    """Register a callback function to display native OS notifications."""
    global _desktop_notifier
    _desktop_notifier = callback


def trigger_alert(level: str, message: str, event_data: dict = None):
    """
    Generate an alert at the specified severity level.

    - Writes to logs/alerts.log (JSON-line format)
    - Prints a formatted, color-coded message to the console
    - Prints a full banner for CRITICAL alerts
    - Dispatches native OS notification if desktop mode is active

    Args:
        level:      'INFO', 'WARNING', or 'CRITICAL'
        message:    Human-readable alert summary
        event_data: Optional dict of event context (source, destination, etc.)
    """
    ts = datetime.now().isoformat()
    alert_entry = {
        "timestamp":  ts,
        "level":      level,
        "message":    message,
        "event_data": event_data or {},
    }

    # Write to alerts log
    with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert_entry) + "\n")

    # Console output
    color, icon = _LEVEL_STYLE.get(level, (Fore.WHITE, "[ALERT]"))
    ts_short = datetime.now().strftime("%H:%M:%S")

    if level == "CRITICAL":
        _print_critical_banner(message, event_data, ts_short)
    else:
        out = f"{color}{ts_short} {icon} [{level}] {message}{Style.RESET_ALL}"
        try:
            print(out)
        except UnicodeEncodeError:
            print(out.encode("ascii", errors="replace").decode("ascii"))

    # Native desktop toast notification for policy violations
    if level in ("WARNING", "CRITICAL") and _desktop_notifier:
        try:
            _desktop_notifier(level, message, event_data or {})
        except Exception:
            pass


def _print_critical_banner(message: str, event_data: dict, ts: str):
    """Print a loud CRITICAL alert banner to the console."""
    src  = event_data.get("source", "N/A")      if event_data else "N/A"
    dest = event_data.get("destination", "N/A") if event_data else "N/A"
    user = event_data.get("user", "N/A")        if event_data else "N/A"

    line = "=" * 62
    banner = f"""
{Fore.RED}{Back.BLACK}
+{line}+
|  [!]  CRITICAL SECURITY ALERT  {ts:>29}  |
+{line}+
|  {message[:60]:<60}  |
|  User   : {user[:52]:<52}  |
|  Source : {src[:52]:<52}  |
|  Dest   : {dest[:52]:<52}  |
+{line}+
{Style.RESET_ALL}"""
    try:
        print(banner)
    except UnicodeEncodeError:
        print(banner.encode("ascii", errors="replace").decode("ascii"))


def load_alerts(limit: int = 50) -> list[dict]:
    """
    Read the most recent alert entries from alerts.log.

    Args:
        limit: Maximum number of alerts to return.

    Returns:
        List of alert dicts, most recent last.
    """
    if not os.path.exists(ALERT_LOG_PATH):
        return []

    alerts = []
    with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return alerts[-limit:]
