"""
logger.py - Structured Audit Logging Module
Writes JSON-line entries to logs/audit.log.
Also provides colored console output via colorama (always available, no network needed).
"""

from __future__ import annotations   # PEP 563: compatible with Python 3.7+

import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init as colorama_init

from config import AUDIT_LOG_PATH, LOG_DIR, HASH_ALGORITHM

# Initialize colorama (autoreset=True resets color after each print)
colorama_init(autoreset=True)

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Color map for alert levels
_LEVEL_COLORS = {
    "INFO":     Fore.CYAN,
    "WARNING":  Fore.YELLOW,
    "CRITICAL": Fore.RED,
    "NORMAL":   Fore.GREEN,
}

_LEVEL_PREFIX = {
    "INFO":     "[INFO]    ",
    "WARNING":  "[WARNING] ",
    "CRITICAL": "[CRITICAL]",
    "NORMAL":   "[NORMAL]  ",
}


def _console_print(level: str, message: str):
    """Print a color-coded line to the console safely across all Windows code pages."""
    color  = _LEVEL_COLORS.get(level, Fore.WHITE)
    prefix = _LEVEL_PREFIX.get(level, "[?]       ")
    ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out    = f"{color}{ts} {prefix} {message}{Style.RESET_ALL}"
    try:
        print(out)
    except UnicodeEncodeError:
        print(out.encode("ascii", errors="replace").decode("ascii"))


def log_event(
    event_type: str,
    source: str,
    destination: str,
    user: str,
    process: str,
    hash_pre: str | None,
    hash_post: str | None,
    integrity_status: str,
    alert_level: str,
    extra: dict = None,
):
    """
    Write a structured JSON log entry to audit.log and print to console.

    Args:
        event_type:        Type of FS event (CREATED, MODIFIED, MOVED, DELETED).
        source:            Source file path.
        destination:       Destination path (empty string if not applicable).
        user:              OS username performing the action.
        process:           Name of the triggering process (or 'N/A').
        hash_pre:          Hash before event (or None).
        hash_post:         Hash after event (or None).
        integrity_status:  'INTACT', 'TAMPERED', or 'UNAVAILABLE'.
        alert_level:       'INFO', 'WARNING', or 'CRITICAL'.
        extra:             Optional dict of additional fields.
    """
    entry = {
        "timestamp":        datetime.now().isoformat(),
        "event_type":       event_type,
        "source":           source,
        "destination":      destination,
        "user":             user,
        "process":          process,
        "hash_algorithm":   HASH_ALGORITHM,
        "hash_pre":         hash_pre or "N/A",
        "hash_post":        hash_post or "N/A",
        "integrity_status": integrity_status,
        "alert_level":      alert_level,
    }
    if extra:
        entry.update(extra)

    # Write to audit log file (always utf-8)
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    # Print to console with colors (using ASCII -> arrow)
    dest_str = f" -> {destination}" if destination else ""
    msg = f"{event_type:10} | {os.path.basename(source)}{dest_str} | {integrity_status}"
    _console_print(alert_level, msg)


def load_logs(limit: int = None, level_filter: str = None, keyword: str = None) -> list[dict]:
    """
    Read and parse audit.log entries with optional filtering.

    Args:
        limit:        Maximum number of recent entries to return. None = all.
        level_filter: Filter by alert level string ('INFO', 'WARNING', 'CRITICAL').
        keyword:      Filter entries where keyword appears in source or destination.

    Returns:
        List of log entry dicts, most recent last.
    """
    if not os.path.exists(AUDIT_LOG_PATH):
        return []

    entries = []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                # Apply filters
                if level_filter and entry.get("alert_level") != level_filter:
                    continue
                if keyword:
                    kw = keyword.lower()
                    if kw not in entry.get("source", "").lower() \
                       and kw not in entry.get("destination", "").lower() \
                       and kw not in entry.get("event_type", "").lower():
                        continue
                entries.append(entry)
            except json.JSONDecodeError:
                continue

    if limit:
        entries = entries[-limit:]
    return entries


def get_stats() -> dict:
    """Return summary statistics from the audit log."""
    entries = load_logs()
    stats = {
        "total":              len(entries),
        "info":               sum(1 for e in entries if e.get("alert_level") == "INFO"),
        "warning":            sum(1 for e in entries if e.get("alert_level") == "WARNING"),
        "critical":           sum(1 for e in entries if e.get("alert_level") == "CRITICAL"),
        "integrity_tampered": sum(1 for e in entries if e.get("integrity_status") == "TAMPERED"),
        "integrity_ok":       sum(1 for e in entries if e.get("integrity_status") == "INTACT"),
    }
    return stats


def print_banner():
    """Print styled startup banner to the console safely across Windows terminals."""
    line = "=" * 62
    banner = f"""
{Fore.CYAN}+{line}+
|       SECURE FILE TRANSFER MONITORING SYSTEM                 |
|       Blue Team DLP & Integrity Checker  |  v1.0             |
+{line}+{Style.RESET_ALL}
"""
    try:
        print(banner)
    except UnicodeEncodeError:
        print(banner.encode("ascii", errors="replace").decode("ascii"))
