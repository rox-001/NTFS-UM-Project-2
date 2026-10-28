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


# File type extension categories for advanced filtering
_FILE_TYPE_MAP = {
    "documents": {".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".pdf", ".txt", ".csv", ".rtf"},
    "secrets":   {".pem", ".key", ".env", ".pfx", ".p12", ".crt", ".cer", ".kdbx", ".id_rsa"},
    "databases": {".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb"},
    "scripts":   {".py", ".ps1", ".bat", ".cmd", ".sh", ".vbs", ".js", ".ts"},
    "archives":  {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"},
}

_ALERT_LEVEL_WEIGHT = {
    "CRITICAL": 3,
    "WARNING":  2,
    "INFO":     1,
    "NORMAL":   0,
}


def load_logs(
    limit: int = None,
    level_filter: str = None,
    keyword: str = None,
    sort_by: str = None,
    order: str = "desc",
    file_type: str = None,
    directory: str = None,
) -> list[dict]:
    """
    Read and parse audit.log entries with optional filtering and sorting.

    Args:
        limit:        Maximum number of entries to return. None = all.
        level_filter: Filter by alert level string ('INFO', 'WARNING', 'CRITICAL').
        keyword:      Filter entries where keyword appears in source, destination, or user.
        sort_by:      Sort key: 'timestamp', 'level', 'source', 'destination', 'event_type', 'ext', 'integrity'.
        order:        Sort order: 'asc' or 'desc'.
        file_type:    Category ('documents', 'secrets', 'databases', 'scripts', 'archives') or specific extension.
        directory:    Filter entries where directory path substring appears in source or destination.

    Returns:
        List of log entry dicts.
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
                # Apply level filter
                if level_filter and entry.get("alert_level") != level_filter:
                    continue

                # Apply keyword filter
                if keyword:
                    kw = keyword.lower()
                    src_kw = entry.get("source", "").lower()
                    dest_kw = entry.get("destination", "").lower()
                    evt_kw = entry.get("event_type", "").lower()
                    user_kw = entry.get("user", "").lower()
                    if kw not in src_kw and kw not in dest_kw and kw not in evt_kw and kw not in user_kw:
                        continue

                # Apply file type / extension filter
                if file_type:
                    ft_lower = file_type.lower()
                    src_path = entry.get("source", "")
                    dest_path = entry.get("destination", "")
                    target = dest_path if (entry.get("event_type") == "MOVED" and dest_path) else src_path
                    _, ext = os.path.splitext(target.lower())
                    if ft_lower in _FILE_TYPE_MAP:
                        if ext not in _FILE_TYPE_MAP[ft_lower]:
                            continue
                    else:
                        norm_ft = ft_lower if ft_lower.startswith(".") else f".{ft_lower}"
                        if ext != norm_ft:
                            continue

                # Apply directory filter
                if directory:
                    dir_lower = directory.lower()
                    src_lower = entry.get("source", "").lower()
                    dest_lower = entry.get("destination", "").lower()
                    if dir_lower not in src_lower and dir_lower not in dest_lower:
                        continue

                entries.append(entry)
            except json.JSONDecodeError:
                continue

    # Apply sorting if requested
    if sort_by:
        s = sort_by.lower()
        if s in ("timestamp", "date"):
            key_fn = lambda e: e.get("timestamp", "")
        elif s in ("level", "alert_level", "severity"):
            key_fn = lambda e: _ALERT_LEVEL_WEIGHT.get(e.get("alert_level", "").upper(), 0)
        elif s in ("source", "directory", "dir", "path"):
            key_fn = lambda e: e.get("source", "").lower()
        elif s in ("destination", "dest"):
            key_fn = lambda e: e.get("destination", "").lower()
        elif s in ("event", "event_type"):
            key_fn = lambda e: e.get("event_type", "").lower()
        elif s in ("ext", "extension", "file_type"):
            key_fn = lambda e: os.path.splitext(e.get("source", ""))[1].lower()
        elif s in ("integrity", "integrity_status"):
            key_fn = lambda e: e.get("integrity_status", "").lower()
        else:
            key_fn = lambda e: e.get("timestamp", "")

        is_desc = (order.lower() == "desc")
        entries.sort(key=key_fn, reverse=is_desc)

    if limit:
        entries = entries[:limit] if sort_by else entries[-limit:]
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
