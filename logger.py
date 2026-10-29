"""
logger.py - Structured Audit Logging Module
Writes JSON-line entries to logs/audit.log.
Also provides colored console output via colorama (always available, no network needed).
"""

from __future__ import annotations   # PEP 563: compatible with Python 3.7+

import json
import os
import sys
from datetime import datetime, timedelta

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
    risk_score: int = 0,
):
    """
    Write a structured JSON log entry to audit.log and print to console.

    Args:
        event_type:        Type of FS event (CREATED, MODIFIED, MOVED, DELETED, DOWNLOADED).
        source:            Source file path.
        destination:       Destination path (empty string if not applicable).
        user:              OS username performing the action.
        process:           Name of the triggering process (or 'N/A').
        hash_pre:          Hash before event (or None).
        hash_post:         Hash after event (or None).
        integrity_status:  'INTACT', 'TAMPERED', or 'UNAVAILABLE'.
        alert_level:       'INFO', 'WARNING', or 'CRITICAL'.
        extra:             Optional dict of additional fields (diff, dlp_matches, process_telemetry).
        risk_score:        Numerical risk assessment score (0-100).
    """
    entry = {
        "timestamp":        datetime.now().isoformat(),
        "event_type":       event_type,
        "source":           source,
        "destination":      destination,
        "user":             user,
        "process":          process,
        "risk_score":       risk_score,
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
    msg = f"{event_type:10} | {os.path.basename(source)}{dest_str} | [Risk {risk_score:02d}] {integrity_status}"
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
    start_time: str = None,
    end_time: str = None,
    timeframe: str = None,
) -> list[dict]:
    """
    Read and parse audit.log entries with multi-criteria filtering,
    time-window slicing, smart token query parsing, and custom sorting.
    """
    if not os.path.exists(AUDIT_LOG_PATH):
        return []

    # Calculate dynamic relative timeframe threshold
    start_threshold = None
    end_threshold = None

    if timeframe == "1h":
        start_threshold = (datetime.now() - timedelta(hours=1)).isoformat()
    elif timeframe == "24h":
        start_threshold = (datetime.now() - timedelta(hours=24)).isoformat()
    elif timeframe == "7d":
        start_threshold = (datetime.now() - timedelta(days=7)).isoformat()
    elif start_time:
        start_threshold = start_time.replace("Z", "").split("+")[0]

    if end_time:
        end_threshold = end_time.replace("Z", "").split("+")[0]

    # Parse search tokens if present in keyword (e.g. user:admin ext:pem level:crit)
    token_filters = {}
    free_text_terms = []
    if keyword:
        parts = keyword.strip().split()
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                token_filters[k.lower()] = v.lower()
            else:
                free_text_terms.append(p.lower())

    entries = []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                ts = entry.get("timestamp", "")

                # 1. Date/Time Window Filter
                if start_threshold and ts < start_threshold:
                    continue
                if end_threshold and ts > end_threshold:
                    continue

                # 2. Alert Level Filter
                if level_filter and entry.get("alert_level") != level_filter:
                    continue

                # 3. File Type / Category Filter
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

                # 4. Directory Filter
                if directory:
                    dir_lower = directory.lower()
                    src_lower = entry.get("source", "").lower()
                    dest_lower = entry.get("destination", "").lower()
                    if dir_lower not in src_lower and dir_lower not in dest_lower:
                        continue

                # 5. Smart Token & Keyword Filters
                if token_filters:
                    # user: token
                    if "user" in token_filters:
                        if token_filters["user"] not in entry.get("user", "").lower():
                            continue
                    # ext: token
                    if "ext" in token_filters:
                        t_ext = token_filters["ext"]
                        target_ext = os.path.splitext(entry.get("source", "").lower())[1].lstrip(".")
                        if t_ext.lstrip(".") != target_ext:
                            continue
                    # level: token
                    if "level" in token_filters:
                        if token_filters["level"] not in entry.get("alert_level", "").lower():
                            continue
                    # event: token
                    if "event" in token_filters:
                        if token_filters["event"] not in entry.get("event_type", "").lower():
                            continue
                    # dir: token
                    if "dir" in token_filters:
                        d_val = token_filters["dir"]
                        if d_val not in entry.get("source", "").lower() and d_val not in entry.get("destination", "").lower():
                            continue
                    # risk:>N or risk:N
                    if "risk" in token_filters:
                        r_val = token_filters["risk"]
                        e_risk = entry.get("risk_score", 0)
                        if r_val.startswith(">="):
                            if e_risk < int(r_val[2:]):
                                continue
                        elif r_val.startswith(">"):
                            if e_risk <= int(r_val[1:]):
                                continue
                        elif r_val.startswith("<="):
                            if e_risk > int(r_val[2:]):
                                continue
                        elif r_val.startswith("<"):
                            if e_risk >= int(r_val[1:]):
                                continue
                        elif int(r_val) != e_risk:
                            continue

                if free_text_terms:
                    combined_text = " ".join([
                        entry.get("source", ""),
                        entry.get("destination", ""),
                        entry.get("event_type", ""),
                        entry.get("user", ""),
                        entry.get("process", ""),
                        str(entry.get("cmdline", "")),
                        str(entry.get("dlp_summary", ""))
                    ]).lower()
                    if not all(term in combined_text for term in free_text_terms):
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
        elif s in ("risk", "risk_score"):
            key_fn = lambda e: e.get("risk_score", 0)
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


def get_stats(
    start_time: str = None,
    end_time: str = None,
    timeframe: str = None,
    keyword: str = None,
    file_type: str = None,
) -> dict:
    """Return summary statistics from the audit log, optionally filtered by timeframe/search."""
    entries = load_logs(
        start_time=start_time,
        end_time=end_time,
        timeframe=timeframe,
        keyword=keyword,
        file_type=file_type,
    )
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
