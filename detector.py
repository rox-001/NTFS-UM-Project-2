"""
detector.py - Event Classification & Unauthorized Movement Detection
Classifies each filesystem event as NORMAL, WARNING, or CRITICAL.
"""

from __future__ import annotations   # PEP 563: compatible with Python 3.7+

import os
from config import (
    SENSITIVE_EXTENSIONS,
    SENSITIVE_DIRECTORIES,
    SUSPICIOUS_DRIVE_LETTERS,
    SUSPICIOUS_PATH_KEYWORDS,
    SUSPICIOUS_NETWORK_PREFIXES,
)

# FIX: Precompute as a frozenset at module load time — avoids rebuilding on every call.
_SENSITIVE_EXT_SET = frozenset(e.lower() for e in SENSITIVE_EXTENSIONS)


def is_sensitive_file(path: str) -> bool:
    """
    Return True if the file path has a sensitive extension
    or resides inside a sensitive directory.
    """
    if not path:
        return False

    # Check extension against precomputed set (O(1) lookup)
    _, ext = os.path.splitext(path)
    if ext.lower() in _SENSITIVE_EXT_SET:
        return True

    # Edge case: dotfiles like ".env", ".cfg" — os.path.splitext treats the
    # whole filename as the stem with no extension, so we check the basename directly.
    basename = os.path.basename(path).lower()
    if basename in _SENSITIVE_EXT_SET:
        return True

    # Check if path is inside a sensitive directory
    norm_path = os.path.normpath(path).lower()
    for sensitive_dir in SENSITIVE_DIRECTORIES:
        if norm_path.startswith(os.path.normpath(sensitive_dir).lower()):
            return True

    return False


def is_suspicious_destination(path: str) -> bool:
    """
    Return True if the destination path represents a suspicious
    exfiltration vector: USB drives, network shares, or cloud-sync folders.
    """
    if not path:
        return False

    norm = os.path.normpath(path)

    # Check USB / external drive letters
    for drive in SUSPICIOUS_DRIVE_LETTERS:
        if norm.lower().startswith(drive.lower()):
            return True

    # Check UNC network paths (\\server\share) — must check original path
    for prefix in SUSPICIOUS_NETWORK_PREFIXES:
        if path.startswith(prefix):
            return True

    # Check for cloud-sync or temp keywords in path
    norm_lower = norm.lower()
    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword.lower() in norm_lower:
            return True

    return False


def classify_event(event_type: str, src_path: str, dest_path: str = "") -> str:
    """
    Classify a filesystem event and return an alert level string.

    Classification logic:
    - CRITICAL: Any file transferred to a suspicious destination
    - CRITICAL: Sensitive file MOVED or DELETED
    - WARNING:  Sensitive file CREATED or MODIFIED
    - INFO:     Normal files in normal locations

    Args:
        event_type: 'CREATED', 'MODIFIED', 'MOVED', 'DELETED'
        src_path:   Source file path
        dest_path:  Destination path (for MOVED events)

    Returns:
        'CRITICAL', 'WARNING', or 'INFO'
    """
    src_sensitive   = is_sensitive_file(src_path)
    dest_suspicious = is_suspicious_destination(dest_path) if dest_path else False

    # Highest severity: anything going to a suspicious destination
    if dest_suspicious:
        return "CRITICAL"

    # High sensitivity: sensitive file being touched
    if src_sensitive:
        if event_type in ("MOVED", "DELETED"):
            return "CRITICAL"   # Moving or deleting sensitive files = high risk
        return "WARNING"        # Created / modified sensitive = suspicious but less severe

    # Default
    return "INFO"


def describe_event(event_type: str, src_path: str, dest_path: str = "") -> str:
    """
    Generate a human-readable description of the event for logs and alerts.
    """
    basename = os.path.basename(src_path)
    descriptions = {
        "CREATED":  f"File created: '{basename}'",
        "MODIFIED": f"File modified: '{basename}'",
        "DELETED":  f"File deleted: '{basename}'",
        "MOVED":    f"File moved: '{basename}' \u2192 '{dest_path}'",
    }
    return descriptions.get(event_type, f"Unknown event on '{basename}'")
