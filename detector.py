r"""
detector.py - Event Classification & Unauthorized Movement Detection
Classifies each filesystem event as INFO, WARNING, or CRITICAL.
Includes path-component matching, dynamic drive-type detection, and multi-extension parsing.
"""

from __future__ import annotations

import os
import sys
import tempfile
from config import (
    SENSITIVE_EXTENSIONS,
    SENSITIVE_DIRECTORIES,
    SUSPICIOUS_DRIVE_LETTERS,
    SUSPICIOUS_NETWORK_PREFIXES,
)

# Precompute sensitive extension set (O(1) lookup)
_SENSITIVE_EXT_SET = frozenset(e.lower() for e in SENSITIVE_EXTENSIONS)

# Recognized cloud storage folder names (matched against directory path components only)
_CLOUD_KEYWORDS = frozenset({"onedrive", "dropbox", "google drive", "iclouddrive", "icloud", "box", "nextcloud"})

# Recognized recycle bin folder names
_RECYCLER_KEYWORDS = frozenset({"recycler", "$recycle.bin", "$recycles.bin"})

# System temp directories (normalized lowercase)
_SYSTEM_TEMP_DIRS: set[str] = set()
for _t_env in ("TEMP", "TMP", "TMPDIR"):
    _t_val = os.environ.get(_t_env)
    if _t_val:
        _SYSTEM_TEMP_DIRS.add(os.path.normcase(os.path.normpath(os.path.abspath(_t_val))))

try:
    _SYSTEM_TEMP_DIRS.add(os.path.normcase(os.path.normpath(os.path.abspath(tempfile.gettempdir()))))
except Exception:
    pass

if sys.platform == "win32":
    _SYSTEM_TEMP_DIRS.add(os.path.normcase("c:\\windows\\temp"))
else:
    _SYSTEM_TEMP_DIRS.add("/tmp")
    _SYSTEM_TEMP_DIRS.add("/var/tmp")


def _get_drive_type_windows(drive_root: str) -> int:
    """
    Query Windows GetDriveTypeW:
      2 = DRIVE_REMOVABLE (USB flash drive, memory card)
      3 = DRIVE_FIXED     (internal hard drive / SSD)
      4 = DRIVE_REMOTE    (network share mapped drive)
      5 = DRIVE_CDROM     (optical drive)
      6 = DRIVE_RAMDISK
    """
    if sys.platform != "win32":
        return 0
    try:
        import ctypes
        if not drive_root.endswith("\\"):
            drive_root += "\\"
        return ctypes.windll.kernel32.GetDriveTypeW(drive_root)
    except Exception:
        return 0


def is_sensitive_file(path: str) -> bool:
    """
    Return True if the file path has a sensitive extension
    or resides inside a configured sensitive directory.
    Supports dotfiles (.env), sub-extensions (secret.pem.tmp), and full paths.
    """
    if not path:
        return False

    norm = os.path.normpath(path)
    basename = os.path.basename(norm).lower()

    # 1. Primary extension check
    _, ext = os.path.splitext(norm)
    if ext.lower() in _SENSITIVE_EXT_SET:
        return True

    # 2. Dotfiles like ".env", ".cfg" where os.path.splitext treats the whole filename as stem
    if basename in _SENSITIVE_EXT_SET:
        return True

    # 3. Double-extension check (e.g. secret.pem.tmp -> check if stem 'secret.pem' is sensitive)
    stem, sub_ext = os.path.splitext(basename)
    if sub_ext in {".tmp", ".part", ".crdownload", ".bak", ".swp", ".lock"}:
        _, inner_ext = os.path.splitext(stem)
        if inner_ext in _SENSITIVE_EXT_SET or stem in _SENSITIVE_EXT_SET:
            return True

    # 4. Check if path resides inside a sensitive directory
    norm_path = os.path.normcase(norm)
    for sensitive_dir in SENSITIVE_DIRECTORIES:
        if sensitive_dir:
            norm_sens = os.path.normcase(os.path.normpath(os.path.abspath(sensitive_dir)))
            if norm_path == norm_sens or norm_path.startswith(norm_sens.rstrip(os.sep) + os.sep):
                return True

    return False


def is_cloud_or_removable_location(path: str) -> bool:
    """
    Return True if the path is located on removable media (USB), network shares,
    or cloud-sync folders (OneDrive, Dropbox, Google Drive, iCloud, Box).
    """
    if not path:
        return False

    raw_path = path.strip()
    norm = os.path.normpath(raw_path)

    # 1. UNC network paths: \\server\share or //server/share
    if raw_path.startswith("\\\\") or raw_path.startswith("//") or norm.startswith(r"\\"):
        return True

    # 2. Windows drive type check (Removable media / Network drives)
    if sys.platform == "win32" and len(norm) >= 2 and norm[1] == ":":
        drive_letter = norm[:2].upper() + "\\"
        dtype = _get_drive_type_windows(drive_letter)
        # 2 = DRIVE_REMOVABLE, 4 = DRIVE_REMOTE, 5 = DRIVE_CDROM
        if dtype in (2, 4, 5):
            return True
        elif dtype == 3:
            # Internal disk
            pass
        else:
            if drive_letter in [d.upper() for d in SUSPICIOUS_DRIVE_LETTERS]:
                return True
    elif sys.platform != "win32":
        norm_lower = norm.lower()
        if any(norm_lower.startswith(p) for p in ("/media/", "/mnt/", "/volumes/")):
            return True
        drive_letter = norm[:3].upper() if len(norm) >= 3 and norm[1:3] == ":\\" else ""
        if drive_letter and drive_letter in [d.upper() for d in SUSPICIOUS_DRIVE_LETTERS]:
            return True

    # 3. Path component analysis for directory path (excluding filename)
    dir_path = os.path.dirname(norm)
    if dir_path:
        parts = [p.lower() for p in dir_path.replace("/", "\\").split("\\") if p]
        for part in parts:
            if any(part == ck or part.startswith(ck + " ") or part.startswith(ck + "-") for ck in _CLOUD_KEYWORDS):
                return True

    return False


def is_suspicious_destination(path: str) -> bool:
    """
    Return True if the destination path represents an exfiltration vector:
      - Removable media (USB drives)
      - Network shares (UNC paths \\\\server\\share or //server/share)
      - Cloud synchronization folders (OneDrive, Dropbox, Google Drive, iCloud)
      - Recycle bin staging
      - System or user Temp staging locations

    Uses whole-path-component matching to avoid false positives (e.g. 'Templates' or 'attempt2.txt').
    """
    if not path:
        return False

    # Check cloud, network, and removable media
    if is_cloud_or_removable_location(path):
        return True

    norm = os.path.normpath(path.strip())
    dir_path = os.path.dirname(norm)
    if dir_path:
        parts = [p.lower() for p in dir_path.replace("/", "\\").split("\\") if p]

        # Check recycle bin components
        if any(part in _RECYCLER_KEYWORDS for part in parts):
            return True

        # Check temp directory components:
        # Must match actual system temp directory path OR be an exact folder named 'temp' or 'tmp'
        norm_case_dir = os.path.normcase(os.path.abspath(dir_path))
        for sys_temp in _SYSTEM_TEMP_DIRS:
            if norm_case_dir == sys_temp or norm_case_dir.startswith(sys_temp.rstrip(os.sep) + os.sep):
                return True

        if any(part in {"temp", "tmp"} for part in parts):
            return True

    return False


def classify_event(event_type: str, src_path: str, dest_path: str = "") -> str:
    """
    Classify a filesystem event and return an alert level string ('INFO', 'WARNING', or 'CRITICAL').

    Classification logic:
    - CRITICAL: File transferred TO a suspicious destination (USB, Cloud, Network, Temp)
    - CRITICAL: Sensitive file CREATED or MODIFIED directly inside an exfiltration location (USB / Cloud Sync)
    - CRITICAL: Sensitive file MOVED or DELETED
    - WARNING:  Sensitive file CREATED or MODIFIED in normal monitored locations
    - INFO:     Normal files in normal locations
    """
    src_sensitive   = is_sensitive_file(src_path)
    dest_sensitive  = is_sensitive_file(dest_path) if dest_path else False
    is_sensitive    = src_sensitive or dest_sensitive

    dest_suspicious = is_suspicious_destination(dest_path) if dest_path else False

    # 1. Any file transferred TO a suspicious destination (USB, Cloud, Network, Temp staging)
    if dest_suspicious:
        return "CRITICAL"

    # 2. Sensitive file created/modified directly in a cloud-sync or removable media location (F-06)
    if is_sensitive and is_cloud_or_removable_location(src_path):
        return "CRITICAL"

    # 3. Sensitive file moved or deleted locally
    if is_sensitive:
        if event_type in ("MOVED", "DELETED"):
            return "CRITICAL"
        return "WARNING"

    # 4. Default
    return "INFO"


def describe_event(event_type: str, src_path: str, dest_path: str = "") -> str:
    """
    Generate a human-readable description of the event for logs and alerts.
    """
    basename = os.path.basename(src_path)
    descriptions = {
        "CREATED":     f"File created: '{basename}'",
        "MODIFIED":    f"File modified: '{basename}'",
        "DELETED":     f"File deleted: '{basename}'",
        "MOVED":       f"File moved: '{basename}' \u2192 '{dest_path}'",
        "CREATED_DIR": f"Directory created: '{basename}'",
        "DELETED_DIR": f"Directory deleted: '{basename}'",
        "MOVED_DIR":   f"Directory moved: '{basename}' \u2192 '{dest_path}'",
    }
    return descriptions.get(event_type, f"Event {event_type} on '{basename}'")
