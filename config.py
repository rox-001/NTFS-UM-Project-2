"""
config.py - Central Configuration for Secure File Transfer Monitoring System
Adjust these values to match your environment before running.
"""

import os
import sys

# =============================================================================
# MONITORING TARGETS & DYNAMIC RESOLUTION
# =============================================================================
# Baseline directories to watch
DEFAULT_MONITORED_DIRECTORIES = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
]


def get_auto_discovered_targets() -> list[str]:
    """
    Dynamically discover all relevant monitoring targets:
      1. Default user folders (Desktop, Documents, Downloads).
      2. OneDrive redirected folders (e.g. %OneDrive%\\Desktop).
      3. Active Cloud-sync roots (Dropbox, Google Drive, iCloud, Nextcloud).
      4. Active Removable Media (USB flash drives, external drives).
    """
    targets: set[str] = set()

    # 1. Base user profile paths
    for p in DEFAULT_MONITORED_DIRECTORIES:
        expanded = os.path.normpath(os.path.abspath(os.path.expanduser(p)))
        if os.path.isdir(expanded):
            targets.add(expanded)

    user_home = os.path.expanduser("~")

    # 2. Known cloud sync directories
    cloud_candidates = [
        os.environ.get("OneDrive"),
        os.environ.get("OneDriveConsumer"),
        os.environ.get("OneDriveCommercial"),
        os.path.join(user_home, "Dropbox"),
        os.path.join(user_home, "Google Drive"),
        os.path.join(user_home, "iCloudDrive"),
        os.path.join(user_home, "Box"),
        os.path.join(user_home, "Nextcloud"),
    ]

    for candidate in cloud_candidates:
        if candidate and os.path.isdir(candidate):
            targets.add(os.path.normpath(os.path.abspath(candidate)))

    # 3. Dynamic Windows Removable Drive Discovery (USB drives, network drives)
    if sys.platform == "win32":
        try:
            import ctypes
            # GetLogicalDrives returns a bitmask of available drives (bit 0 = A, bit 1 = B, etc.)
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    drive_letter = f"{chr(65 + i)}:\\"
                    dtype = ctypes.windll.kernel32.GetDriveTypeW(drive_letter)
                    # 2 = DRIVE_REMOVABLE (USB flash drives, SD cards)
                    # 4 = DRIVE_REMOTE    (Mapped network drives)
                    if dtype in (2, 4) and os.path.isdir(drive_letter):
                        targets.add(os.path.normpath(drive_letter))
        except Exception:
            pass

    return sorted(list(targets))


MONITORED_DIRECTORIES = get_auto_discovered_targets()

# =============================================================================
# SENSITIVE FILE CRITERIA
# =============================================================================
SENSITIVE_EXTENSIONS = [
    ".key", ".pem", ".pfx", ".p12",          # Cryptographic keys / certs
    ".docx", ".xlsx", ".pptx", ".pdf",       # Office documents
    ".db", ".sqlite", ".sql",                 # Databases
    ".csv", ".json", ".xml",                  # Data files
    ".py", ".sh", ".bat", ".ps1",            # Scripts
    ".zip", ".rar", ".tar", ".gz", ".7z",   # Archives (potential exfil containers)
    ".env", ".cfg", ".ini", ".conf",         # Config / secrets
    ".bak", ".backup",                        # Backup files
]

# Dedicated directories containing confidential or restricted data
SENSITIVE_DIRECTORIES = [
    os.path.expanduser("~/Documents/Confidential"),
    os.path.expanduser("~/Desktop/Confidential"),
]

# =============================================================================
# IGNORED FILES & SYSTEM NOISE
# =============================================================================
IGNORED_EXTENSIONS = [
    ".tmp", ".crdownload", ".part", ".lock", ".swp",
]

IGNORED_FILENAMES = [
    "desktop.ini", "thumbs.db", ".ds_store",
]

# =============================================================================
# SUSPICIOUS DESTINATIONS
# =============================================================================
# Fallback drive letters for non-Windows or offline environments
SUSPICIOUS_DRIVE_LETTERS = ["D:\\", "E:\\", "F:\\", "G:\\", "H:\\"]

SUSPICIOUS_PATH_KEYWORDS = [
    "OneDrive", "Dropbox", "Google Drive", "iCloud", "Box",
    "RECYCLER", "$Recycle.Bin",
    "Temp", "tmp",
]

SUSPICIOUS_NETWORK_PREFIXES = [
    "\\\\", "//",
]

# =============================================================================
# ALERT LEVELS
# =============================================================================
ALERT_LEVELS = {
    "INFO":     "INFO",
    "WARNING":  "WARNING",
    "CRITICAL": "CRITICAL",
}

# =============================================================================
# LOGGING & OUTPUT PATHS & RESOURCE RESOLUTION (PyInstaller Frozen Support)
# =============================================================================
if getattr(sys, "frozen", False):
    RESOURCE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    _exe_dir = os.path.dirname(sys.executable)
    try:
        _test_file = os.path.join(_exe_dir, ".perm_test")
        with open(_test_file, "w") as _f:
            _f.write("1")
        os.remove(_test_file)
        BASE_DIR = _exe_dir
    except (PermissionError, OSError):
        BASE_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "FileSentinel")
else:
    RESOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = RESOURCE_DIR

LOG_DIR         = os.path.join(BASE_DIR, "logs")
REPORT_DIR      = os.path.join(BASE_DIR, "reports")

AUDIT_LOG_PATH  = os.path.join(LOG_DIR, "audit.log")
ALERT_LOG_PATH  = os.path.join(LOG_DIR, "alerts.log")

# Ensure log and report directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# =============================================================================
# HASHING
# =============================================================================
HASH_ALGORITHM  = "sha256"
HASH_CHUNK_SIZE = 65536

# =============================================================================
# DASHBOARD SETTINGS
# =============================================================================
DASHBOARD_ENABLED   = True
DASHBOARD_HOST      = "127.0.0.1"
DASHBOARD_PORT      = 5000
DASHBOARD_DEBUG     = False
LOGS_PER_PAGE       = 50

# =============================================================================
# PROCESS TRACKING
# =============================================================================
ENABLE_PROCESS_TRACKING = True
