"""
config.py - Central Configuration for Secure File Transfer Monitoring System
Adjust these values to match your environment before running.
"""

import os
import sys

# =============================================================================
# MONITORING TARGETS
# Directories to watch for file events. Add all paths you want monitored.
# =============================================================================
MONITORED_DIRECTORIES = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
    # Add more paths as needed, e.g.:
    # "C:\\SensitiveData",
    # "D:\\Projects",
]

# =============================================================================
# SENSITIVE FILE CRITERIA
# Files matching these extensions or located in dedicated sensitive directories
# are treated as sensitive and will trigger higher-severity alerts (WARNING / CRITICAL).
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

# Dedicated directories containing confidential or restricted data.
# Note: Do NOT list your entire general Desktop or user root here,
# otherwise every non-sensitive file inside it will trigger sensitivity alerts.
SENSITIVE_DIRECTORIES = [
    # Add your specific high-security folders here, for example:
    # "C:\\SensitiveData",
    # os.path.expanduser("~/Documents/Confidential"),
]

# =============================================================================
# IGNORED FILES & SYSTEM NOISE
# These files/patterns are automatically ignored to prevent log flooding.
# =============================================================================
IGNORED_EXTENSIONS = [
    ".tmp", ".crdownload", ".part", ".lock", ".swp",
]

IGNORED_FILENAMES = [
    "desktop.ini", "thumbs.db", ".ds_store",
]

# =============================================================================
# SUSPICIOUS DESTINATIONS
# Transfers to these destinations trigger CRITICAL alerts.
# These represent common data exfiltration vectors.
# =============================================================================
SUSPICIOUS_DRIVE_LETTERS = ["D:\\", "E:\\", "F:\\", "G:\\", "H:\\"]  # USB / external drives

SUSPICIOUS_PATH_KEYWORDS = [
    "OneDrive", "Dropbox", "Google Drive", "iCloud",  # Cloud sync folders
    "RECYCLER", "$Recycle.Bin",                         # Recycle bin (deletion hiding)
    "Temp", "tmp",                                       # Temp (staging for exfil)
]

SUSPICIOUS_NETWORK_PREFIXES = [
    "\\\\",     # UNC network paths (\\server\share)
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
    # PyInstaller unpacks bundled assets (templates, static, icons) into _MEIPASS
    RESOURCE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    # Output logs and reports next to executable (or AppData if installed in Program Files)
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

# =============================================================================
# HASHING
# hashlib is a Python built-in module — no installation required.
# Supported algorithms: 'sha256', 'sha512', 'md5'
# =============================================================================
HASH_ALGORITHM  = "sha256"   # Recommended: sha256
HASH_CHUNK_SIZE = 65536      # 64KB chunks for reading large files efficiently

# =============================================================================
# DASHBOARD SETTINGS
# Flask runs completely locally on localhost — no internet required.
# =============================================================================
DASHBOARD_ENABLED   = True
DASHBOARD_HOST      = "127.0.0.1"
DASHBOARD_PORT      = 5000
DASHBOARD_DEBUG     = False
LOGS_PER_PAGE       = 50     # Number of log entries shown per page

# =============================================================================
# PROCESS TRACKING (requires psutil)
# If psutil is unavailable, process name is logged as 'N/A'
# =============================================================================
ENABLE_PROCESS_TRACKING = True
