"""
monitor.py - Filesystem Event Monitor (Watchdog-based)
Detects file create/modify/move/delete events across configured directories.
Orchestrates the full pipeline: detect → hash → log → alert.
Includes noise-filtering and write-burst debouncing to prevent event flooding.
"""

from __future__ import annotations

import os
import time
import getpass
import threading

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from config import (
    MONITORED_DIRECTORIES,
    ENABLE_PROCESS_TRACKING,
    BASE_DIR,
    IGNORED_EXTENSIONS,
    IGNORED_FILENAMES,
)
import hasher
import detector
import logger
import alerter


# Pre-calculate normalized base project path to ignore internal project files
_PROJECT_BASE_NORM = os.path.normcase(os.path.normpath(os.path.abspath(BASE_DIR)))
_IGNORED_EXTS_SET = frozenset(ext.lower() for ext in IGNORED_EXTENSIONS)
_IGNORED_NAMES_SET = frozenset(name.lower() for name in IGNORED_FILENAMES)

# ── Debounce & Burst Filtering ───────────────────────────────────────────────
# When copying/saving a file, the OS flushes buffers in chunks, firing dozens
# of MODIFIED events. We track recent creations and modifications to eliminate noise.
_DEBOUNCE_WINDOW = 2.0        # Seconds to suppress identical events for same file
_RECENT_CREATION_WINDOW = 3.0 # Seconds to suppress MODIFIED events after CREATED

_recent_events: dict[str, float] = {}       # key: "EVENT_TYPE:norm_path" -> timestamp
_recent_creations: dict[str, float] = {}    # key: "norm_path" -> timestamp
_debounce_lock = threading.Lock()


def _should_ignore_path(path: str) -> bool:
    """
    Return True if the file should be ignored:
      - Inside the project's own folder (audit.log, alerts.log, reports, pycache)
      - Temporary / lock files (~$doc.docx, .tmp, .crdownload, .part)
      - OS system files (desktop.ini, thumbs.db)
      - Version control / package directories (.git, __pycache__, node_modules)
    """
    if not path:
        return True

    norm = os.path.normcase(os.path.normpath(os.path.abspath(path)))

    # 1. CRITICAL: Ignore own project directory to prevent log recursion loops
    if norm.startswith(_PROJECT_BASE_NORM):
        return True

    # 2. Ignore common version control & cache directories
    if any(segment in norm for segment in ("\\.git", "/.git", "__pycache__", "node_modules", ".vscode")):
        return True

    basename = os.path.basename(norm).lower()

    # 3. Ignore system filenames
    if basename in _IGNORED_NAMES_SET:
        return True

    # 4. Ignore temporary Office lock files and hidden temp markers
    if basename.startswith("~$") or basename.startswith(".~"):
        return True

    # 5. Ignore temporary / partial download extensions
    _, ext = os.path.splitext(norm)
    if ext.lower() in _IGNORED_EXTS_SET:
        return True

    return False


def _is_burst_duplicate(event_type: str, path: str) -> bool:
    """
    Filter out duplicate/burst events:
      - If file was CREATED within the last 3s, suppress subsequent MODIFIED events.
      - Suppress identical event_type on same path within 2s.
    """
    norm_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    now = time.monotonic()

    with _debounce_lock:
        # If this is a MODIFIED event right after a CREATED event for the same file, suppress it.
        # (This is just Windows writing the file content after creation).
        if event_type == "MODIFIED":
            last_created = _recent_creations.get(norm_path)
            if last_created is not None and (now - last_created) < _RECENT_CREATION_WINDOW:
                return True

        # Check general debounce for the exact event_type + path
        event_key = f"{event_type}:{norm_path}"
        last_seen = _recent_events.get(event_key)
        if last_seen is not None and (now - last_seen) < _DEBOUNCE_WINDOW:
            return True

        # Record this event
        _recent_events[event_key] = now
        if event_type == "CREATED":
            _recent_creations[norm_path] = now

        # Periodic cleanup when table grows large
        if len(_recent_events) > 600:
            cutoff = now - 15.0
            stale_keys = [k for k, t in _recent_events.items() if t < cutoff]
            for k in stale_keys:
                del _recent_events[k]

            stale_creations = [p for p, t in _recent_creations.items() if t < cutoff]
            for p in stale_creations:
                del _recent_creations[p]

    return False


def _get_current_user() -> str:
    """Return the current OS username."""
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _get_process_name() -> str:
    """
    Attempt to retrieve the name of the process that triggered the event.
    Falls back to 'N/A' if psutil is unavailable or lookup fails.
    """
    if not ENABLE_PROCESS_TRACKING or not PSUTIL_AVAILABLE:
        return "N/A"
    try:
        return psutil.Process(os.getpid()).name()
    except Exception:
        return "N/A"


class SecureTransferEventHandler(FileSystemEventHandler):
    """
    Custom watchdog event handler that processes all filesystem events
    through the full security pipeline.
    """

    def _process_event(self, event_type: str, src_path: str, dest_path: str = ""):
        """
        Core pipeline for each filesystem event:
          1. Ignore filter check (system noise & project internal logs)
          2. Debounce & burst suppression
          3. Classify event severity
          4. Compute integrity hashes
          5. Log the event
          6. Trigger alert if needed
        """
        # Step 1: Filter out system noise and internal log files
        if _should_ignore_path(src_path):
            return
        if dest_path and _should_ignore_path(dest_path):
            return

        # Step 2: Burst & duplicate suppression
        target_path = dest_path if (event_type == "MOVED" and dest_path) else src_path
        if _is_burst_duplicate(event_type, target_path):
            return

        user    = _get_current_user()
        process = _get_process_name()

        # Step 3: Classify severity (INFO / WARNING / CRITICAL)
        level = detector.classify_event(event_type, src_path, dest_path)

        # Step 4: Integrity hashing
        pre_hash = hasher.snapshot_file(src_path) if os.path.exists(src_path) else None

        if event_type == "MOVED" and dest_path and os.path.exists(dest_path):
            post_hash = hasher.compute_hash(dest_path)
        elif event_type not in ("DELETED", "MOVED") and os.path.exists(src_path):
            post_hash = hasher.compute_hash(src_path)
        else:
            post_hash = None

        _, integrity_status = hasher.verify_integrity(pre_hash, post_hash)

        # Step 5: Log event to audit.log and console
        logger.log_event(
            event_type       = event_type,
            source           = src_path,
            destination      = dest_path,
            user             = user,
            process          = process,
            hash_pre         = pre_hash,
            hash_post        = post_hash,
            integrity_status = integrity_status,
            alert_level      = level,
        )

        # Step 6: Trigger alert if policy violation (WARNING or CRITICAL)
        if level in ("WARNING", "CRITICAL"):
            description = detector.describe_event(event_type, src_path, dest_path)
            alerter.trigger_alert(
                level      = level,
                message    = description,
                event_data = {
                    "source":      src_path,
                    "destination": dest_path,
                    "user":        user,
                    "process":     process,
                },
            )

    # ── Watchdog callbacks ───────────────────────────────────────────────────

    def on_created(self, event):
        if not event.is_directory:
            self._process_event("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process_event("MOVED", event.src_path, event.dest_path)


class FileMonitor:
    """
    Manages one or more watchdog Observer instances for all
    configured directories.
    """

    def __init__(self, directories: list[str] | None = None):
        self.observer = Observer()
        self._running = False
        self.event_handler = SecureTransferEventHandler()
        self.directories = directories if directories is not None else MONITORED_DIRECTORIES

    def start(self):
        """Schedule watchers for all configured directories and start the observer."""
        scheduled = 0
        for directory in self.directories:
            directory = os.path.expandvars(directory)
            if os.path.isdir(directory):
                self.observer.schedule(
                    self.event_handler,
                    path      = directory,
                    recursive = True,
                )
                print(f"  [+] Watching: {directory}")
                scheduled += 1
            else:
                print(f"  [-] Skipped (not found): {directory}")

        if scheduled == 0:
            print("[WARNING] No valid directories to monitor. Edit config.py to add paths.")
            return

        self.observer.start()
        self._running = True
        print(f"\n  Monitoring {scheduled} director(ies). Press Ctrl+C to stop.\n")

    def stop(self):
        """Gracefully stop the observer."""
        if self._running:
            self.observer.stop()
            self.observer.join()
            self._running = False
            print("\n  Monitor stopped. Goodbye.")

    def is_running(self) -> bool:
        return self._running
