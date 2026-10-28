"""
monitor.py - Filesystem Event Monitor (Watchdog-based)
Detects file create/modify/move/delete events across configured directories.
Orchestrates the full pipeline: detect → hash → log → alert.
Includes noise-filtering, write-burst debouncing, directory recursion, and exfiltration correlation.
"""

from __future__ import annotations

import os
import sys
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
    LOG_DIR,
    REPORT_DIR,
    IGNORED_EXTENSIONS,
    IGNORED_FILENAMES,
    get_auto_discovered_targets,
)
import hasher
import detector
import logger
import alerter
import diff_tracker


# Pre-calculate normalized directory paths
_LOG_DIR_NORM = os.path.normcase(os.path.normpath(os.path.abspath(LOG_DIR)))
_REPORT_DIR_NORM = os.path.normcase(os.path.normpath(os.path.abspath(REPORT_DIR)))
_BASE_DIR_NORM = os.path.normcase(os.path.normpath(os.path.abspath(BASE_DIR)))

_IGNORED_EXTS_SET = frozenset(ext.lower() for ext in IGNORED_EXTENSIONS)
_IGNORED_NAMES_SET = frozenset(name.lower() for name in IGNORED_FILENAMES)

# Debounce & Burst Filtering
_DEBOUNCE_WINDOW = 0.8         # Seconds to absorb OS chunked write-buffer flushes
_RECENT_CREATION_WINDOW = 1.0  # Seconds to absorb immediate post-create writes

_recent_events: dict[str, float] = {}       # key: "EVENT_TYPE:norm_path" -> timestamp
_recent_creations: dict[str, float] = {}    # key: "norm_path" -> timestamp
_recent_file_sizes: dict[str, int] = {}     # key: "norm_path" -> last known size
_recent_deletions: dict[str, tuple[float, str, str | None]] = {}  # basename -> (time, src_path, hash)
_pending_deletions: dict[str, tuple[float, str, str | None]] = {} # basename -> (time, src_path, pre_hash)
_pending_delete_timers: dict[str, threading.Timer] = {}           # basename -> Timer

_debounce_lock = threading.Lock()


def _should_ignore_path(path: str) -> bool:
    """
    Return True if the file should be ignored:
      - Internal application folders (logs/, reports/, build/, dist/, .git/)
      - Zero-length system/lock files (desktop.ini, thumbs.db)
      - Temporary non-sensitive download fragments
    Does NOT drop files with sensitive double extensions (secret.pem.tmp).
    Does NOT ignore sibling folders (Downloads2) or .github folders.
    """
    if not path:
        return True

    norm = os.path.normcase(os.path.normpath(os.path.abspath(path)))

    # 1. Ignore application runtime folders with trailing separator
    if norm == _LOG_DIR_NORM or norm.startswith(_LOG_DIR_NORM + os.sep):
        return True
    if norm == _REPORT_DIR_NORM or norm.startswith(_REPORT_DIR_NORM + os.sep):
        return True

    # Check internal build/dist folders only if inside application base
    if norm == _BASE_DIR_NORM or norm.startswith(_BASE_DIR_NORM + os.sep):
        rel = os.path.relpath(norm, _BASE_DIR_NORM).replace("/", "\\")
        top_segment = rel.split("\\")[0].lower()
        if top_segment in {"build", "dist", "tools", "__pycache__", ".pytest_cache"}:
            return True

    # 2. Version control and package directories (exact path segment matching)
    parts = [p.lower() for p in norm.replace("/", "\\").split("\\") if p]
    if any(p in {".git", "__pycache__", "node_modules", ".vscode"} for p in parts):
        return True

    basename = os.path.basename(norm).lower()

    # 3. System metadata files
    if basename in _IGNORED_NAMES_SET:
        return True

    # 4. Office lock files (~$)
    if basename.startswith("~$") or basename.startswith(".~"):
        try:
            if os.path.exists(path) and os.path.getsize(path) > 1024:
                return False  # Not a standard lock file; investigate
        except OSError:
            pass
        return True

    # 5. Temporary download extensions
    _, ext = os.path.splitext(norm)
    if ext.lower() in _IGNORED_EXTS_SET:
        # Double extension check: if stem has a sensitive extension, DO NOT drop!
        stem, _ = os.path.splitext(norm)
        if detector.is_sensitive_file(stem):
            return False
        return True

    return False


def _is_burst_duplicate(event_type: str, path: str) -> bool:
    """
    Filter out duplicate OS buffer-flush events while allowing legitimate edits.
    """
    norm_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    now = time.monotonic()

    with _debounce_lock:
        # If this is a MODIFIED event within 1.0s of CREATED, suppress it (initial buffer write)
        if event_type == "MODIFIED":
            last_created = _recent_creations.get(norm_path)
            if last_created is not None and (now - last_created) < _RECENT_CREATION_WINDOW:
                return True

        event_key = f"{event_type}:{norm_path}"
        last_seen = _recent_events.get(event_key)
        if last_seen is not None and (now - last_seen) < _DEBOUNCE_WINDOW:
            return True

        # Record this event
        _recent_events[event_key] = now
        if event_type == "CREATED":
            _recent_creations[norm_path] = now

        # Periodic cache cleanup
        if len(_recent_events) > 800:
            cutoff = now - 10.0
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
    Identify the active user-facing process interacting with files.
    On Windows, inspects the foreground window process (e.g. explorer.exe, powershell.exe).
    Falls back to 'System / Background' rather than attributing to FileSentinel.
    """
    if not ENABLE_PROCESS_TRACKING:
        return "N/A"

    if sys.platform == "win32":
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            if hwnd:
                pid = ctypes.c_ulong()
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value and pid.value != os.getpid() and PSUTIL_AVAILABLE:
                    return psutil.Process(pid.value).name()
        except Exception:
            pass

    return "System / Background"


class SecureTransferEventHandler(FileSystemEventHandler):
    """
    Custom watchdog event handler that processes filesystem events
    through the security pipeline with exfiltration correlation,
    line-by-line diff tracking, and cross-directory move resolution.
    """

    def _buffer_or_process_deletion(self, src_path: str):
        """
        Buffer deletion briefly (0.35s) so that if a corresponding creation
        arrives in another monitored root, it is resolved as a single MOVED event
        with both source and destination populated.
        """
        norm = os.path.normcase(os.path.normpath(os.path.abspath(src_path)))
        basename = os.path.basename(norm).lower()
        pre_hash = hasher.get_baseline_hash(src_path)

        with _debounce_lock:
            old_timer = _pending_delete_timers.pop(basename, None)
            if old_timer:
                old_timer.cancel()

            timer = threading.Timer(0.35, self._flush_deletion, args=[src_path, pre_hash])
            _pending_delete_timers[basename] = timer
            _pending_deletions[basename] = (time.monotonic(), src_path, pre_hash)
            timer.start()

    def _flush_deletion(self, src_path: str, pre_hash: str | None):
        """Callback when deletion timer expires without a matching creation (true delete)."""
        basename = os.path.basename(os.path.normcase(src_path)).lower()
        with _debounce_lock:
            _pending_deletions.pop(basename, None)
            _pending_delete_timers.pop(basename, None)
        self._process_event("DELETED", src_path, pre_hash_override=pre_hash)

    def _process_event(self, event_type: str, src_path: str, dest_path: str = "", pre_hash_override: str | None = None):
        if _should_ignore_path(src_path):
            return
        if dest_path and _should_ignore_path(dest_path):
            return

        target_path = dest_path if (event_type == "MOVED" and dest_path) else src_path
        if _is_burst_duplicate(event_type, target_path):
            return

        user    = _get_current_user()
        process = _get_process_name()

        # Step 3: Classify severity
        level = detector.classify_event(event_type, src_path, dest_path)

        # Step 4: Integrity hashing with baseline registry
        if pre_hash_override is not None:
            pre_hash = pre_hash_override
        else:
            pre_hash = hasher.get_baseline_hash(src_path)

        if event_type in ("CREATED", "CREATED_DIR"):
            post_hash = hasher.compute_hash(src_path) if os.path.exists(src_path) else None
            if not pre_hash and post_hash:
                pre_hash = post_hash
            if post_hash:
                hasher.set_baseline_hash(src_path, post_hash)
                diff_tracker.record_initial_state(src_path)
            integrity_status = "INTACT" if post_hash else "UNAVAILABLE"

        elif event_type == "MODIFIED":
            post_hash = hasher.compute_hash(src_path) if os.path.exists(src_path) else None
            if pre_hash and post_hash:
                _, integrity_status = hasher.verify_integrity(pre_hash, post_hash)
            elif post_hash:
                integrity_status = "INTACT"
            else:
                integrity_status = "UNAVAILABLE"
            if post_hash:
                hasher.set_baseline_hash(src_path, post_hash)

        elif event_type in ("MOVED", "MOVED_DIR"):
            post_hash = hasher.compute_hash(dest_path) if (dest_path and os.path.exists(dest_path)) else None
            hasher.remove_baseline_hash(src_path)
            if dest_path and post_hash:
                hasher.set_baseline_hash(dest_path, post_hash)
            if pre_hash and post_hash:
                _, integrity_status = hasher.verify_integrity(pre_hash, post_hash)
            elif post_hash:
                integrity_status = "INTACT"
            else:
                integrity_status = "UNAVAILABLE"

        elif event_type in ("DELETED", "DELETED_DIR"):
            post_hash = None
            hasher.remove_baseline_hash(src_path)
            integrity_status = "INTACT" if pre_hash else "UNAVAILABLE"

        else:
            post_hash = hasher.compute_hash(src_path) if os.path.exists(src_path) else None
            _, integrity_status = hasher.verify_integrity(pre_hash, post_hash)

        # Step 5: Diff & Content change calculation
        diff_data = diff_tracker.compute_file_diff(event_type, src_path, dest_path)

        # Step 6: Exfiltration correlation (F-01)
        basename = os.path.basename(src_path)
        now = time.monotonic()

        # Track sensitive deletions
        if event_type == "DELETED" and detector.is_sensitive_file(src_path):
            with _debounce_lock:
                _recent_deletions[basename.lower()] = (now, src_path, pre_hash)

        # Correlate creation on removable / cloud destination
        correlation_note = ""
        if event_type in ("CREATED", "MOVED"):
            dest_check = dest_path if dest_path else src_path
            if detector.is_suspicious_destination(dest_check):
                with _debounce_lock:
                    match = _recent_deletions.get(basename.lower())
                    if match and (now - match[0]) < 10.0:
                        del_src = match[1]
                        level = "CRITICAL"
                        correlation_note = f" [Cross-Volume Exfiltration: moved/copied from '{del_src}']"

        # Step 7: Log event (with exact diff)
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
            extra            = {"diff": diff_data},
        )

        # Step 8: Trigger alert
        if level in ("WARNING", "CRITICAL"):
            description = detector.describe_event(event_type, src_path, dest_path) + correlation_note
            alerter.trigger_alert(
                level      = level,
                message    = description,
                event_data = {
                    "event_type":       event_type,
                    "source":           src_path,
                    "destination":      dest_path,
                    "user":             user,
                    "process":          process,
                    "hash_pre":         pre_hash or "N/A",
                    "hash_post":        post_hash or "N/A",
                    "integrity_status": integrity_status,
                    "diff":             diff_data,
                },
            )

    # ── Watchdog Callbacks (with Directory Expansion F-08 & Move Correlation) ─

    def on_created(self, event):
        if event.is_directory:
            self._process_event("CREATED_DIR", event.src_path)
            if os.path.isdir(event.src_path):
                try:
                    for root, _, files in os.walk(event.src_path):
                        for f in files:
                            self._process_event("CREATED", os.path.join(root, f))
                except OSError:
                    pass
        else:
            basename = os.path.basename(os.path.normcase(event.src_path)).lower()
            with _debounce_lock:
                pending = _pending_deletions.pop(basename, None)
                timer = _pending_delete_timers.pop(basename, None)
                if timer:
                    timer.cancel()

            if pending and pending[1] != event.src_path:
                # Correlated cross-directory move!
                orig_src = pending[1]
                orig_pre_hash = pending[2]
                self._process_event("MOVED", orig_src, event.src_path, pre_hash_override=orig_pre_hash)
            else:
                self._process_event("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            self._process_event("DELETED_DIR", event.src_path)
        else:
            self._buffer_or_process_deletion(event.src_path)

    def on_moved(self, event):
        basename = os.path.basename(os.path.normcase(event.src_path)).lower()
        with _debounce_lock:
            timer = _pending_delete_timers.pop(basename, None)
            if timer:
                timer.cancel()
            _pending_deletions.pop(basename, None)

        if event.is_directory:
            self._process_event("MOVED_DIR", event.src_path, event.dest_path)
            if os.path.isdir(event.dest_path):
                try:
                    for root, _, files in os.walk(event.dest_path):
                        for f in files:
                            dest_f = os.path.join(root, f)
                            rel = os.path.relpath(dest_f, event.dest_path)
                            src_f = os.path.join(event.src_path, rel)
                            self._process_event("MOVED", src_f, dest_f)
                except OSError:
                    pass
        else:
            self._process_event("MOVED", event.src_path, event.dest_path)


class FileMonitor:
    """
    Manages watchdog Observer instances with auto-discovered directories,
    baseline seeding, and background USB/removable media polling.
    """

    def __init__(self, directories: list[str] | None = None):
        self.observer = Observer()
        self._running = False
        self._stop_event = threading.Event()
        self.event_handler = SecureTransferEventHandler()
        self.directories = directories if directories is not None else get_auto_discovered_targets()
        self._scheduled_paths: set[str] = set()

    def _seed_baseline(self):
        """Index existing files in monitored folders to populate baseline hashes and diff caches."""
        try:
            for d in self.directories:
                expanded = os.path.expandvars(d)
                if not os.path.isdir(expanded):
                    continue
                for root, _, files in os.walk(expanded):
                    if _should_ignore_path(root):
                        continue
                    for f in files:
                        fp = os.path.join(root, f)
                        if not _should_ignore_path(fp):
                            try:
                                hasher.set_baseline_hash(fp)
                                diff_tracker.record_initial_state(fp)
                            except Exception:
                                pass
        except Exception:
            pass

    def start(self):
        """Schedule watchers for all discovered directories and start observer."""
        scheduled = 0
        for directory in self.directories:
            directory = os.path.expandvars(directory)
            if os.path.isdir(directory):
                norm = os.path.normcase(os.path.normpath(directory))
                if norm not in self._scheduled_paths:
                    try:
                        self.observer.schedule(
                            self.event_handler,
                            path      = directory,
                            recursive = True,
                        )
                        self._scheduled_paths.add(norm)
                        print(f"  [+] Watching: {directory}")
                        scheduled += 1
                    except Exception as e:
                        print(f"  [-] Could not watch {directory}: {e}")
            else:
                print(f"  [-] Skipped (not found): {directory}")

        if scheduled == 0:
            print("[WARNING] No valid directories to monitor. Edit config.py to add paths.")
            return

        self.observer.start()
        self._running = True
        print(f"\n  Monitoring {scheduled} director(ies) & cloud/removable drives. Press Ctrl+C to stop.\n")

        # Start dynamic USB/removable drive attachment watcher
        poll_thread = threading.Thread(target=self._poll_new_drives, daemon=True)
        poll_thread.start()

        # Seed baseline hashes and diff caches in background
        seed_thread = threading.Thread(target=self._seed_baseline, daemon=True)
        seed_thread.start()

    def _poll_new_drives(self):
        """Polls periodically for newly plugged-in USB or network drives."""
        while not self._stop_event.is_set():
            time.sleep(5.0)
            if not self._running:
                break
            discovered = get_auto_discovered_targets()
            for d in discovered:
                norm = os.path.normcase(os.path.normpath(d))
                if norm not in self._scheduled_paths and os.path.isdir(d):
                    try:
                        self.observer.schedule(self.event_handler, path=d, recursive=True)
                        self._scheduled_paths.add(norm)
                        print(f"  [+] Auto-detected & watching new target: {d}")
                    except Exception:
                        pass

    def stop(self):
        """Gracefully stop observer, timers, and polling threads."""
        if self._running:
            self._stop_event.set()
            with _debounce_lock:
                for timer in _pending_delete_timers.values():
                    timer.cancel()
                _pending_delete_timers.clear()
                _pending_deletions.clear()
            self.observer.stop()
            self.observer.join(timeout=1.0)
            self._running = False
            print("\n  Monitor stopped. Goodbye.")

    def is_running(self) -> bool:
        return self._running
