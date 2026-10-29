"""
db.py - Persistent SQLite Database Engine for FileSentinel
Manages persistent baseline file hashes, custom monitored directories,
SOC allowlists, and quarantine vault metadata across system reboots.
"""

import os
import sqlite3
import threading
import time
import shutil
from config import BASE_DIR

DATA_DIR = os.path.join(BASE_DIR, "data")
VAULT_DIR = os.path.join(BASE_DIR, "vault")
QUARANTINE_DIR = os.path.join(VAULT_DIR, "quarantine")
DB_PATH = os.path.join(DATA_DIR, "filesentinel.db")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

_db_lock = threading.Lock()


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and indexes if they do not exist."""
    with _db_lock, _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS baseline_hashes (
                norm_path TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitored_directories (
                path TEXT PRIMARY KEY,
                added_at REAL NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS allowlist (
                entry TEXT PRIMARY KEY,
                entry_type TEXT NOT NULL,
                reason TEXT,
                added_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantined_path TEXT NOT NULL,
                quarantined_at REAL NOT NULL,
                file_size INTEGER NOT NULL,
                original_hash TEXT,
                reason TEXT
            )
        """)
        conn.commit()


# Initialize database schema immediately on module import
init_db()


# ── Baseline Hash Functions ──────────────────────────────────────────────────

def set_baseline(filepath: str, digest: str, size: int = 0, mtime: float = 0.0):
    if not filepath or not digest:
        return
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    now = time.time()
    with _db_lock, _get_connection() as conn:
        conn.execute("""
            INSERT INTO baseline_hashes (norm_path, hash, size, mtime, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(norm_path) DO UPDATE SET
                hash = excluded.hash,
                size = excluded.size,
                mtime = excluded.mtime,
                updated_at = excluded.updated_at
        """, (norm, digest, size, mtime, now))
        conn.commit()


def get_baseline(filepath: str) -> dict | None:
    if not filepath:
        return None
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    with _db_lock, _get_connection() as conn:
        row = conn.execute(
            "SELECT norm_path, hash, size, mtime, updated_at FROM baseline_hashes WHERE norm_path = ?",
            (norm,)
        ).fetchone()
        if row:
            return dict(row)
    return None


def remove_baseline(filepath: str):
    if not filepath:
        return
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    with _db_lock, _get_connection() as conn:
        conn.execute("DELETE FROM baseline_hashes WHERE norm_path = ?", (norm,))
        conn.commit()


def get_all_baselines() -> dict[str, str]:
    with _db_lock, _get_connection() as conn:
        rows = conn.execute("SELECT norm_path, hash FROM baseline_hashes").fetchall()
        return {r["norm_path"]: r["hash"] for r in rows}


# ── Monitored Directories Functions ──────────────────────────────────────────

def get_monitored_directories() -> list[str]:
    with _db_lock, _get_connection() as conn:
        rows = conn.execute(
            "SELECT path FROM monitored_directories WHERE is_active = 1 ORDER BY path ASC"
        ).fetchall()
        return [r["path"] for r in rows]


def add_monitored_directory(path: str) -> bool:
    if not path or not os.path.isdir(path):
        return False
    norm = os.path.normpath(os.path.abspath(path))
    with _db_lock, _get_connection() as conn:
        conn.execute("""
            INSERT INTO monitored_directories (path, added_at, is_active)
            VALUES (?, ?, 1)
            ON CONFLICT(path) DO UPDATE SET is_active = 1
        """, (norm, time.time()))
        conn.commit()
    return True


def remove_monitored_directory(path: str) -> bool:
    if not path:
        return False
    norm = os.path.normpath(os.path.abspath(path))
    with _db_lock, _get_connection() as conn:
        conn.execute("DELETE FROM monitored_directories WHERE path = ?", (norm,))
        conn.commit()
    return True


# ── Allowlist Functions ──────────────────────────────────────────────────────

def add_to_allowlist(entry: str, entry_type: str = "path", reason: str = "") -> bool:
    if not entry:
        return False
    norm = os.path.normcase(os.path.normpath(entry)) if entry_type == "path" else entry.strip().lower()
    with _db_lock, _get_connection() as conn:
        conn.execute("""
            INSERT INTO allowlist (entry, entry_type, reason, added_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(entry) DO UPDATE SET reason = excluded.reason
        """, (norm, entry_type, reason, time.time()))
        conn.commit()
    return True


def is_allowlisted(filepath: str, digest: str = None) -> bool:
    if not filepath:
        return False
    norm_path = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    _, ext = os.path.splitext(norm_path)

    with _db_lock, _get_connection() as conn:
        # Check path
        row = conn.execute("SELECT 1 FROM allowlist WHERE entry = ? AND entry_type = 'path'", (norm_path,)).fetchone()
        if row:
            return True
        # Check extension
        if ext:
            row = conn.execute("SELECT 1 FROM allowlist WHERE entry = ? AND entry_type = 'ext'", (ext,)).fetchone()
            if row:
                return True
        # Check hash
        if digest:
            row = conn.execute("SELECT 1 FROM allowlist WHERE entry = ? AND entry_type = 'hash'", (digest.lower(),)).fetchone()
            if row:
                return True
    return False


def get_allowlist() -> list[dict]:
    with _db_lock, _get_connection() as conn:
        rows = conn.execute("SELECT entry, entry_type, reason, added_at FROM allowlist ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]


# ── Quarantine Vault Functions ───────────────────────────────────────────────

def quarantine_file(src_path: str, reason: str = "User Initiated Quarantine") -> dict:
    """
    Safely relocate a file to the isolated quarantine vault,
    rename it with .quarantine extension, and make it read-only.
    """
    if not src_path or not os.path.exists(src_path):
        return {"success": False, "error": f"File does not exist on disk: '{src_path}'"}

    norm_src = os.path.normpath(os.path.abspath(src_path))
    try:
        size = os.path.getsize(norm_src)
    except OSError:
        size = 0

    basename = os.path.basename(norm_src)
    ts = int(time.time())
    dest_filename = f"{ts}_{basename}.quarantine"
    dest_path = os.path.join(QUARANTINE_DIR, dest_filename)

    try:
        shutil.move(norm_src, dest_path)
        # Set read-only permissions on quarantined file
        try:
            os.chmod(dest_path, 0o444)
        except OSError:
            pass

        with _db_lock, _get_connection() as conn:
            conn.execute("""
                INSERT INTO quarantine_vault (original_path, quarantined_path, quarantined_at, file_size, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (norm_src, dest_path, time.time(), size, reason))
            conn.commit()

        # Remove from baseline registry
        remove_baseline(norm_src)

        return {
            "success": True,
            "original_path": norm_src,
            "quarantined_path": dest_path,
            "size": size,
            "message": f"Successfully quarantined {basename} to vault."
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_quarantined_files() -> list[dict]:
    with _db_lock, _get_connection() as conn:
        rows = conn.execute("""
            SELECT id, original_path, quarantined_path, quarantined_at, file_size, reason
            FROM quarantine_vault ORDER BY quarantined_at DESC
        """).fetchall()
        return [dict(r) for r in rows]
