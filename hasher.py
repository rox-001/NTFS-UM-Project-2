"""
hasher.py - File Integrity Hashing Module
Uses Python's built-in hashlib — no installation required.
Supports SHA256, SHA512, MD5, and Sparse Tri-Point Hashing for large files (>50MB),
with Windows file-lock retry backoff and persistent SQLite baseline database.
"""

from __future__ import annotations

import hashlib
import os
import time
from config import HASH_ALGORITHM, HASH_CHUNK_SIZE
import db

# Sparse hashing threshold: 50 MB
SPARSE_HASH_THRESHOLD = 50 * 1024 * 1024
SPARSE_CHUNK_SIZE = 1024 * 1024  # 1 MB

# In-memory snapshot: {filepath: hash_digest}
_hash_snapshot: dict[str, str] = {}

# In-memory baseline cache: {norm_path: hash_digest}
_baseline_hashes: dict[str, str] = {}


def compute_hash(
    filepath: str,
    algorithm: str = HASH_ALGORITHM,
    retries: int = 3,
    retry_delay: float = 0.05,
    force_full: bool = False,
) -> str | None:
    """
    Compute cryptographic hash of a file.
    Uses sparse tri-point hashing for files > 50MB to prevent I/O lockups,
    and includes automated retry backoff to handle transient Windows write locks.

    Args:
        filepath:    Absolute path to the file.
        algorithm:   Hash algorithm name ('sha256', 'sha512', 'md5').
        retries:     Number of retry attempts if file is temporarily locked.
        retry_delay: Initial delay in seconds between retries.
        force_full:  If True, forces full byte hashing even for large files.

    Returns:
        Hex digest string, or None if the file cannot be read.
    """
    if not filepath:
        return None

    for attempt in range(max(1, retries)):
        try:
            if not os.path.exists(filepath):
                return None

            file_size = os.path.getsize(filepath)

            # Sparse Hashing Optimization for Large Files (>50 MB)
            if not force_full and file_size > SPARSE_HASH_THRESHOLD:
                return _compute_sparse_hash(filepath, file_size, algorithm)

            # Standard Full Hash for normal files
            h = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                while chunk := f.read(HASH_CHUNK_SIZE):
                    h.update(chunk)
            return h.hexdigest()

        except PermissionError:
            # Windows file locking (WinError 32) during active application flush
            if attempt < retries - 1:
                time.sleep(retry_delay * (attempt + 1))
            else:
                return None
        except (FileNotFoundError, OSError, ValueError):
            return None
    return None


def _compute_sparse_hash(filepath: str, file_size: int, algorithm: str) -> str:
    """
    Compute a fast sparse tri-point hash:
    Samples 1 MB from header, 1 MB from midpoint, and 1 MB from footer,
    combined with file size and modification time.
    """
    h = hashlib.new(algorithm)
    mtime = os.path.getmtime(filepath)
    h.update(f"SPARSE_V1:{file_size}:{mtime}:".encode("utf-8"))

    with open(filepath, "rb") as f:
        # 1. Header chunk (1 MB)
        h.update(f.read(SPARSE_CHUNK_SIZE))

        # 2. Middle chunk (1 MB)
        mid_offset = max(0, (file_size // 2) - (SPARSE_CHUNK_SIZE // 2))
        f.seek(mid_offset)
        h.update(f.read(SPARSE_CHUNK_SIZE))

        # 3. Footer chunk (1 MB)
        tail_offset = max(0, file_size - SPARSE_CHUNK_SIZE)
        f.seek(tail_offset)
        h.update(f.read(SPARSE_CHUNK_SIZE))

    return h.hexdigest()


def verify_integrity(pre_hash: str | None, post_hash: str | None) -> tuple[bool, str]:
    """
    Compare pre- and post-transfer hashes.

    Returns:
        (True, "INTACT")       if hashes match
        (False, "TAMPERED")    if hashes differ
        (False, "UNAVAILABLE") if either hash is None
    """
    if pre_hash is None or post_hash is None:
        return False, "UNAVAILABLE"
    if pre_hash == post_hash:
        return True, "INTACT"
    return False, "TAMPERED"


def snapshot_file(filepath: str) -> str | None:
    """Compute and store hash of a file in memory snapshot and persistent database."""
    digest = compute_hash(filepath)
    if digest:
        _hash_snapshot[filepath] = digest
        set_baseline_hash(filepath, digest)
    return digest


def check_against_snapshot(filepath: str) -> tuple[bool, str, str | None, str | None]:
    pre_hash = _hash_snapshot.get(filepath) or get_baseline_hash(filepath)
    post_hash = compute_hash(filepath)
    ok, status = verify_integrity(pre_hash, post_hash)
    return ok, status, pre_hash, post_hash


def clear_snapshot(filepath: str = None):
    if filepath:
        _hash_snapshot.pop(filepath, None)
    else:
        _hash_snapshot.clear()


def get_snapshot() -> dict:
    return dict(_hash_snapshot)


# ── Baseline Registry Functions (Dual Memory & SQLite Persistence) ───────────

def set_baseline_hash(filepath: str, digest: str | None = None) -> str | None:
    """Store or update the baseline hash in memory and persistent SQLite."""
    if not filepath:
        return None
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    if digest is None:
        digest = compute_hash(filepath)
    if digest:
        _baseline_hashes[norm] = digest
        size = 0
        mtime = 0.0
        try:
            if os.path.exists(filepath):
                size = os.path.getsize(filepath)
                mtime = os.path.getmtime(filepath)
        except OSError:
            pass
        db.set_baseline(filepath, digest, size, mtime)
    return digest


def get_baseline_hash(filepath: str) -> str | None:
    """Retrieve the last recorded baseline hash (memory cache with SQLite fallback)."""
    if not filepath:
        return None
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    cached = _baseline_hashes.get(norm)
    if cached:
        return cached

    # Persistent SQLite lookup
    row = db.get_baseline(filepath)
    if row and row.get("hash"):
        _baseline_hashes[norm] = row["hash"]
        return row["hash"]
    return None


def remove_baseline_hash(filepath: str) -> str | None:
    """Remove a file from baseline memory cache and persistent SQLite."""
    if not filepath:
        return None
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    db.remove_baseline(filepath)
    return _baseline_hashes.pop(norm, None)
