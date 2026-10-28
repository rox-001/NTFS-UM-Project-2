"""
hasher.py - File Integrity Hashing Module
Uses Python's built-in hashlib — no installation required.
Supports SHA256, SHA512, and MD5 algorithms with Windows file-lock retry backoff
and baseline hash registry for continuous file integrity tracking.
"""

from __future__ import annotations

import hashlib
import os
import time
from config import HASH_ALGORITHM, HASH_CHUNK_SIZE

# In-memory snapshot: {filepath: hash_digest}
_hash_snapshot: dict[str, str] = {}

# Continuous baseline hash registry: {norm_path: hash_digest}
_baseline_hashes: dict[str, str] = {}


def compute_hash(
    filepath: str,
    algorithm: str = HASH_ALGORITHM,
    retries: int = 3,
    retry_delay: float = 0.05,
) -> str | None:
    """
    Compute the hash of a file using the specified algorithm.
    Includes automated retry backoff to handle transient Windows file locks during writes.

    Args:
        filepath:    Absolute path to the file.
        algorithm:   Hash algorithm name ('sha256', 'sha512', 'md5').
        retries:     Number of retry attempts if file is temporarily locked.
        retry_delay: Initial delay in seconds between retries.

    Returns:
        Hex digest string, or None if the file cannot be read.
    """
    if not filepath:
        return None

    for attempt in range(max(1, retries)):
        try:
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
    """
    Compute and store the hash of a file in the snapshot dict.
    Call this BEFORE a transfer occurs.

    Returns:
        The computed hash, or None on failure.
    """
    digest = compute_hash(filepath)
    if digest:
        _hash_snapshot[filepath] = digest
        set_baseline_hash(filepath, digest)
    return digest


def check_against_snapshot(filepath: str) -> tuple[bool, str, str | None, str | None]:
    """
    Compare a file's current hash against its stored snapshot.
    Call this AFTER a transfer/modification occurs.

    Returns:
        (integrity_ok, status, pre_hash, post_hash)
    """
    pre_hash  = _hash_snapshot.get(filepath)
    post_hash = compute_hash(filepath)
    ok, status = verify_integrity(pre_hash, post_hash)
    return ok, status, pre_hash, post_hash


def clear_snapshot(filepath: str = None):
    """Remove a specific file from the snapshot, or clear all."""
    if filepath:
        _hash_snapshot.pop(filepath, None)
    else:
        _hash_snapshot.clear()


def get_snapshot() -> dict:
    """Return a copy of the current hash snapshot."""
    return dict(_hash_snapshot)


# ── Baseline Registry Functions ──────────────────────────────────────────────

def set_baseline_hash(filepath: str, digest: str | None = None) -> str | None:
    """Store or update the known baseline hash for a normalized path."""
    if not filepath:
        return None
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    if digest is None:
        digest = compute_hash(filepath)
    if digest:
        _baseline_hashes[norm] = digest
    return digest


def get_baseline_hash(filepath: str) -> str | None:
    """Retrieve the last recorded baseline hash for a file."""
    if not filepath:
        return None
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    return _baseline_hashes.get(norm)


def remove_baseline_hash(filepath: str) -> str | None:
    """Remove a file from the baseline registry."""
    if not filepath:
        return None
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    return _baseline_hashes.pop(norm, None)
