"""
hasher.py - File Integrity Hashing Module
Uses Python's built-in hashlib — no installation required.
Supports SHA256, SHA512, and MD5 algorithms.
"""

from __future__ import annotations   # PEP 563: compatible with Python 3.7+

import hashlib
import os
from config import HASH_ALGORITHM, HASH_CHUNK_SIZE

# In-memory snapshot: {filepath: hash_digest}
# Populated before a transfer for pre/post comparison.
_hash_snapshot: dict[str, str] = {}


def compute_hash(filepath: str, algorithm: str = HASH_ALGORITHM) -> str | None:
    """
    Compute the hash of a file using the specified algorithm.

    Args:
        filepath:  Absolute path to the file.
        algorithm: Hash algorithm name ('sha256', 'sha512', 'md5').

    Returns:
        Hex digest string, or None if the file cannot be read.
    """
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
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
