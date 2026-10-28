"""
diff_tracker.py - Exact File Content Diff & Change Tracking Engine
Tracks before-and-after content modifications for files in real time.
Computes unified diffs for text/code/config files and byte deltas for binary documents.
"""

from __future__ import annotations

import difflib
import os
import time

# In-memory baseline content & size caches: {norm_path: text_content}
_content_cache: dict[str, str] = {}
_size_cache: dict[str, int] = {}

# Max file size to cache text content for diffing (1 MB)
_MAX_DIFF_TEXT_SIZE = 1024 * 1024


def _is_binary_file(filepath: str) -> bool:
    """Return True if file is binary (contains null bytes or non-text extension)."""
    _, ext = os.path.splitext(filepath.lower())
    if ext in {
        ".docx", ".xlsx", ".pptx", ".pdf", ".zip", ".rar", ".tar", ".gz",
        ".7z", ".db", ".sqlite", ".png", ".jpg", ".jpeg", ".ico", ".exe",
        ".dll", ".bin", ".dat", ".pfx", ".p12"
    }:
        return True

    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except Exception:
        return True
    return False


def _read_text_safely(filepath: str, retries: int = 3) -> str | None:
    """Read file as text with encoding fallbacks and Windows file-lock retry backoff."""
    for attempt in range(max(1, retries)):
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except PermissionError:
            if attempt < retries - 1:
                time.sleep(0.05 * (attempt + 1))
            else:
                return None
        except Exception:
            return None
    return None


def record_initial_state(filepath: str):
    """Snapshot a file's initial content/size when first observed."""
    if not filepath or not os.path.isfile(filepath):
        return
    norm = os.path.normcase(os.path.normpath(os.path.abspath(filepath)))
    try:
        size = os.path.getsize(filepath)
        _size_cache[norm] = size
        if size <= _MAX_DIFF_TEXT_SIZE and not _is_binary_file(filepath):
            content = _read_text_safely(filepath)
            if content is not None:
                _content_cache[norm] = content
    except Exception:
        pass


def compute_file_diff(event_type: str, src_path: str, dest_path: str = "") -> dict:
    """
    Compute what actually changed in the file during an event.

    Returns a structured dictionary:
      - type: 'text' | 'binary' | 'lifecycle'
      - summary: Brief human-readable delta (e.g. '+3 lines, -1 line (+48 bytes)')
      - added_count: Number of added lines (for text)
      - removed_count: Number of deleted lines (for text)
      - snippet: Formatted unified diff or binary status string
      - size_delta: Byte difference (positive or negative)
    """
    target_path = dest_path if (event_type == "MOVED" and dest_path) else src_path
    if not target_path:
        return {"type": "none", "summary": "No target path", "snippet": ""}

    norm = os.path.normcase(os.path.normpath(os.path.abspath(target_path)))
    src_norm = os.path.normcase(os.path.normpath(os.path.abspath(src_path)))

    # 1. CREATED
    if event_type in ("CREATED", "CREATED_DIR"):
        size = 0
        try:
            if os.path.exists(target_path):
                size = os.path.getsize(target_path)
        except OSError:
            pass

        _size_cache[norm] = size
        if not _is_binary_file(target_path) and size <= _MAX_DIFF_TEXT_SIZE:
            content = _read_text_safely(target_path) or ""
            _content_cache[norm] = content
            line_count = len(content.splitlines())
            return {
                "type": "text",
                "summary": f"Initial file created ({line_count} lines, {size:,} bytes)",
                "added_count": line_count,
                "removed_count": 0,
                "size_delta": size,
                "snippet": f"+++ Initial File Content ({line_count} lines, {size:,} bytes) +++",
            }
        return {
            "type": "binary",
            "summary": f"New file created ({size:,} bytes)",
            "added_count": 0,
            "removed_count": 0,
            "size_delta": size,
            "snippet": f"[Binary payload established: {size:,} bytes]",
        }

    # 2. DELETED
    if event_type in ("DELETED", "DELETED_DIR"):
        old_size = _size_cache.pop(src_norm, 0)
        _content_cache.pop(src_norm, None)
        return {
            "type": "lifecycle",
            "summary": f"File deleted from disk ({old_size:,} bytes removed)",
            "added_count": 0,
            "removed_count": 0,
            "size_delta": -old_size,
            "snippet": f"--- File Removed ({old_size:,} bytes) ---",
        }

    # 3. MOVED
    if event_type in ("MOVED", "MOVED_DIR"):
        old_size = _size_cache.pop(src_norm, 0)
        old_content = _content_cache.pop(src_norm, None)

        new_size = old_size
        try:
            if os.path.exists(target_path):
                new_size = os.path.getsize(target_path)
        except OSError:
            pass

        _size_cache[norm] = new_size
        if old_content is not None:
            _content_cache[norm] = old_content

        dest_name = os.path.basename(dest_path) if dest_path else "new destination"
        return {
            "type": "lifecycle",
            "summary": f"Relocated to: {dest_path or target_path} ({new_size:,} bytes)",
            "added_count": 0,
            "removed_count": 0,
            "size_delta": 0,
            "snippet": f"→ Transferred to {dest_name}",
        }

    # 4. MODIFIED
    old_size = _size_cache.get(norm, 0)
    new_size = old_size
    try:
        if os.path.exists(target_path):
            new_size = os.path.getsize(target_path)
    except OSError:
        pass
    size_delta = new_size - old_size
    _size_cache[norm] = new_size

    # Check if text file for unified diff
    if not _is_binary_file(target_path) and new_size <= _MAX_DIFF_TEXT_SIZE:
        new_content = _read_text_safely(target_path)
        old_content = _content_cache.get(norm)

        if new_content is not None and old_content is not None:
            old_lines = old_content.splitlines(keepends=True)
            new_lines = new_content.splitlines(keepends=True)

            diff_generator = difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile="previous",
                tofile="current",
                n=2,
            )
            diff_lines = list(diff_generator)

            added = [l.rstrip("\r\n") for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
            removed = [l.rstrip("\r\n") for l in diff_lines if l.startswith("-") and not l.startswith("---")]

            _content_cache[norm] = new_content

            if added or removed:
                delta_sign = "+" if size_delta >= 0 else ""
                summary = f"+{len(added)} added, -{len(removed)} removed ({delta_sign}{size_delta:,} bytes)"
                snippet_text = "".join(diff_lines[:40])  # Cap at 40 lines
                if len(diff_lines) > 40:
                    snippet_text += f"\n... [{len(diff_lines) - 40} additional lines truncated]"
                return {
                    "type": "text",
                    "summary": summary,
                    "added_count": len(added),
                    "removed_count": len(removed),
                    "added_samples": added[:5],
                    "removed_samples": removed[:5],
                    "size_delta": size_delta,
                    "snippet": snippet_text,
                }

        if new_content is not None:
            _content_cache[norm] = new_content

    # Binary or non-diffable file
    delta_sign = "+" if size_delta >= 0 else ""
    summary = f"Binary content modified: {old_size:,} bytes → {new_size:,} bytes ({delta_sign}{size_delta:,} bytes)"
    return {
        "type": "binary",
        "summary": summary,
        "added_count": 0,
        "removed_count": 0,
        "size_delta": size_delta,
        "snippet": f"[Binary Payload: {delta_sign}{size_delta:,} bytes change]",
    }
