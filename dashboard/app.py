"""
dashboard/app.py - SPLUNK-style Local Web Dashboard
Serves a real-time log viewer at http://localhost:5000
100% LOCAL — no internet, no external APIs, reads only from local log files.
"""

import sys
import os

# Allow imports from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
import logger
import alerter
import db
import process_tracker
from monitor import get_active_monitor
from config import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG, LOGS_PER_PAGE, RESOURCE_DIR

template_dir = os.path.join(RESOURCE_DIR, "dashboard", "templates")
static_dir   = os.path.join(RESOURCE_DIR, "dashboard", "static")

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/api/logs")
def api_logs():
    """
    Return paginated, filterable, and sortable log entries as JSON.
    Query params:
      - level:      Filter by alert level (INFO / WARNING / CRITICAL)
      - keyword:    Search in source/destination/event_type/user/dlp (free text or tokens like user:X ext:Y)
      - sort_by:    Field to sort by (timestamp, level, risk, source, ext, integrity)
      - order:      Sort direction (asc / desc)
      - file_type:  Filter by category (documents, secrets, databases, scripts, archives)
      - directory:  Filter by directory path substring
      - start_time: ISO start timestamp filter (e.g. 2026-10-27T14:00)
      - end_time:   ISO end timestamp filter (e.g. 2026-10-27T18:00)
      - timeframe:  Quick timeframe preset ('1h', '24h', '7d', 'all')
      - page:       Page number (1-indexed)
    """
    level      = request.args.get("level", "").upper() or None
    keyword    = request.args.get("keyword", "") or None
    sort_by    = request.args.get("sort_by", "timestamp")
    order      = request.args.get("order", "desc").lower()
    file_type  = request.args.get("file_type", "") or None
    directory  = request.args.get("directory", "") or None
    start_time = request.args.get("start_time", "") or None
    end_time   = request.args.get("end_time", "") or None
    timeframe  = request.args.get("timeframe", "") or None
    page       = max(1, int(request.args.get("page", 1)))

    entries = logger.load_logs(
        level_filter=level,
        keyword=keyword,
        sort_by=sort_by,
        order=order,
        file_type=file_type,
        directory=directory,
        start_time=start_time,
        end_time=end_time,
        timeframe=timeframe,
    )
    total = len(entries)
    start = (page - 1) * LOGS_PER_PAGE
    end   = start + LOGS_PER_PAGE
    page_entries = entries[start:end]

    return jsonify({
        "logs":        page_entries,
        "total":       total,
        "page":        page,
        "per_page":    LOGS_PER_PAGE,
        "total_pages": max(1, (total + LOGS_PER_PAGE - 1) // LOGS_PER_PAGE),
        "sort_by":     sort_by,
        "order":       order,
    })


@app.route("/api/stats")
def api_stats():
    """Return summary statistics filtered by timeframe/search."""
    timeframe  = request.args.get("timeframe", "") or None
    start_time = request.args.get("start_time", "") or None
    end_time   = request.args.get("end_time", "") or None
    keyword    = request.args.get("keyword", "") or None
    file_type  = request.args.get("file_type", "") or None
    return jsonify(logger.get_stats(
        timeframe=timeframe,
        start_time=start_time,
        end_time=end_time,
        keyword=keyword,
        file_type=file_type,
    ))


@app.route("/api/alerts")
def api_alerts():
    """Return the most recent alerts."""
    limit  = int(request.args.get("limit", 30))
    alerts = alerter.load_alerts(limit=limit)
    return jsonify(list(reversed(alerts)))  # Most recent first


# ── Directory Management Endpoints ───────────────────────────────────────────

@app.route("/api/directories", methods=["GET"])
def api_get_directories():
    """Return active and configured monitored directories."""
    monitor = get_active_monitor()
    if monitor:
        dirs = monitor.get_monitored_directories()
    else:
        db_dirs = db.get_monitored_directories()
        dirs = [{"path": p, "is_active": True, "is_custom": True} for p in db_dirs]
    return jsonify({"directories": dirs})


@app.route("/api/directories/add", methods=["POST"])
def api_add_directory():
    """Add and schedule a new monitored directory dynamically."""
    data = request.get_json(force=True, silent=True) or {}
    path = (data.get("path") or data.get("directory") or "").strip()
    if not path or not os.path.isdir(path):
        return jsonify({"success": False, "error": f"Invalid or non-existent directory path: '{path}'"}), 400

    monitor = get_active_monitor()
    if monitor:
        ok = monitor.add_directory(path)
    else:
        ok = db.add_monitored_directory(path)

    return jsonify({
        "success": ok,
        "message": f"Successfully registered '{path}' for real-time monitoring." if ok else "Failed to register directory."
    })


@app.route("/api/directories/remove", methods=["POST"])
def api_remove_directory():
    """Remove and unschedule a monitored directory."""
    data = request.get_json(force=True, silent=True) or {}
    path = (data.get("path") or data.get("directory") or "").strip()
    if not path:
        return jsonify({"success": False, "error": "Missing directory path."}), 400

    monitor = get_active_monitor()
    if monitor:
        ok = monitor.remove_directory(path)
    else:
        ok = db.remove_monitored_directory(path)

    return jsonify({
        "success": ok,
        "message": f"Successfully removed '{path}' from monitoring." if ok else "Failed to remove directory."
    })


@app.route("/api/browse-directory", methods=["GET"])
def api_browse_directory():
    """List child directories and files of a given folder or system drives for GUI browsing."""
    target = request.args.get("path", "").strip()
    if not target:
        # Return common user roots and drive letters
        import string
        common = [
            os.path.normpath(os.path.expanduser("~/Desktop")),
            os.path.normpath(os.path.expanduser("~/Documents")),
            os.path.normpath(os.path.expanduser("~/Downloads")),
        ]
        if sys.platform == "win32":
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            drives = [f"{letter}:\\" for i, letter in enumerate(string.ascii_uppercase) if bitmask & (1 << i)]
            return jsonify({
                "current": "",
                "parent": "",
                "folders": [{"name": os.path.basename(p), "path": p, "type": "folder"} for p in common if os.path.isdir(p)],
                "files": [],
                "drives": drives
            })
        return jsonify({
            "current": "",
            "parent": "",
            "folders": [{"name": os.path.basename(p), "path": p, "type": "folder"} for p in common if os.path.isdir(p)],
            "files": [],
            "drives": []
        })

    target = os.path.normpath(target)
    if not os.path.isdir(target):
        return jsonify({"error": f"Path is not a valid directory: '{target}'"}), 400

    try:
        subfolders = []
        files = []
        for name in os.listdir(target):
            if name.startswith("$") or name.startswith("."):
                continue
            full = os.path.join(target, name)
            try:
                if os.path.isdir(full):
                    subfolders.append({
                        "name": name,
                        "path": os.path.normpath(full),
                        "type": "folder"
                    })
                elif os.path.isfile(full):
                    size = os.path.getsize(full)
                    files.append({
                        "name": name,
                        "path": os.path.normpath(full),
                        "size": size,
                        "type": "file"
                    })
            except (OSError, PermissionError):
                continue

        subfolders.sort(key=lambda x: x["name"].lower())
        files.sort(key=lambda x: x["name"].lower())
        parent = os.path.dirname(target) if os.path.dirname(target) != target else ""

        return jsonify({
            "current": target,
            "parent": parent,
            "folders": subfolders[:300],
            "files": files[:300],
            "total_folders": len(subfolders),
            "total_files": len(files),
            "drives": []
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── SOC One-Click Remediation Endpoints ───────────────────────────────────────

@app.route("/api/action/quarantine", methods=["POST"])
def api_action_quarantine():
    """Quarantine a flagged file into the encrypted vault."""
    data = request.get_json(force=True, silent=True) or {}
    source = (data.get("source") or data.get("file_path") or data.get("path") or "").strip()
    reason = data.get("reason", "SOC Operator Manual Action")
    if not source:
        return jsonify({"success": False, "error": "Missing file source path"}), 400

    res = db.quarantine_file(source, reason)
    if res.get("success"):
        res["quarantine_vault_path"] = res.get("quarantined_path")
    return jsonify(res)


@app.route("/api/action/terminate", methods=["POST"])
def api_action_terminate():
    """Terminate an unapproved exfiltration process."""
    data = request.get_json(force=True, silent=True) or {}
    pid = data.get("pid")
    if not pid:
        return jsonify({"success": False, "error": "Missing process PID"}), 400

    res = process_tracker.terminate_process(int(pid))
    return jsonify(res)


@app.route("/api/action/allowlist", methods=["POST"])
def api_action_allowlist():
    """Add a file path, extension, or hash to the SOC allowlist."""
    data = request.get_json(force=True, silent=True) or {}
    entry = (data.get("entry") or data.get("path") or "").strip()
    entry_type = data.get("entry_type") or data.get("type") or "path"
    reason = data.get("reason", "Operator Allowed")
    if not entry:
        return jsonify({"success": False, "error": "Missing entry value"}), 400

    ok = db.add_to_allowlist(entry, entry_type, reason)
    return jsonify({"success": ok, "message": f"Successfully added '{entry}' to allowlist."})


@app.route("/api/allowlist", methods=["GET"])
def api_get_allowlist():
    """Return all active allowlist entries."""
    return jsonify({"allowlist": db.get_allowlist()})


@app.route("/api/quarantine", methods=["GET"])
def api_get_quarantine():
    """Return all quarantined files in vault along with vault directory."""
    files = db.get_quarantined_files()
    return jsonify({
        "vault": files,
        "quarantined_files": files,
        "quarantine_dir": db.QUARANTINE_DIR
    })


@app.route("/api/quarantine/restore", methods=["POST"])
def api_restore_quarantine():
    """Restore a quarantined file back to its original location."""
    data = request.get_json(force=True, silent=True) or {}
    record_id = data.get("id")
    if not record_id:
        return jsonify({"success": False, "error": "Missing record ID"}), 400
    res = db.restore_quarantined_file(int(record_id))
    return jsonify(res)


@app.route("/api/quarantine/open-folder", methods=["POST"])
def api_open_quarantine_folder():
    """Open the quarantine vault folder in Windows Explorer."""
    try:
        if sys.platform == "win32":
            os.startfile(db.QUARANTINE_DIR)
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Folder viewing is only supported on Windows."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


def run_dashboard(host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT):
    """Start the Flask development server (blocking call)."""
    print(f"\n  Dashboard → http://{host}:{port}  (local only, no internet needed)")
    app.run(host=host, port=port, debug=DASHBOARD_DEBUG, use_reloader=False)
