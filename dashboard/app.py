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
      - level:     Filter by alert level (INFO / WARNING / CRITICAL)
      - keyword:   Search in source/destination/event_type/user
      - sort_by:   Field to sort by (timestamp, source, ext, level, integrity)
      - order:     Sort direction (asc / desc)
      - file_type: Filter by file category (documents, secrets, databases, scripts, archives)
      - directory: Filter by directory path substring
      - page:      Page number (1-indexed)
    """
    level     = request.args.get("level", "").upper() or None
    keyword   = request.args.get("keyword", "") or None
    sort_by   = request.args.get("sort_by", "timestamp")
    order     = request.args.get("order", "desc").lower()
    file_type = request.args.get("file_type", "") or None
    directory = request.args.get("directory", "") or None
    page      = max(1, int(request.args.get("page", 1)))

    entries = logger.load_logs(
        level_filter=level,
        keyword=keyword,
        sort_by=sort_by,
        order=order,
        file_type=file_type,
        directory=directory,
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
    """Return summary statistics."""
    return jsonify(logger.get_stats())


@app.route("/api/alerts")
def api_alerts():
    """Return the most recent alerts."""
    limit  = int(request.args.get("limit", 30))
    alerts = alerter.load_alerts(limit=limit)
    return jsonify(list(reversed(alerts)))  # Most recent first


def run_dashboard(host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT):
    """Start the Flask development server (blocking call)."""
    print(f"\n  Dashboard → http://{host}:{port}  (local only, no internet needed)")
    app.run(host=host, port=port, debug=DASHBOARD_DEBUG, use_reloader=False)
