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
from config import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG, LOGS_PER_PAGE

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/api/logs")
def api_logs():
    """
    Return paginated, filterable log entries as JSON.
    Query params:
      - level:   Filter by alert level (INFO / WARNING / CRITICAL)
      - keyword: Search in source/destination/event_type
      - page:    Page number (1-indexed)
    """
    level   = request.args.get("level", "").upper() or None
    keyword = request.args.get("keyword", "") or None
    page    = max(1, int(request.args.get("page", 1)))

    entries  = logger.load_logs(level_filter=level, keyword=keyword)
    total    = len(entries)
    # Most recent first for display
    entries  = list(reversed(entries))
    start    = (page - 1) * LOGS_PER_PAGE
    end      = start + LOGS_PER_PAGE
    page_entries = entries[start:end]

    return jsonify({
        "logs":       page_entries,
        "total":      total,
        "page":       page,
        "per_page":   LOGS_PER_PAGE,
        "total_pages": max(1, (total + LOGS_PER_PAGE - 1) // LOGS_PER_PAGE),
    })


@app.route("/api/stats")
def api_stats():
    """Return summary statistics."""
    return jsonify(logger.get_stats())


@app.route("/api/alerts")
def api_alerts():
    """Return the most recent alerts."""
    limit  = int(request.args.get("limit", 20))
    alerts = alerter.load_alerts(limit=limit)
    return jsonify(list(reversed(alerts)))  # Most recent first


def run_dashboard(host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT):
    """Start the Flask development server (blocking call)."""
    print(f"\n  Dashboard → http://{host}:{port}  (local only, no internet needed)")
    app.run(host=host, port=port, debug=DASHBOARD_DEBUG, use_reloader=False)
