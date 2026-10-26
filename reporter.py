"""
reporter.py - Audit Report Generator
Reads audit.log and produces a formatted text report with summary stats and event table.
"""

import os
from datetime import datetime
from tabulate import tabulate

from config import REPORT_DIR, AUDIT_LOG_PATH
from logger import load_logs, get_stats

os.makedirs(REPORT_DIR, exist_ok=True)


def generate_report(output_path: str = None) -> str:
    """
    Generate a comprehensive audit report from the current audit.log.

    Args:
        output_path: Optional custom file path. Defaults to
                     reports/audit_report_<timestamp>.txt

    Returns:
        Absolute path to the generated report file.
    """
    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(REPORT_DIR, f"audit_report_{ts}.txt")

    entries = load_logs()
    stats   = get_stats()
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []

    # ─── Header ───────────────────────────────────────────────────────────────
    lines.append("=" * 72)
    lines.append("  SECURE FILE TRANSFER MONITORING SYSTEM — AUDIT REPORT")
    lines.append("=" * 72)
    lines.append(f"  Generated : {now}")
    lines.append(f"  Log file  : {AUDIT_LOG_PATH}")
    lines.append("=" * 72)
    lines.append("")

    # ─── Summary Statistics ───────────────────────────────────────────────────
    lines.append("[ SUMMARY STATISTICS ]")
    lines.append("")
    summary_table = [
        ["Total Events",            stats["total"]],
        ["INFO",                    stats["info"]],
        ["WARNING",                 stats["warning"]],
        ["CRITICAL",                stats["critical"]],
        ["Integrity OK",            stats["integrity_ok"]],
        ["Integrity TAMPERED",      stats["integrity_tampered"]],
    ]
    lines.append(tabulate(summary_table, headers=["Metric", "Count"], tablefmt="grid"))
    lines.append("")

    # ─── Top Suspicious Sources ───────────────────────────────────────────────
    critical_entries = [e for e in entries if e.get("alert_level") == "CRITICAL"]
    warning_entries  = [e for e in entries if e.get("alert_level") == "WARNING"]

    if critical_entries or warning_entries:
        lines.append("[ POLICY VIOLATIONS ]")
        lines.append("")
        violations = []
        for e in (critical_entries + warning_entries):
            violations.append([
                e.get("timestamp", "")[:19],
                e.get("alert_level", ""),
                e.get("event_type", ""),
                _truncate(e.get("source", ""), 35),
                _truncate(e.get("destination", ""), 25),
                e.get("user", ""),
                e.get("integrity_status", ""),
            ])
        headers = ["Timestamp", "Level", "Event", "Source", "Destination", "User", "Integrity"]
        lines.append(tabulate(violations, headers=headers, tablefmt="grid"))
        lines.append("")

    # ─── Full Event Log ───────────────────────────────────────────────────────
    lines.append("[ FULL EVENT LOG ]")
    lines.append("")
    if not entries:
        lines.append("  No events recorded.")
    else:
        rows = []
        for e in entries[-100:]:   # Last 100 entries in report
            rows.append([
                e.get("timestamp", "")[:19],
                e.get("alert_level", ""),
                e.get("event_type", ""),
                _truncate(e.get("source", ""), 40),
                _truncate(e.get("destination", ""), 30),
                e.get("user", ""),
                e.get("integrity_status", ""),
            ])
        headers = ["Timestamp", "Level", "Event", "Source", "Destination", "User", "Integrity"]
        lines.append(tabulate(rows, headers=headers, tablefmt="simple"))

    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF REPORT")
    lines.append("=" * 72)

    report_text = "\n".join(lines)

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(report_text)
    print(f"\n  Report saved → {output_path}")
    return output_path


def _truncate(text: str, max_len: int) -> str:
    """Truncate a string to max_len characters, adding '…' if cut."""
    if not text:
        return ""
    return text if len(text) <= max_len else text[:max_len - 1] + "…"
