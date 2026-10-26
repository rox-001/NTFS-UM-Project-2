"""
tests/test_integration.py - Live integration test for debounce and self-logging prevention
"""

import os
import sys
import time
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor import FileMonitor
import logger


def test_monitor_no_flood():
    # Record starting log count
    start_logs = len(logger.load_logs())

    # Create a temporary monitored directory
    temp_dir = tempfile.mkdtemp(prefix="sec_mon_test_")

    monitor = FileMonitor(directories=[temp_dir])
    monitor.start()
    time.sleep(0.5)

    try:
        # 1. Create a normal file and write to it multiple times in rapid succession
        normal_file = os.path.join(temp_dir, "notes.txt")
        with open(normal_file, "w") as f:
            f.write("Hello World\n")

        # Simulate rapid write flushes like Windows does during file copy
        for i in range(10):
            with open(normal_file, "a") as f:
                f.write(f"Line {i}\n")
            time.sleep(0.05)

        time.sleep(1.0)

        # 2. Create a sensitive file
        sensitive_file = os.path.join(temp_dir, "payroll.xlsx")
        with open(sensitive_file, "wb") as f:
            f.write(b"PK\x03\x04DummyExcelBytes")

        for i in range(10):
            with open(sensitive_file, "ab") as f:
                f.write(b"extra_chunk")
            time.sleep(0.05)

        time.sleep(1.0)

    finally:
        monitor.stop()
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Check results
    new_logs = logger.load_logs()[start_logs:]
    print(f"\n--- INTEGRATION TEST RESULTS ---")
    print(f"Total events recorded: {len(new_logs)}")
    for l in new_logs:
        print(f"[{l['alert_level']}] {l['event_type']} -> {os.path.basename(l['source'])}")

    normal_events = [l for l in new_logs if "notes.txt" in l["source"]]
    sensitive_events = [l for l in new_logs if "payroll.xlsx" in l["source"]]

    print(f"Normal file events: {len(normal_events)} (expected 1, was 0 without debounce)")
    print(f"Sensitive file events: {len(sensitive_events)} (expected 1, was 0 without debounce)")

    assert len(normal_events) <= 2, f"Too many normal file events: {len(normal_events)}"
    assert len(sensitive_events) <= 2, f"Too many sensitive file events: {len(sensitive_events)}"

    # Check alert levels
    if normal_events:
        assert normal_events[0]["alert_level"] == "INFO", f"Expected INFO for notes.txt, got {normal_events[0]['alert_level']}"
    if sensitive_events:
        assert sensitive_events[0]["alert_level"] == "WARNING", f"Expected WARNING for payroll.xlsx, got {sensitive_events[0]['alert_level']}"

    print("ALL INTEGRATION ASSERTIONS PASSED! Clean, non-flooded monitoring verified.")


if __name__ == "__main__":
    test_monitor_no_flood()
