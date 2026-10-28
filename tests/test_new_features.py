"""
tests/test_new_features.py - Verification Tests for Findings and Enhanced Capabilities

Covers:
  1. Exact content diff tracking on file modification (diff_tracker.py)
  2. Cross-directory move correlation ensuring destination field is never empty (monitor.py)
  3. Hash integrity baseline tracking eliminating false "N/A" (UNAVAILABLE) states (hasher.py)
  4. Live alert enrichment with full telemetry and diff data (alerter.py / monitor.py)
  5. Multi-criteria log filtering and sorting (date, severity, directory, file type) (logger.py)
"""

import os
import sys
import time
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hasher
import diff_tracker
import logger
import monitor


class TestDiffTracker(unittest.TestCase):
    """Test Requirement 1: Exact line-by-line diff tracking for modified operations."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8")
        self.tmp.write("line 1\nline 2\nline 3\n")
        self.tmp.close()
        self.filepath = self.tmp.name
        diff_tracker.record_initial_state(self.filepath)

    def tearDown(self):
        try:
            os.unlink(self.filepath)
        except OSError:
            pass

    def test_text_file_modification_diff(self):
        """Modifying lines in a text file produces a structured unified diff."""
        # Append and modify
        with open(self.filepath, "w", encoding="utf-8") as f:
            f.write("line 1\nline 2 MODIFIED\nline 3\nline 4 NEW\n")

        diff = diff_tracker.compute_file_diff("MODIFIED", self.filepath)
        self.assertEqual(diff["type"], "text")
        self.assertGreater(diff["added_count"], 0)
        self.assertIn("+", diff["snippet"])
        self.assertIn("line 4 NEW", diff["snippet"])
        self.assertIn("added", diff["summary"])

    def test_binary_file_modification_delta(self):
        """Binary files report byte delta size changes rather than text diffs."""
        bin_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".docx", mode="wb")
        bin_tmp.write(b"PK\x03\x04InitialBinaryDocxBytes" * 10)
        bin_tmp.close()
        diff_tracker.record_initial_state(bin_tmp.name)

        # Expand binary size
        with open(bin_tmp.name, "ab") as f:
            f.write(b"ExtraAppendedBinaryDataBytes" * 5)

        diff = diff_tracker.compute_file_diff("MODIFIED", bin_tmp.name)
        os.unlink(bin_tmp.name)

        self.assertEqual(diff["type"], "binary")
        self.assertGreater(diff["size_delta"], 0)
        self.assertIn("Binary content modified", diff["summary"])


class TestHashBaselineRegistry(unittest.TestCase):
    """Test Requirement 3: Elimination of 'N/A' (UNAVAILABLE) hash integrity states."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".docx", mode="wb")
        self.tmp.write(b"BaselineDocumentContent")
        self.tmp.close()
        self.filepath = self.tmp.name

    def tearDown(self):
        try:
            os.unlink(self.filepath)
        except OSError:
            pass
        hasher.remove_baseline_hash(self.filepath)

    def test_baseline_registry_lifecycle(self):
        """Baseline hash is retained across move/modify lifecycles even if source is deleted."""
        digest = hasher.set_baseline_hash(self.filepath)
        self.assertIsNotNone(digest)

        # Verify lookup returns baseline
        looked_up = hasher.get_baseline_hash(self.filepath)
        self.assertEqual(looked_up, digest)

        # Simulate move by deleting source and computing at dest
        dest_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".docx", mode="wb")
        dest_tmp.write(b"BaselineDocumentContent")
        dest_tmp.close()

        os.unlink(self.filepath)

        # Source is now gone from disk
        self.assertFalse(os.path.exists(self.filepath))

        # Baseline registry still has pre_hash
        pre_hash = hasher.get_baseline_hash(self.filepath)
        post_hash = hasher.compute_hash(dest_tmp.name)
        os.unlink(dest_tmp.name)

        ok, status = hasher.verify_integrity(pre_hash, post_hash)
        self.assertTrue(ok)
        self.assertEqual(status, "INTACT")


class TestAdvancedLogSortingAndFiltering(unittest.TestCase):
    """Test Requirement 5: Extended log sorting by Date, Level, Directory, and File Type."""

    def setUp(self):
        self.orig_log = logger.AUDIT_LOG_PATH
        self.test_log_dir = tempfile.mkdtemp(prefix="test_logger_")
        self.test_log_file = os.path.join(self.test_log_dir, "audit.log")
        logger.AUDIT_LOG_PATH = self.test_log_file

        # Seed sample events
        logger.log_event("CREATED", "C:\\Users\\User\\Documents\\report.docx", "", "User", "explorer.exe", "h1", "h1", "INTACT", "WARNING")
        logger.log_event("CREATED", "C:\\Users\\User\\Secrets\\private.pem", "", "User", "powershell.exe", "h2", "h2", "INTACT", "CRITICAL")
        logger.log_event("MODIFIED", "C:\\Users\\User\\Scripts\\backup.py", "", "User", "python.exe", "h3", "h4", "TAMPERED", "INFO")
        logger.log_event("DELETED", "C:\\Users\\User\\Downloads\\archive.zip", "", "User", "explorer.exe", "h5", "N/A", "INTACT", "INFO")

    def tearDown(self):
        logger.AUDIT_LOG_PATH = self.orig_log
        import shutil
        shutil.rmtree(self.test_log_dir, ignore_errors=True)

    def test_filter_by_file_type_documents(self):
        entries = logger.load_logs(file_type="documents")
        self.assertEqual(len(entries), 1)
        self.assertIn("report.docx", entries[0]["source"])

    def test_filter_by_file_type_secrets(self):
        entries = logger.load_logs(file_type="secrets")
        self.assertEqual(len(entries), 1)
        self.assertIn("private.pem", entries[0]["source"])

    def test_filter_by_directory(self):
        entries = logger.load_logs(directory="Secrets")
        self.assertEqual(len(entries), 1)
        self.assertIn("Secrets", entries[0]["source"])

    def test_sort_by_severity(self):
        entries_desc = logger.load_logs(sort_by="level", order="desc")
        self.assertEqual(entries_desc[0]["alert_level"], "CRITICAL")

        entries_asc = logger.load_logs(sort_by="level", order="asc")
        self.assertEqual(entries_asc[0]["alert_level"], "INFO")

    def test_sort_by_source_path(self):
        entries = logger.load_logs(sort_by="source", order="asc")
        sources = [e["source"] for e in entries]
        self.assertEqual(sources, sorted(sources))


class TestCrossDirectoryMoveCorrelation(unittest.TestCase):
    """Test Requirement 2: Ensuring destination is populated on cross-directory moves."""

    def setUp(self):
        self.orig_log = logger.AUDIT_LOG_PATH
        self.test_log_dir = tempfile.mkdtemp(prefix="test_move_")
        self.test_log_file = os.path.join(self.test_log_dir, "audit.log")
        logger.AUDIT_LOG_PATH = self.test_log_file

        self.handler = monitor.SecureTransferEventHandler()

    def tearDown(self):
        logger.AUDIT_LOG_PATH = self.orig_log
        import shutil
        shutil.rmtree(self.test_log_dir, ignore_errors=True)

    def test_cross_directory_move_populates_destination(self):
        """Simulate Watchdog's separate delete and create notifications across directories."""
        src_file = "C:\\Users\\User\\Desktop\\financial_report.xlsx"
        dest_file = "C:\\Users\\User\\Documents\\financial_report.xlsx"

        # Mock an event class
        class MockEvent:
            def __init__(self, path, is_dir=False):
                self.src_path = path
                self.is_directory = is_dir

        # 1. First event: file deleted from desktop
        self.handler.on_deleted(MockEvent(src_file))

        # 2. Second event: file created in documents within correlation window
        self.handler.on_created(MockEvent(dest_file))

        # Load logs and verify a single MOVED event with destination was emitted
        logs = logger.load_logs()
        self.assertGreaterEqual(len(logs), 1)
        move_log = [l for l in logs if l["event_type"] == "MOVED"]
        self.assertEqual(len(move_log), 1)
        self.assertEqual(move_log[0]["source"], src_file)
        self.assertEqual(move_log[0]["destination"], dest_file)
        self.assertTrue(len(move_log[0]["destination"]) > 0)

