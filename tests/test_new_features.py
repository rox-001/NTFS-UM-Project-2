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


class TestV2Enhancements(unittest.TestCase):
    """Unit tests covering the Do Now V2 architecture enhancements."""

    def test_dlp_scanner_secrets_and_pii(self):
        """Test true DLP regex pattern matching and Luhn credit card validation."""
        import dlp_scanner

        # 1. AWS Access Key
        aws_sample = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
            f.write(aws_sample)
            tmp_path = f.name
        res = dlp_scanner.scan_file_content(tmp_path)
        os.unlink(tmp_path)
        self.assertTrue(res["is_violation"])
        match_types = [m["type"] for m in res["matches"]]
        self.assertIn("AWS Access Key", match_types)
        self.assertGreater(res["risk_bonus"], 0)

        # 2. RSA / Private Key
        rsa_sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
            f.write(rsa_sample)
            tmp_path = f.name
        res = dlp_scanner.scan_file_content(tmp_path)
        os.unlink(tmp_path)
        self.assertTrue(res["is_violation"])
        match_types = [m["type"] for m in res["matches"]]
        self.assertIn("Private Key", match_types)

        # 3. Luhn Valid vs Invalid Credit Card
        self.assertTrue(dlp_scanner._luhn_checksum_valid("4111111111111111"))
        self.assertFalse(dlp_scanner._luhn_checksum_valid("4111111111111112"))

    def test_database_persistence_layer(self):
        """Test SQLite persistence for baselines, monitored dirs, allowlist, and quarantine."""
        import db

        test_path = "C:\\Files\\sample_test.docx"
        test_hash = "abcdef0123456789"

        # Baseline hash CRUD
        db.set_baseline(test_path, test_hash, size=1024)
        fetched = db.get_baseline(test_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["hash"], test_hash)
        self.assertEqual(fetched["size"], 1024)

        db.remove_baseline(test_path)
        self.assertIsNone(db.get_baseline(test_path))

        # Monitored directories CRUD
        test_dir = tempfile.mkdtemp(prefix="test_mon_")
        try:
            db.add_monitored_directory(test_dir)
            dirs = db.get_monitored_directories()
            self.assertIn(test_dir, dirs)
            db.remove_monitored_directory(test_dir)
            self.assertNotIn(test_dir, db.get_monitored_directories())
        finally:
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)

        # Allowlist CRUD
        db.add_to_allowlist(test_path, entry_type="path", reason="Testing")
        self.assertTrue(db.is_allowlisted(test_path, test_hash))
        db.add_to_allowlist("C:\\Files\\other.txt", entry_type="path")
        self.assertTrue(db.is_allowlisted("C:\\Files\\other.txt"))

    def test_process_tracker_safety(self):
        """Test process termination safety guards preventing kill of critical system PIDs."""
        import process_tracker

        # Refusal to kill PID 0, 4 (System)
        res_zero = process_tracker.terminate_process(0)
        self.assertFalse(res_zero["success"])
        self.assertIn("system process", res_zero["error"].lower())

        res_four = process_tracker.terminate_process(4)
        self.assertFalse(res_four["success"])
        self.assertIn("system process", res_four["error"].lower())

        # Current process telemetry lookup
        curr_pid = os.getpid()
        telem = process_tracker.get_process_telemetry(curr_pid)
        self.assertIsNotNone(telem)
        self.assertEqual(telem["pid"], curr_pid)
        self.assertIn("python", telem["name"].lower())

    def test_risk_scoring_matrix(self):
        """Test 0-100 mathematical risk scoring and severity mapping."""
        import detector

        # Normal file locally: low risk, INFO
        score, level = detector.calculate_risk_score("CREATED", "C:\\Users\\User\\notes.txt", "")
        self.assertLess(score, 40)
        self.assertEqual(level, "INFO")

        # Sensitive file moved to USB: high risk, CRITICAL
        score_crit, level_crit = detector.calculate_risk_score(
            "MOVED",
            "C:\\Users\\User\\keys.pem",
            "E:\\keys.pem",
            process_name="powershell.exe",
            dlp_bonus=15
        )
        self.assertGreaterEqual(score_crit, 70)
        self.assertEqual(level_crit, "CRITICAL")

    def test_smart_search_token_parsing(self):
        """Test tokenized smart search in audit logs."""
        import logger
        orig_log = logger.AUDIT_LOG_PATH
        test_dir = tempfile.mkdtemp(prefix="test_search_")
        test_file = os.path.join(test_dir, "audit.log")
        logger.AUDIT_LOG_PATH = test_file

        try:
            logger.log_event("CREATED", "C:\\HR\\payroll.xlsx", "", "alice", "excel.exe", "h1", "h1", "INTACT", "WARNING", risk_score=55)
            logger.log_event("DOWNLOADED", "C:\\Downloads\\installer.exe", "", "bob", "chrome.exe", "h2", "h2", "INTACT", "INFO", risk_score=20)
            logger.log_event("MOVED", "C:\\Keys\\id_rsa", "E:\\id_rsa", "charlie", "cmd.exe", "h3", "h3", "INTACT", "CRITICAL", risk_score=85)

            # 1. Search by risk token
            high_risk = logger.load_logs(keyword="risk:>50")
            self.assertEqual(len(high_risk), 2)

            # 2. Search by event token
            downloads = logger.load_logs(keyword="event:DOWNLOADED")
            self.assertEqual(len(downloads), 1)
            self.assertEqual(downloads[0]["user"], "bob")

            # 3. Search by user token
            alice_logs = logger.load_logs(keyword="user:alice")
            self.assertEqual(len(alice_logs), 1)
        finally:
            logger.AUDIT_LOG_PATH = orig_log
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_quarantine_and_restore_lifecycle(self):
        """Test file quarantine and subsequent safe restoration to original location."""
        import db

        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
            f.write("Quarantine test payload data")
            orig_path = f.name

        try:
            # Quarantine
            q_res = db.quarantine_file(orig_path, reason="Automated Unit Test")
            self.assertTrue(q_res["success"])
            record_id = q_res["record_id"]
            self.assertFalse(os.path.exists(orig_path))

            # Verify in vault list
            vault_list = db.get_quarantined_files()
            self.assertTrue(any(item["id"] == record_id for item in vault_list))

            # Restore
            rest_res = db.restore_quarantined_file(record_id)
            self.assertTrue(rest_res["success"])
            self.assertTrue(os.path.exists(orig_path))

            # Verify removed from vault
            vault_after = db.get_quarantined_files()
            self.assertFalse(any(item["id"] == record_id for item in vault_after))
        finally:
            if os.path.exists(orig_path):
                os.unlink(orig_path)

    def test_timeframe_stats_filtering(self):
        """Test relative timeframe calculation in logger.load_logs and logger.get_stats."""
        import json
        import logger
        from datetime import datetime, timedelta

        orig_log = logger.AUDIT_LOG_PATH
        test_dir = tempfile.mkdtemp(prefix="test_tf_")
        test_file = os.path.join(test_dir, "audit.log")
        logger.AUDIT_LOG_PATH = test_file

        try:
            now = datetime.now()
            ts_recent = (now - timedelta(minutes=10)).isoformat()
            ts_yesterday = (now - timedelta(hours=12)).isoformat()
            ts_old = (now - timedelta(days=5)).isoformat()

            logger.log_event("CREATED", "C:\\recent.txt", "", "user1", "p1", "", "", "INTACT", "INFO")
            logger.log_event("MODIFIED", "C:\\yesterday.txt", "", "user2", "p2", "", "", "INTACT", "WARNING")
            logger.log_event("DELETED", "C:\\old.txt", "", "user3", "p3", "", "", "INTACT", "CRITICAL")

            # Rewrite timestamps in test file to simulate past events
            entries = []
            with open(test_file, "r") as f:
                for line in f:
                    entries.append(json.loads(line))
            entries[0]["timestamp"] = ts_recent
            entries[1]["timestamp"] = ts_yesterday
            entries[2]["timestamp"] = ts_old

            with open(test_file, "w") as f:
                for e in entries:
                    f.write(json.dumps(e) + "\n")

            # 1h should only contain 1 event
            stats_1h = logger.get_stats(timeframe="1h")
            self.assertEqual(stats_1h["total"], 1)

            # 24h should contain 2 events
            stats_24h = logger.get_stats(timeframe="24h")
            self.assertEqual(stats_24h["total"], 2)

            # all should contain 3 events
            stats_all = logger.get_stats(timeframe="all")
            self.assertEqual(stats_all["total"], 3)
        finally:
            logger.AUDIT_LOG_PATH = orig_log
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)



