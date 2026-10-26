"""
tests/test_detector.py - Unit Tests for detector.py
Uses Python's built-in unittest module.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detector


class TestIsSensitiveFile(unittest.TestCase):

    def test_sensitive_extension_docx(self):
        self.assertTrue(detector.is_sensitive_file("C:\\Reports\\budget.docx"))

    def test_sensitive_extension_pem(self):
        self.assertTrue(detector.is_sensitive_file("/etc/ssl/server.pem"))

    def test_sensitive_extension_env(self):
        self.assertTrue(detector.is_sensitive_file("C:\\project\\.env"))

    def test_sensitive_extension_sql(self):
        self.assertTrue(detector.is_sensitive_file("D:\\backup\\dump.sql"))

    def test_normal_extension_txt(self):
        # .txt is not in the sensitive extensions list
        self.assertFalse(detector.is_sensitive_file("C:\\Users\\Public\\note.txt"))

    def test_normal_extension_png(self):
        self.assertFalse(detector.is_sensitive_file("C:\\Photos\\img.png"))

    def test_empty_path(self):
        self.assertFalse(detector.is_sensitive_file(""))

    def test_none_path(self):
        self.assertFalse(detector.is_sensitive_file(None))


class TestIsSuspiciousDestination(unittest.TestCase):

    def test_usb_drive_e(self):
        self.assertTrue(detector.is_suspicious_destination("E:\\secret\\file.docx"))

    def test_usb_drive_f(self):
        self.assertTrue(detector.is_suspicious_destination("F:\\backup.zip"))

    def test_unc_network_path(self):
        self.assertTrue(detector.is_suspicious_destination("\\\\fileserver\\share\\doc.pdf"))

    def test_onedrive_path(self):
        self.assertTrue(
            detector.is_suspicious_destination("C:\\Users\\Sven\\OneDrive\\secret.docx")
        )

    def test_dropbox_path(self):
        self.assertTrue(
            detector.is_suspicious_destination("C:\\Users\\Sven\\Dropbox\\report.xlsx")
        )

    def test_normal_local_path(self):
        self.assertFalse(
            detector.is_suspicious_destination("C:\\Users\\Sven\\Documents\\notes.docx")
        )

    def test_empty_destination(self):
        self.assertFalse(detector.is_suspicious_destination(""))


class TestClassifyEvent(unittest.TestCase):

    def test_sensitive_file_to_usb_is_critical(self):
        level = detector.classify_event("MOVED", "C:\\Secret\\payroll.xlsx", "E:\\copy.xlsx")
        self.assertEqual(level, "CRITICAL")

    def test_normal_file_to_usb_is_critical(self):
        # FIX: use C:\Projects instead of C:\Temp (Temp is in SUSPICIOUS_PATH_KEYWORDS)
        level = detector.classify_event("MOVED", "C:\\Projects\\notes.txt", "E:\\notes.txt")
        self.assertEqual(level, "CRITICAL")

    def test_sensitive_file_moved_locally_is_critical(self):
        # Moving sensitive files is CRITICAL even within local directories
        level = detector.classify_event("MOVED", "C:\\Docs\\contract.docx", "C:\\Archive\\")
        self.assertEqual(level, "CRITICAL")

    def test_sensitive_file_deleted_is_critical(self):
        level = detector.classify_event("DELETED", "C:\\Docs\\key.pem")
        self.assertEqual(level, "CRITICAL")

    def test_sensitive_file_created_is_warning(self):
        level = detector.classify_event("CREATED", "C:\\Docs\\report.pdf")
        self.assertEqual(level, "WARNING")

    def test_sensitive_file_modified_is_warning(self):
        level = detector.classify_event("MODIFIED", "C:\\Docs\\budget.xlsx")
        self.assertEqual(level, "WARNING")

    def test_normal_file_normal_path_is_info(self):
        # FIX: C:\Temp contains "Temp" which is in SUSPICIOUS_PATH_KEYWORDS.
        # Use C:\Projects instead — a neutral path with no sensitive/suspicious markers.
        level = detector.classify_event("CREATED", "C:\\Projects\\notes.txt")
        self.assertEqual(level, "INFO")

    def test_normal_file_modified_is_info(self):
        level = detector.classify_event("MODIFIED", "C:\\Public\\readme.txt")
        self.assertEqual(level, "INFO")


class TestDescribeEvent(unittest.TestCase):

    def test_created_description(self):
        desc = detector.describe_event("CREATED", "C:\\Docs\\report.pdf")
        self.assertIn("created", desc.lower())
        self.assertIn("report.pdf", desc)

    def test_moved_description(self):
        desc = detector.describe_event("MOVED", "C:\\Docs\\file.docx", "E:\\file.docx")
        self.assertIn("moved", desc.lower())

    def test_deleted_description(self):
        desc = detector.describe_event("DELETED", "C:\\secret.key")
        self.assertIn("deleted", desc.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
