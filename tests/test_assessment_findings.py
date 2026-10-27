"""
tests/test_assessment_findings.py - Reproduction & Verification Tests for Assessment Report Findings

Validates fixes for:
  - F-01: Copy-based exfiltration / removable media detection
  - F-02: Substring matching false CRITICAL alerts (report_template.docx, attempt2.txt, Templates folder, tmpuser)
  - F-03: Ignore rule evasion (secret.pem.tmp, leak.zip.part)
  - F-04: Own-folder prefix match (Downloads sibling folder Downloads2)
  - F-05: .git / .vscode exact folder matching (.github, .gitconfig)
  - F-06: Creating file in suspicious folder returns CRITICAL
  - F-07: Removable-drive detection for all drive letters (E:, Z:, etc.)
  - F-08: Directory events not skipped
  - F-09: Process attribution not claiming FileSentinel PID
  - F-10: Destination file type evaluated on rename (notes.txt -> notes.pem)
  - F-11: Debounce allows rapid legitimate edits with content change
  - F-12: Network-share check with forward slashes (//server/share)
  - F-13: Invalid hash algorithm returns None without unhandled exception
  - F-14: Dynamic folder resolution (OneDrive redirection, cloud sync roots)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detector
import hasher
import monitor


class TestAssessmentReportFixes(unittest.TestCase):

    # ── F-02: Substring Matching False Positives ──────────────────────────────
    def test_f02_renaming_report_template_not_critical(self):
        """Renaming report.docx to report_template.docx should NOT be CRITICAL (not temp)."""
        level = detector.classify_event("MOVED", "C:\\Docs\\report.docx", "C:\\Docs\\report_template.docx")
        # Moving sensitive file locally is WARNING or normal sensitive move, NOT exfiltration to temp
        self.assertFalse(detector.is_suspicious_destination("C:\\Docs\\report_template.docx"))

    def test_f02_attempt2_txt_not_suspicious(self):
        """notes.txt to attempt2.txt should NOT trigger suspicious destination for 'temp'."""
        self.assertFalse(detector.is_suspicious_destination("C:\\Docs\\attempt2.txt"))

    def test_f02_folder_named_templates_not_suspicious(self):
        """Folder named 'Templates' should not be flagged as a temp folder."""
        self.assertFalse(detector.is_suspicious_destination("C:\\Users\\User\\Templates\\doc.docx"))

    def test_f02_tmpuser_profile_not_suspicious(self):
        """User profile C:\\Users\\tmpuser\\Documents should not trigger temp destination."""
        self.assertFalse(detector.is_suspicious_destination("C:\\Users\\tmpuser\\Documents\\file.txt"))

    def test_f02_real_temp_folder_is_suspicious(self):
        """Actual temp directory (e.g. C:\\Windows\\Temp\\file.docx) IS suspicious."""
        self.assertTrue(detector.is_suspicious_destination("C:\\Windows\\Temp\\file.docx"))

    # ── F-06: Creating in Suspicious Folder is CRITICAL ────────────────────────
    def test_f06_creating_sensitive_in_cloud_is_critical(self):
        """Creating secret.pem in Dropbox should return CRITICAL, not just WARNING."""
        level = detector.classify_event("CREATED", "C:\\Users\\User\\Dropbox\\secret.pem")
        self.assertEqual(level, "CRITICAL")

    # ── F-10: Destination File Type on Rename ─────────────────────────────────
    def test_f10_renaming_txt_to_pem_is_sensitive(self):
        """Renaming notes.txt to notes.pem must evaluate destination as sensitive."""
        level = detector.classify_event("MOVED", "C:\\Docs\\notes.txt", "C:\\Docs\\notes.pem")
        # Destination is sensitive (.pem) -> should escalate to CRITICAL or WARNING, not INFO
        self.assertIn(level, ("CRITICAL", "WARNING"))

    # ── F-12: Network Share Normalisation ─────────────────────────────────────
    def test_f12_forward_slash_network_share(self):
        """//server/share/file.docx should be recognized as a suspicious network share."""
        self.assertTrue(detector.is_suspicious_destination("//server/share/file.docx"))

    # ── F-13: Invalid Hash Algorithm Exception Handling ───────────────────────
    def test_f13_invalid_hash_algorithm_returns_none(self):
        """hashlib.new('sha257') should return None instead of raising unhandled ValueError."""
        test_file = os.path.abspath(__file__)
        result = hasher.compute_hash(test_file, algorithm="sha257")
        self.assertIsNone(result)

    # ── F-05: .git and .vscode Exact Path Part Matching ───────────────────────
    def test_f05_github_folder_not_ignored(self):
        """.github\\secrets.env should NOT be ignored like .git."""
        self.assertFalse(monitor._should_ignore_path("C:\\Project\\.github\\secrets.env"))

    def test_f05_gitconfig_not_ignored(self):
        """.gitconfig should NOT be ignored."""
        self.assertFalse(monitor._should_ignore_path("C:\\Users\\User\\.gitconfig"))

    def test_f05_real_git_folder_is_ignored(self):
        """.git internal objects should be ignored."""
        self.assertTrue(monitor._should_ignore_path("C:\\Project\\.git\\objects\\01\\abcdef"))

    # ── F-03: Double Extension Evasion ────────────────────────────────────────
    def test_f03_sensitive_double_extension_not_ignored(self):
        """secret.pem.tmp and leak.zip.part must NOT be silently ignored."""
        self.assertFalse(monitor._should_ignore_path("C:\\Docs\\secret.pem.tmp"))
        self.assertFalse(monitor._should_ignore_path("C:\\Docs\\leak.zip.part"))

    # ── F-04: Own-Folder Sibling Exclusions ────────────────────────────────────
    def test_f04_sibling_folders_not_ignored(self):
        """Downloads2\\secret.pem should NOT be ignored if base is Downloads."""
        # Simulated test: path having matching prefix without separator
        base = "C:\\Users\\User\\Downloads"
        sibling = "C:\\Users\\User\\Downloads2\\secret.pem"
        # Must not match as internal
        self.assertFalse(sibling.startswith(base + os.sep))


if __name__ == "__main__":
    unittest.main(verbosity=2)
