"""
tests/test_hasher.py - Unit Tests for hasher.py
Uses Python's built-in unittest module — no extra install needed.
"""

import os
import sys
import tempfile
import unittest
import hashlib

# Allow imports from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hasher


class TestComputeHash(unittest.TestCase):
    """Tests for hasher.compute_hash()"""

    def setUp(self):
        """Create a temporary file with known content for testing."""
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb")
        self.tmp.write(b"SecureMonitor Test File - 12345")
        self.tmp.close()
        self.filepath = self.tmp.name

    def tearDown(self):
        os.unlink(self.filepath)
        hasher.clear_snapshot()

    def test_sha256_returns_hex_string(self):
        result = hasher.compute_hash(self.filepath, "sha256")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)   # SHA256 produces 64-char hex

    def test_md5_returns_hex_string(self):
        result = hasher.compute_hash(self.filepath, "md5")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 32)   # MD5 produces 32-char hex

    def test_sha512_returns_hex_string(self):
        result = hasher.compute_hash(self.filepath, "sha512")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 128)  # SHA512 produces 128-char hex

    def test_hash_matches_manual_calculation(self):
        """Verify compute_hash matches a direct hashlib calculation."""
        expected = hashlib.sha256(b"SecureMonitor Test File - 12345").hexdigest()
        result   = hasher.compute_hash(self.filepath, "sha256")
        self.assertEqual(result, expected)

    def test_nonexistent_file_returns_none(self):
        result = hasher.compute_hash("C:\\nonexistent\\path\\file.txt")
        self.assertIsNone(result)

    def test_same_file_same_hash(self):
        h1 = hasher.compute_hash(self.filepath)
        h2 = hasher.compute_hash(self.filepath)
        self.assertEqual(h1, h2)

    def test_different_content_different_hash(self):
        # Modify file content
        with open(self.filepath, "wb") as f:
            f.write(b"MODIFIED CONTENT")
        h_modified = hasher.compute_hash(self.filepath)

        tmp2 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb")
        tmp2.write(b"ORIGINAL CONTENT")
        tmp2.close()
        h_original = hasher.compute_hash(tmp2.name)
        os.unlink(tmp2.name)

        self.assertNotEqual(h_modified, h_original)


class TestVerifyIntegrity(unittest.TestCase):
    """Tests for hasher.verify_integrity()"""

    def test_matching_hashes_are_intact(self):
        ok, status = hasher.verify_integrity("abc123", "abc123")
        self.assertTrue(ok)
        self.assertEqual(status, "INTACT")

    def test_different_hashes_are_tampered(self):
        ok, status = hasher.verify_integrity("abc123", "xyz789")
        self.assertFalse(ok)
        self.assertEqual(status, "TAMPERED")

    def test_none_pre_hash_is_unavailable(self):
        ok, status = hasher.verify_integrity(None, "xyz789")
        self.assertFalse(ok)
        self.assertEqual(status, "UNAVAILABLE")

    def test_none_post_hash_is_unavailable(self):
        ok, status = hasher.verify_integrity("abc123", None)
        self.assertFalse(ok)
        self.assertEqual(status, "UNAVAILABLE")

    def test_both_none_is_unavailable(self):
        ok, status = hasher.verify_integrity(None, None)
        self.assertFalse(ok)
        self.assertEqual(status, "UNAVAILABLE")


class TestSnapshot(unittest.TestCase):
    """Tests for snapshot functionality."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb")
        self.tmp.write(b"Snapshot test data")
        self.tmp.close()
        hasher.clear_snapshot()

    def tearDown(self):
        os.unlink(self.tmp.name)
        hasher.clear_snapshot()

    def test_snapshot_stores_hash(self):
        digest = hasher.snapshot_file(self.tmp.name)
        self.assertIsNotNone(digest)
        snapshot = hasher.get_snapshot()
        self.assertIn(self.tmp.name, snapshot)
        self.assertEqual(snapshot[self.tmp.name], digest)

    def test_check_against_snapshot_intact(self):
        hasher.snapshot_file(self.tmp.name)
        ok, status, pre, post = hasher.check_against_snapshot(self.tmp.name)
        self.assertTrue(ok)
        self.assertEqual(status, "INTACT")

    def test_check_against_snapshot_tampered(self):
        hasher.snapshot_file(self.tmp.name)
        # Modify file after snapshot
        with open(self.tmp.name, "wb") as f:
            f.write(b"TAMPERED CONTENT - completely different")
        ok, status, pre, post = hasher.check_against_snapshot(self.tmp.name)
        self.assertFalse(ok)
        self.assertEqual(status, "TAMPERED")

    def test_clear_snapshot(self):
        hasher.snapshot_file(self.tmp.name)
        hasher.clear_snapshot(self.tmp.name)
        self.assertNotIn(self.tmp.name, hasher.get_snapshot())


if __name__ == "__main__":
    unittest.main(verbosity=2)
