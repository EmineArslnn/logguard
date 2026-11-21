
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from logguard import (
    find_failed_logins,
    count_failed_attempts_by_ip,
    SUSPICIOUS_THRESHOLD
)


class LogGuardTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "test.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_failed_login_filtering(self):
        self.log_path.write_text(
            "Failed password for root from 192.0.2.10 port 22 ssh2\n"
            "Invalid user guest from 203.0.113.25 port 23\n"
            "Accepted password for admin from 192.0.2.20 port 24 ssh2\n",
            encoding="utf-8"
        )

        result = find_failed_logins(self.log_path)

        self.assertEqual(len(result), 2)
        self.assertTrue(
            all("Accepted password" not in line for line in result)
        )

    def test_ip_attempt_counts(self):
        entries = [
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for admin from 192.0.2.10 port 23 ssh2",
            "Failed password for test from 192.0.2.10 port 24 ssh2",
            "Failed password for user from 198.51.100.7 port 25 ssh2"
        ]

        result = count_failed_attempts_by_ip(entries)

        self.assertEqual(result["192.0.2.10"], 3)
        self.assertEqual(result["198.51.100.7"], 1)

    def test_suspicious_ip_threshold(self):
        entries = [
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for admin from 192.0.2.10 port 23 ssh2",
            "Failed password for test from 192.0.2.10 port 24 ssh2",
            "Failed password for user from 198.51.100.7 port 25 ssh2"
        ]

        result = count_failed_attempts_by_ip(entries)

        self.assertGreaterEqual(
            result["192.0.2.10"],
            SUSPICIOUS_THRESHOLD
        )

        self.assertLess(
            result["198.51.100.7"],
            SUSPICIOUS_THRESHOLD
        )

    def test_invalid_ip_is_ignored(self):
        entries = [
            "Failed password for root from invalid-ip port 22 ssh2"
        ]

        result = count_failed_attempts_by_ip(entries)

        self.assertEqual(result, {})

    def test_empty_entries(self):
        result = count_failed_attempts_by_ip([])

        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
