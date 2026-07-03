"""Tests for URL and file input handling."""

import tempfile
import unittest
from pathlib import Path

from csp_scanner.inputs import InputError, load_targets, normalise_url


class NormaliseUrlTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(normalise_url("example.com"), "https://example.com")

    def test_preserves_http_scheme(self):
        self.assertEqual(normalise_url("http://example.com"), "http://example.com")

    def test_strips_whitespace(self):
        self.assertEqual(normalise_url("  example.com \n"), "https://example.com")

    def test_rejects_empty(self):
        with self.assertRaises(InputError):
            normalise_url("   ")

    def test_rejects_unsupported_scheme(self):
        for bad in ("ftp://example.com", "file:///etc/passwd", "javascript:alert(1)"):
            with self.assertRaises(InputError):
                normalise_url(bad)

    def test_rejects_missing_host(self):
        with self.assertRaises(InputError):
            normalise_url("https://")


class LoadTargetsTests(unittest.TestCase):
    def test_single_url(self):
        self.assertEqual(load_targets(url="example.com"), ["https://example.com"])

    def test_file_input_skips_comments_blanks_and_dedupes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "urls.txt"
            path.write_text(
                "# comment\nexample.com\n\nhttps://example.com\nb.example.com\n"
            )
            self.assertEqual(
                load_targets(input_file=str(path)),
                ["https://example.com", "https://b.example.com"],
            )

    def test_missing_file(self):
        with self.assertRaises(InputError):
            load_targets(input_file="/nonexistent/urls.txt")

    def test_no_targets(self):
        with self.assertRaises(InputError):
            load_targets()


if __name__ == "__main__":
    unittest.main()
