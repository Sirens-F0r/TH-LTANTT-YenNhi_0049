import unittest
from securevalidator import (
    validate_email, validate_url, validate_filename,
    sanitize_sql_input, sanitize_html_input
)

class TestValidators(unittest.TestCase):
    def setUp(self):
        print("\nRunning", self._testMethodName)

    def test_validate_email_valid(self):
        self.assertTrue(validate_email("user@example.com"))

    def test_validate_email_invalid(self):
        self.assertFalse(validate_email("ádmín@example.com"))

    def test_validate_url_valid(self):
        self.assertTrue(validate_url("https://example.com"))

    def test_validate_url_invalid(self):
        self.assertFalse(validate_url("http://2130706433/"))

    def test_validate_filename_valid(self):
        self.assertTrue(validate_filename("report.pdf"))

    def test_validate_filename_traversal(self):
        self.assertFalse(validate_filename("passwd.txt%00.jpg"))

    def test_sanitize_sql_input_injection(self):
        input_str = "' || 1=1 /*"
        sanitized = sanitize_sql_input(input_str)
        self.assertNotIn("'", sanitized)
        self.assertNotIn("||", sanitized)
        self.assertNotIn("/*", sanitized)

    def test_sanitize_sql_input_safe_text(self):
        input_str = "hello world"
        sanitized = sanitize_sql_input(input_str)
        self.assertEqual(sanitized, "hello world")

    def test_sanitize_html_input_script(self):
        input_str = 'x onmouseover=alert(1)'
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(sanitized, "x onmouseover=alert(1)")

    def test_sanitize_html_input_safe_text(self):
        input_str = "Hello World"
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(sanitized, "Hello World")
