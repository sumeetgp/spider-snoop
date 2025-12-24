import unittest
from app.core.dlp_patterns import DLPPatternMatcher

class TestDLPRedaction(unittest.TestCase):
    def setUp(self):
        self.matcher = DLPPatternMatcher()
        
    def test_redact_basic(self):
        text = "My email is test@example.com and my secret is AKIAIOSFODNN7EXAMPLE."
        redacted = self.matcher.redact(text)
        self.assertIn("[REDACTED: Email Address]", redacted)
        self.assertIn("[REDACTED: AWS Access Key ID]", redacted)
        self.assertNotIn("test@example.com", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        
    def test_redact_multiple(self):
        text = "Contact: test@example.com, Phone: 555-555-0199."
        redacted = self.matcher.redact(text)
        self.assertIn("[REDACTED: Email Address]", redacted)
        self.assertIn("[REDACTED: US Phone Number]", redacted)
        self.assertNotIn("555-555-0199", redacted)
        
    def test_redact_overlap(self):
        # Construct a case where multiple patterns might match same Text
        # E.g. a generic API key might match inside something else if loose
        # Or Keyword "password" inside a sentence
        text = "The password is password123!"
        redacted = self.matcher.redact(text)
        # "password" keyword should be redacted
        self.assertIn("[REDACTED: Sensitive Keyword]", redacted)
        self.assertNotIn("password is password123", redacted)

if __name__ == "__main__":
    unittest.main()
