import sys
import os
import unittest

# Add project root to path
sys.path.append(os.getcwd())

from app.core.dlp_patterns import DLPPatternMatcher

class TestDLPEnhanced(unittest.TestCase):
    def setUp(self):
        self.matcher = DLPPatternMatcher()

    def test_slack_api_token(self):
        text = "Here is my bot token: xoxb-123456789012-1234567890123-abcdef123456"
        results = self.matcher.scan(text)
        slack_findings = [f for f in results["CRITICAL"] if f["type"] == "slack_api_token"]
        self.assertTrue(slack_findings, "Should detect Slack API Token")
        self.assertTrue("xoxb-" in str(slack_findings[0]["value"]), "Should mask Slack Token preserving prefix")

    def test_slack_webhook(self):
        text = "Incoming webhook: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        results = self.matcher.scan(text)
        webhook_findings = [f for f in results["CRITICAL"] if f["type"] == "slack_webhook"]
        self.assertTrue(webhook_findings, "Should detect Slack Webhook")

    def test_google_api_key(self):
        # AIza + 35 random chars (High Entropy)
        text = "gcp_key = AIzaSyD-7b9X2kL4nQ8jR1mZ3vP6w0tY5uO9aXX"
        results = self.matcher.scan(text)
        google_findings = [f for f in results["CRITICAL"] if f["type"] == "google_api_key"]
        self.assertTrue(google_findings, "Should detect Google API Key")

    def test_aws_session_token(self):
        # FQoGZXRfYXJj + random base64 chars (High Entropy)
        token = "FQoGZXRfYXJj" + "7b9X2kL4nQ8jR1mZ3vP6w0tY5uO9a7b9X2kL4nQ8jR1mZ3vP6w0tY5uO9a"
        text = f"AWS_SESSION_TOKEN={token}"
        results = self.matcher.scan(text)
        aws_findings = [f for f in results["HIGH"] if f["type"] == "aws_session_token"]
        self.assertTrue(aws_findings, "Should detect AWS Session Token")

if __name__ == "__main__":
    unittest.main()
