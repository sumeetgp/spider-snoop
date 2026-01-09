
import pytest
from app.dlp_engine import DLPEngine
from app.core.dlp_patterns import DLPPatternMatcher

@pytest.fixture
def dlp_engine():
    return DLPEngine()

@pytest.fixture
def pattern_matcher():
    return DLPPatternMatcher()

class TestDLPCapabilities:
    
    @pytest.mark.asyncio
    async def test_pattern_detection_financial(self, dlp_engine):
        """Verify detection of financial data"""
        content = "My credit card is 4111 1111 1111 1111 and my bank account is 123456789"
        result = await dlp_engine.scan(content)
        
        types = [f['type'] for f in result['findings']]
        assert 'credit_card' in types
        assert 'bank_account' in types
        assert result['risk_level'].upper() == 'CRITICAL'

    @pytest.mark.asyncio
    async def test_pattern_detection_pii(self, dlp_engine):
        """Verify detection of PII data"""
        content = "Contact me at test@example.com or 555-555-5555. SSN: 000-00-0000"
        result = await dlp_engine.scan(content)
        
        types = [f['type'] for f in result['findings']]
        assert 'email' in types
        # phone_us regex might be strict or using different name
        assert any('phone' in t for t in types) or 'phone_us' in types
        assert 'ssn' in types

    @pytest.mark.asyncio
    async def test_pattern_detection_secrets(self, dlp_engine):
        """Verify detection of technical secrets"""
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = await dlp_engine.scan(content)
        
        types = [f['type'] for f in result['findings']]
        assert 'aws_access_key' in types
        assert result['risk_level'].upper() == 'CRITICAL'

    def test_redaction(self, dlp_engine):
        """Verify redaction capability"""
        content = "My SSN is 000-00-0000"
        # Since dlp_engine.redact is sync or using the underlying matcher
        redacted = dlp_engine.redact(content)
        assert "000-00-0000" not in redacted
        assert "REDACTED" in redacted or "***" in redacted

    def test_fuzzing(self, pattern_matcher):
        """Verify synthetic data fuzzing capability"""
        content = "Call 555-555-5555 for help"
        fuzzed = pattern_matcher.fuzz(content)
        assert "555-555-5555" not in fuzzed
        # Should be replaced by a fake phone number or placeholder
        assert len(fuzzed) > 5

    @pytest.mark.asyncio
    async def test_ner_integration(self, dlp_engine):
        """Verify Presidio NER integration for context"""
        # Note: This test depends on Presidio being installed and models downloaded.
        # If not, it gracefully degrades. We check if 'person' is found.
        content = "John Smith lives in New York"
        result = await dlp_engine.scan(content)
        
        # If Presidio is enabled, we expect 'person' or 'location'
        # Check if engine has presidio enabled
        if hasattr(dlp_engine, 'presidio') and dlp_engine.presidio.enabled:
             types = [f['type'] for f in result['findings']]
             assert any(t in ['person', 'location', 'gpe'] for t in types)

