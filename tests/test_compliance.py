import pytest
from unittest.mock import MagicMock, AsyncMock
from app.dlp_engine import DLPEngine

@pytest.mark.asyncio
async def test_dlp_compliance_parsing(monkeypatch):
    """Verify that DLPEngine handles compliance_alerts from AI"""
    
    # Mock OpenAI
    mock_client = MagicMock()
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message.content = """
    {
        "verdict": "BLOCK",
        "score": 90,
        "category": "Personal",
        "reason": "Found medical records.",
        "compliance_alerts": ["HIPAA", "GDPR"]
    }
    """
    mock_client.chat.completions.create = MagicMock(return_value=mock_completion)
    
    monkeypatch.setattr("openai.OpenAI", lambda api_key: mock_client)
    monkeypatch.setattr("app.config.settings.OPENAI_API_KEY", "sk-fake")
    
    engine = DLPEngine()
    
    # Run Scan
    # We mock _ai_analyze to just return the dict directly if we were unit testing _ai_analyze specifically,
    # but here we want to test the full flow if possible, or at least how scan() handles it.
    # Actually DLPEngine.scan calls _ai_analyze.
    
    # Let's test _ai_analyze directly to confirm parsing
    result = await engine._ai_analyze("sensitive content", [{"type": "ssn", "count": 1}])
    
    assert result['verdict'] == "BLOCK"
    assert "HIPAA" in result['compliance_alerts']
    assert "GDPR" in result['compliance_alerts']
