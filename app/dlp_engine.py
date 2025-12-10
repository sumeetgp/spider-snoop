"""DLP Engine - Core scanning logic"""
import re
import asyncio
from typing import Dict, List, Any
from datetime import datetime
import openai
from app.config import settings

if settings.OPENAI_API_KEY:
    openai.api_key = settings.OPENAI_API_KEY

class DLPEngine:
    """Data Loss Prevention scanning engine"""
    
    def __init__(self):
        self.patterns = {
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'api_key': r'\b(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*[\'\"]?([a-zA-Z0-9_\-]{20,})[\'\"]?\b',
            'aws_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        }
    
    async def scan(self, content: str, use_ai: bool = True) -> Dict[str, Any]:
        """Perform DLP scan on content"""
        start_time = datetime.utcnow()
        
        findings = []
        risk_level = "LOW"
        
        # Pattern-based detection
        for data_type, pattern in self.patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': data_type,
                    'matches': matches,
                    'count': len(matches)
                })
                
                # Set risk level
                if data_type in ['credit_card', 'ssn', 'aws_key']:
                    risk_level = "CRITICAL"
                elif data_type in ['api_key', 'email'] and risk_level not in ['CRITICAL', 'HIGH']:
                    risk_level = "HIGH"
                elif risk_level == "LOW":
                    risk_level = "MEDIUM"
        
        # AI-based detection (optional)
        ai_verdict = None
        if use_ai and settings.OPENAI_API_KEY and findings:
            ai_verdict = await self._ai_analyze(content, findings)
        
        # Calculate duration
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        # Generate verdict
        verdict = self._generate_verdict(findings, ai_verdict)
        
        return {
            'risk_level': risk_level,
            'findings': findings,
            'verdict': verdict,
            'ai_analysis': ai_verdict,
            'scan_duration_ms': duration_ms,
            'scanned_at': datetime.utcnow().isoformat()
        }
    
    async def _ai_analyze(self, content: str, findings: List[Dict]) -> str:
        """Use AI to analyze content for context"""
        try:
            finding_summary = ", ".join([f"{f['count']} {f['type']}(s)" for f in findings])
            
            prompt = f"""
            Analyze the following content for data sensitivity and provide a brief risk assessment.
            
            Detected patterns: {finding_summary}
            
            Content preview: {content[:500]}...
            
            Provide a concise risk assessment (2-3 sentences) focusing on:
            1. Likelihood this is actual sensitive data vs false positive
            2. Potential business impact if leaked
            3. Recommended action
            """
            
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a data security analyst."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=150,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            return f"AI analysis unavailable: {str(e)}"
    
    def _generate_verdict(self, findings: List[Dict], ai_verdict: str = None) -> str:
        """Generate human-readable verdict"""
        if not findings:
            return "SAFE: No sensitive data detected"
        
        finding_types = [f['type'] for f in findings]
        total_matches = sum(f['count'] for f in findings)
        
        if any(t in finding_types for t in ['credit_card', 'ssn', 'aws_key']):
            return f"BLOCK: Critical sensitive data detected - {total_matches} instance(s) of {', '.join(set(finding_types))}"
        elif any(t in finding_types for t in ['api_key']):
            return f"WARN: High-risk data detected - {total_matches} instance(s) of {', '.join(set(finding_types))}"
        else:
            return f"REVIEW: Potentially sensitive data detected - {total_matches} instance(s) of {', '.join(set(finding_types))}"
