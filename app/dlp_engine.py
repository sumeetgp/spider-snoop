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
    
    def __init__(self, mcp_session=None):
        from app.core.dlp_patterns import DLPPatternMatcher
        self.matcher = DLPPatternMatcher()
        self.mcp_session = mcp_session
    
    async def scan(self, content: str, use_ai: bool = True) -> Dict[str, Any]:
        """Perform DLP scan on content"""
        start_time = datetime.utcnow()
        
        # Use the shared matcher
        scan_results = self.matcher.scan(content)
        
        findings = []
        risk_level = "LOW"
        
        # Flatten findings from the matcher
        for severity, items in scan_results.items():
            for item in items:
                findings.append({
                    'type': item['type'],
                    'matches': [item['value']], # Matcher masks values, but that's probably okay for findings list
                    'count': 1,
                    'severity': severity
                })
                
                # Update overall risk level
                if severity == "CRITICAL":
                    risk_level = "CRITICAL"
                elif severity == "HIGH" and risk_level != "CRITICAL":
                    risk_level = "HIGH"
                elif severity == "MEDIUM" and risk_level in ["LOW", "INFO"]:
                    risk_level = "MEDIUM"
        
        # AI-based detection (optional)
        ai_verdict = None
        if use_ai and settings.OPENAI_API_KEY and findings:
            ai_verdict = await (self._ai_analyze_ciso_langchain(content) if getattr(settings, 'USE_LANGCHAIN_CISO', False) else self._ai_analyze(content, findings))
        
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
            Analyze the following content for data sensitivity and provide a risk assessment with a score.
            
            Detected patterns: {finding_summary}
            
            Content preview: {content[:500]}...
            
            OUTPUT FORMAT:
            Provide a JSON object with:
            - verdict: "BLOCK" or "ALLOW" or "REVIEW"
            - score: 0-100 (0=Safe, 100=Critical)
            - reason: A concise explanation (2 sentences max)
            - category: "Financial", "Personal", "Secrets", or "None"
            """
            
            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a data security analyst. Return strict JSON."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=150,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            
            message_content = response.choices[0].message.content
            import json
            try:
                if message_content:
                    return json.loads(message_content)
                return {"verdict": "REVIEW", "score": 50, "reason": "No content returned"}
            except:
                return {"verdict": "REVIEW", "score": 50, "reason": message_content}
            
        except Exception as e:
            return f"AI analysis unavailable: {str(e)}"
    
    async def _ai_analyze_ciso_langchain(self, text: str) -> dict:
        """LangChain CISO agent with TWO MCP tools: pattern scanner + risk assessment"""
        try:
            from langchain_openai import ChatOpenAI
            from langgraph.prebuilt import create_react_agent
            from langchain_core.tools import tool
        except Exception:
            return {"verdict": "ALLOW", "category": "None", "reason": "LangChain not available."}

        @tool
        async def pattern_scanner_tool(text: str) -> str:
            """Detailed DLP scanner that finds specific PII patterns with exact locations and masked values.
            Use this when you need to identify WHAT types of sensitive data exist and WHERE they are located.
            Returns comprehensive report grouped by severity (CRITICAL, HIGH, MEDIUM, LOW)."""
            try:
                if getattr(self, 'mcp_session', None) is not None:
                    result = await self.mcp_session.call_tool("scan_patterns", arguments={"text": text})  # type: ignore
                    text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                    return "".join(text_blocks)
            except Exception:
                pass
            # Fallback to regex scan using self.patterns
            import re as _re
            findings = []
            for name, cfg in getattr(self, 'patterns', {}).items():
                rgx = cfg.get('regex')
                if rgx and _re.search(rgx, text, _re.MULTILINE):
                    findings.append(f"Matched {name}")
            return "".join(findings) if findings else "No patterns found"

        @tool
        async def risk_assessment_tool(text: str) -> str:
            """Quick risk level assessment without detailed enumeration.
            Use this when you need a fast overview of the severity level.
            Returns summary: total findings count and risk verdict (CRITICAL/HIGH/MEDIUM/LOW)."""
            try:
                if getattr(self, 'mcp_session', None) is not None:
                    result = await self.mcp_session.call_tool("enhanced_scan", arguments={"text": text, "include_context": False})  # type: ignore
                    text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                    return "".join(text_blocks)
            except Exception:
                pass
            # Fallback - simple analysis
            return "Unable to perform risk assessment. MCP session not available."

        try:
            llm = ChatOpenAI(model='gpt-4o-mini', temperature=0)
        except Exception:
            return {"verdict": "ALLOW", "category": "None", "reason": "OpenAI not configured."}

        # Provide BOTH tools to the agent
        tools = [pattern_scanner_tool, risk_assessment_tool]
        
        system_instruction = """
            You are the Chief Information Security Officer (CISO) AI.
            Your mission is to analyze text for ANY risk to the organization.
            
            AVAILABLE TOOLS:
            1. 'pattern_scanner_tool' - Detailed forensic scan showing exact PII types and locations
            2. 'risk_assessment_tool' - Quick risk level summary
            
            RECOMMENDED WORKFLOW:
            - For most cases: Use pattern_scanner_tool to get detailed findings
            - If you need quick overview first: Use risk_assessment_tool, then pattern_scanner_tool for details
            - The tools call an enhanced DLP engine with 30+ pattern types
            
            RISK CATEGORIES (You must enforce ALL of these):
            
            1. [CRITICAL] SECRETS & INFRASTRUCTURE:
               - API Keys (AWS, OpenAI, GitHub, Stripe), Private Keys, Tokens, JWT
               - Database credentials or connection strings (PostgreSQL, MySQL, MongoDB)
               - Internal IP Addresses (10.x.x.x, 192.168.x.x) or internal domains
               - SSH keys, PGP keys, Bearer tokens

            2. [CRITICAL] FINANCIAL & PII:
               - Credit Cards (Luhn validated), SSN, Bank Accounts, IBAN
               - Passport Numbers, Medical Records
               - Cryptocurrency wallet addresses

            3. [HIGH] INTELLECTUAL PROPERTY (IP):
               - Proprietary Source Code (specific logic, not generic examples)
               - Unreleased Product Codenames (e.g., "Project Skylark")
               - Patent applications or chemical formulas
               - Trade secrets marked "confidential", "proprietary"

            4. [HIGH] FINANCIAL & LEGAL:
               - Insider Trading signals ("buy stock", "merger talks")
               - Non-public earnings data ("Q4 revenue is up 20%")
               - Active Lawsuit strategy or Attorney-Client privileged info

            5. [MEDIUM] HR & SENSITIVE PERSONNEL:
               - Salary discussions ("Bob makes $150k")
               - Layoff rumors or termination lists
               - Private medical info (HIPAA) or employee home addresses
               - Driver's licenses, phone numbers, email addresses

            DECISION LOGIC:
            - If pattern_scanner_tool finds CRITICAL findings -> BLOCK immediately
            - If pattern_scanner_tool finds HIGH findings -> BLOCK with detailed reason
            - If pattern_scanner_tool finds MEDIUM findings -> BLOCK unless clearly public/necessary
            - If text falls into CRITICAL/HIGH categories not caught by patterns -> BLOCK
            - If text is generic conversation with no findings -> ALLOW

            OUTPUT FORMAT (STRICT):
            Your Final Answer MUST be exactly in this format:
            "VERDICT: [BLOCK/ALLOW] | SCORE: [0-100] | CATEGORY: [Category Name] | REASON: [Brief explanation with specific findings]"
            
            Scoring Guide:
            0-10: Safe / Public info
            11-40: Low Risk / Internal but not sensitive
            41-70: Medium Risk / Sensitive Personnel or Financial
            71-90: High Risk / IP / Secrets
            91-100: Critical / Immediate Data Exfiltration
            """

        agent = create_react_agent(llm, tools)

        try:
            result = await agent.ainvoke({"input": text, "instructions": system_instruction})
            questions = result["messages"][-1].content
            output = questions if isinstance(questions, str) else str(questions)
        except Exception as e:
            return {"verdict": "ALLOW", "score": 0, "category": "None", "reason": f"Agent error: {e}"}

        verdict, score, category, reason = "ALLOW", 0, "None", output
        try:
            if "VERDICT:" in output:
                parts = output.split("VERDICT:")[-1].strip()
                segments = [s.strip() for s in parts.split("|")]
                
                if segments:
                    verdict = segments[0]
                
                for seg in segments[1:]:
                    up = seg.upper()
                    if up.startswith("CATEGORY:"):
                        category = seg.split(":",1)[1].strip()
                    elif up.startswith("SCORE:"):
                        try:
                            score = int(seg.split(":",1)[1].strip())
                        except ValueError:
                            score = 75 # Default high score if parsing fails but verdict found
                    elif up.startswith("REASON:"):
                        reason = seg.split(":",1)[1].strip()
        except Exception:
            pass

        return {"verdict": verdict, "score": score, "category": category, "reason": reason}

    def _generate_verdict(self, findings: List[Dict], ai_verdict: Any = None) -> str:
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
