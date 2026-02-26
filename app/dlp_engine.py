"""DLP Engine - Core scanning logic"""
import logging
import re
import asyncio
from typing import Dict, List, Any
from datetime import datetime
import openai
from app.config import settings

logger = logging.getLogger(__name__)

if settings.OPENAI_API_KEY:
    openai.api_key = settings.OPENAI_API_KEY

class MockEngine:
    enabled = True
    def scan(self, text, **kwargs):
        findings = []
        text_upper = text.upper()
        if "EICAR" in text_upper:
             findings.append({'type': 'TEST_VIRUS', 'value': 'EICAR String', 'severity': 'CRITICAL', 'count': 1})
        if "4532 0152" in text or "4111 1111" in text:
             findings.append({'type': 'credit_card', 'value': 'Credit Card', 'severity': 'HIGH', 'count': 1})
        if "REQUESTS==2.0.0" in text_upper:
             findings.append({'type': 'vulnerable_dependency', 'value': 'requests==2.0.0', 'severity': 'HIGH', 'count': 1})
             
        # Mock result structure
        risk = "LOW"
        if findings: 
            severities = [f['severity'] for f in findings]
            if "CRITICAL" in severities: risk = "CRITICAL"
            elif "HIGH" in severities: risk = "HIGH"
            
        return findings

    def redact(self, text):
        return text.replace("4532 0152 7700 8192", "[REDACTED_CREDIT_CARD]")\
                   .replace("4111 1111 1111 1111", "[REDACTED_CREDIT_CARD]")

class DLPEngine:
    """Data Loss Prevention scanning engine"""
    
    def __init__(self, mcp_session=None):
        from app.core.dlp_patterns import DLPPatternMatcher
        self.matcher = DLPPatternMatcher()
        
        # Initialize Presidio (with fallback)
        try:
            from app.core.presidio_engine import PresidioEngine
            self.presidio = PresidioEngine()
        except Exception as e:
            logger.warning(f"Using MockEngine due to import error: {e}")
            self.presidio = MockEngine()
        
        self.mcp_session = mcp_session
        # Simple LRU Cache for AI responses (Max 100 items)
        from collections import OrderedDict
        self._cache = OrderedDict()
        self._max_cache_size = 100

    async def scan(self, content: str, use_ai: bool = True, file_path: str = None, force_ai: bool = False, skip_regex: bool = False, secrets_only: bool = False, skip_presidio: bool = False, raw_prompt: bool = False) -> Dict[str, Any]:
        """Perform DLP scan on content"""
        start_time = datetime.utcnow()
        
        # 1. Regex Matcher
        scan_results = {}
        if not skip_regex:
            # Pass secrets_only flag if enabled
            scan_results = self.matcher.scan(content, secrets_only=secrets_only)
        
        findings = []
        risk_level = "LOW"
        
        # Flatten findings from the matcher
        for severity, items in scan_results.items():
            for item in items:
                findings.append({
                    'type': item['type'],
                    'matches': [item['value']],
                    'count': 1,
                    'severity': severity
                })
                
                # Update overall risk level for Regex
                if severity == "CRITICAL":
                    risk_level = "CRITICAL"
                elif severity == "HIGH" and risk_level != "CRITICAL":
                    risk_level = "HIGH"
                elif severity == "MEDIUM" and risk_level in ["LOW", "INFO", "low", "info"]: # keep lowercase check for safety
                    risk_level = "MEDIUM"

        # 2. Presidio NER (Contextual)
        # Truncate to PRESIDIO_MAX_CONTENT_CHARS to cap transformer inference time.
        # Run in a thread so the CPU-bound NER doesn't block the async event loop.
        if self.presidio.enabled and not skip_presidio:
            presidio_findings = await asyncio.to_thread(
                self.presidio.scan, content[:settings.PRESIDIO_MAX_CONTENT_CHARS]
            )
            for pf in presidio_findings:
                # Add to findings list
                findings.append({
                    'type': pf['type'],
                    'matches': [pf['value']],
                    'count': 1,
                    'severity': pf['severity'],
                    'metadata': {'score': pf['score']} 
                })
                
                # Update risk level based on Presidio
                if pf['severity'] == "CRITICAL":
                    risk_level = "CRITICAL"
                elif pf['severity'] == "HIGH" and risk_level != "CRITICAL":
                    risk_level = "HIGH"
                elif pf['severity'] == "MEDIUM" and risk_level in ["LOW", "INFO", "low", "info"]:
                     risk_level = "MEDIUM"

        # AI-based detection (optional)
        ai_verdict = None
        logger.debug(f"Checking AI Trigger. use_ai={use_ai}, has_key={bool(settings.OPENAI_API_KEY)}, findings={len(findings)}, force_ai={force_ai}")
        
        if use_ai and (settings.OPENAI_API_KEY or settings.USE_LOCAL_ML) and (findings or force_ai or raw_prompt):
            logger.debug("Triggering AI Analysis...")
            if getattr(settings, 'USE_LANGCHAIN_CISO', False) and not raw_prompt:
                ai_verdict = await self._ai_analyze_ciso_langchain(content, file_path)
            else:
                ai_verdict = await self._ai_analyze(content, findings, raw_prompt=raw_prompt)
            logger.debug(f"AI Analysis Complete. Verdict: {ai_verdict.get('verdict') if ai_verdict else 'None'}")
        
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

    def redact(self, content: str) -> str:
        """
        Redact sensitive data using best available methods (Presidio + Regex)
        """
        # 1. Presidio (Contextual PII)
        if self.presidio.enabled:
            content = self.presidio.redact(content)
            
        # 2. Regex Pattern Matcher (Secrets / Technical PII)
        # We run this second to catch things Presidio missed (like API keys)
        # The matcher.redact method handles non-overlapping matches
        content = self.matcher.redact(content)
        
        return content
    
    async def scan_macros(self, file_path: str) -> str:
        """
        Directly invoke MCP tool for macro scanning.
        Returns a string description of findings or None if safe/error.
        """
        if self.mcp_session is None:
            pass

        try:
            # We need to access the MCP session. 
            if self.mcp_session:
                 result = await self.mcp_session.call_tool("scan_office_macros", arguments={"file_path": file_path})
                 text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                 return "".join(text_blocks)
            else:
                 return "MCP Session unavailable for macro scan."
        except Exception as e:
            return f"Macro scan failed: {str(e)}"
        
        return None

    async def _ai_analyze(self, content: str, findings: List[Dict], raw_prompt: bool = False) -> str:
        """Use AI to analyze content for context (Cached)"""
        try:
            # Generate Cache Key (Content hash + finding types)
            import hashlib
            import json
            
            # Create a deterministic key
            finding_sig = sorted([f['type'] for f in findings])
            content_hash = hashlib.md5(content.encode()).hexdigest()
            cache_key = f"{content_hash}_{str(finding_sig)}_{raw_prompt}"
            
            # Check Cache
            if cache_key in self._cache:
                # Move to end (LRU)
                self._cache.move_to_end(cache_key)
                logger.debug(f"Cache hit: reusing AI analysis for {cache_key[:8]}")
                return self._cache[cache_key]

            from collections import defaultdict
            counts = defaultdict(int)
            for f in findings:
                counts[f['type']] += f.get('count', 1)
            finding_summary = ", ".join([f"{c} {t}(s)" for t, c in counts.items()])
            
            prompt = ""
            if raw_prompt:
                # Direct Prompt Injection (e.g. for Code Security Agent)
                prompt = content
            else:
                prompt = f"""
                Analyze the following content for data sensitivity and provide a risk assessment with a score.
                
                Detected patterns: {finding_summary}
                
                Content preview: {content[:500]}...
                
                OUTPUT FORMAT:
                Provide a JSON object with:
                - verdict: "BLOCK" or "ALLOW" or "REVIEW"
                - score: 0-100 (0=Safe, 100=Critical)
                - reason: A concise explanation (2 sentences max)
                - category: "Financial", "Personal", "Secrets", "Supply Chain", or "None"
                - compliance_alerts: List of strings (e.g. ["HIPAA", "PCI-DSS", "SOC2"]) if applicable, else []
                - remediation: List of objects [{{"package": "name", "current_version": "v1", "fixed_version": "v2", "cve": "CVE-..."}}] for any vulnerabilities found.
                
                CHECK FOR:
                - HIPAA: Medical data, PHI
                - PCI-DSS: Credit cards, detailed financial info
                - SOC2: Secrets, keys, infrastructure data
                - GDPR: EU Citizen PII
                - Supply Chain: Vulnerable dependencies (extract from report)
                """
            
            # Fallback to Local ML or OpenAI
            if settings.USE_LOCAL_ML or not settings.OPENAI_API_KEY:
                logger.debug("Using LOCAL ML ENGINE (Zero-Shot) for Analysis.")
                from app.core.ml_engine import get_ml_engine
                engine = get_ml_engine()
                
                # Zero-shot classification via NLI
                labels = ["data_exfiltration", "insider_risk", "accidental_sharing", "benign_business"]
                
                ml_res = engine.zero_shot_classify(content[:512], labels)
                best_label = ml_res.get("label", "benign_business")
                confidence = ml_res.get("confidence", 0.0)
                
                is_sensitive = best_label in ["data_exfiltration", "insider_risk", "accidental_sharing"]
                
                verdict = "REVIEW"
                if best_label in ["data_exfiltration", "insider_risk"] and confidence > 0.6:
                    verdict = "BLOCK"
                elif best_label == "benign_business":
                    verdict = "ALLOW"
                    
                score = int(confidence * 100) if is_sensitive else 0
                
                display_label = best_label.replace("_", " ").title()
                
                return {
                    "verdict": verdict,
                    "score": score,
                    "reason": f"Local ML (Zero-Shot) classified as '{display_label}' (Confidence: {confidence:.2f})",
                    "category": "Confidential" if is_sensitive else "None",
                    "compliance_alerts": [],
                    "remediation": [],
                    # Structured Data for UI
                    "ml_model": "DeBERTa-v3 (Zero-Shot NLI)",
                    "confidence": confidence,
                    "inference_label": best_label,
                    "all_scores": ml_res.get("all_scores", {}),
                    "inference_time_ms": ml_res.get("inference_time_ms", 0)
                }

            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a data security analyst. Return strict JSON."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            
            message_content = response.choices[0].message.content
            
            result = None
            try:
                if message_content:
                    result = json.loads(message_content)
                else:
                    result = {"verdict": "REVIEW", "score": 50, "reason": "No content returned"}
            except:
                # If JSON parsing fails completely, do NOT return raw message content as reason
                result = {"verdict": "REVIEW", "score": 50, "reason": "AI Analysis returned invalid format."}
            
            # Update Cache
            self._cache[cache_key] = result
            if len(self._cache) > self._max_cache_size:
                self._cache.popitem(last=False) # Remove oldest
                
            return result
            
        except Exception as e:
            return {"verdict": "REVIEW", "score": 50, "reason": f"AI analysis unavailable: {str(e)}", "category": "None", "compliance_alerts": [], "remediation": []}    
    async def _ai_analyze_ciso_langchain(self, text: str, file_path: str = None) -> dict:
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

        @tool
        async def policy_rag_tool(term: str) -> str:
            """RAG KNOWLEDGE LOOKUP: Look up corporate security policies for specific terms, project names, or people.
            USE THIS ALWAYS if you see proper nouns, codenames, or unfamiliar terms (e.g., 'Skylark', 'Bob', 'Titan').
            Returns the official security classification and handling rules."""
            try:
                if getattr(self, 'mcp_session', None) is not None:
                    result = await self.mcp_session.call_tool("consult_policy_db", arguments={"query": term})  # type: ignore
                    text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                    return "".join(text_blocks)
            except Exception:
                return "RAG/Knowledge Base Unavailable."

        @tool
        async def decode_obfuscation_skill(text: str) -> str:
            """SKILL: Decodes obfuscated text (Base64/Hex).
            Use this ANY TIME you see random-looking strings like 'eyJ...' or '4A6B...'."""
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("decode_obfuscation", arguments={"text": text}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."

        @tool
        async def analyze_code_skill(code: str) -> str:
            """SKILL: Analyzes source code.
            Use this if input LOOKS like code.
            Returns: PROPRIETARY (Block) or GENERIC (Allow)."""
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("analyze_code_snippet", arguments={"code": code}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."

        @tool
        async def scan_metadata_skill() -> str:
            """SKILL: Forensic metadata check (Author, GPS, Edit History) for the file.
            Call this if you suspect hidden document history."""
            if not file_path: return "SKILL_ERROR: No file path context available (Text-only scan)."
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("scan_metadata", arguments={"file_path": file_path}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."

        @tool
        async def scan_macros_skill() -> str:
            """SKILL: VBA Macro analysis for Office docs.
            Call this for any .DOCM, .DOC, .XLSM files to check for malware/auto-exec."""
            if not file_path: return "SKILL_ERROR: No file path context available."
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("scan_office_macros", arguments={"file_path": file_path}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."

        @tool
        async def inspect_zip_skill() -> str:
            """SKILL: Deep Zip inspection.
            Call this for any .ZIP file to check for Zip Bombs or hidden executables."""
            if not file_path: return "SKILL_ERROR: No file path context available."
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("inspect_zip_structure", arguments={"file_path": file_path}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."
            
        @tool
        async def scan_ocr_skill() -> str:
            """SKILL: OCR Text Extraction.
            Call this for Images (PNG/JPG) to get readable text if the user didn't provide it."""
            if not file_path: return "SKILL_ERROR: No file path context available."
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("scan_image_text", arguments={"image_path": file_path}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."

        @tool
        async def scan_dependencies_skill(manifest_content: str, ecosystem: str = "PyPI") -> str:
            """SKILL: Security Audit for Dependencies (OSV.dev).
            Call this if you see a 'requirements.txt' (ecosystem='PyPI') or 'package.json' (ecosystem='npm').
            Returns list of CVEs and Fixed Versions."""
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("scan_dependencies", arguments={"manifest_content": manifest_content, "ecosystem": ecosystem}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."

        @tool
        async def scan_secrets_skill() -> str:
            """SKILL: TruffleHog-style Secret Source Code Scan.
            Call this if the file is a ZIP archive of source code.
            Recursively finds API keys and Secrets."""
            if not file_path: return "SKILL_ERROR: No file path context."
            try:
                if getattr(self, 'mcp_session', None) is not None:
                     result = await self.mcp_session.call_tool("scan_secrets_codebase", arguments={"file_path": file_path}) # type: ignore
                     text_blocks = [c.text for c in result.content if getattr(c, 'type', None) == "text"]
                     return "".join(text_blocks)
            except Exception:
                pass
            return "Skill unavailable."

        # Provide ALL tools to the agent
        tools = [pattern_scanner_tool, risk_assessment_tool, policy_rag_tool, decode_obfuscation_skill, analyze_code_skill, scan_metadata_skill, scan_macros_skill, inspect_zip_skill, scan_ocr_skill, scan_dependencies_skill, scan_secrets_skill]
        
        system_instruction = """
            You are the Chief Information Security Officer (CISO) AI.
            Your mission is to analyze text for ANY risk to the organization.
            
            AVAILABLE TOOLS:
            1. 'pattern_scanner_tool' - Detailed forensic scan (PII, Credentials)
            2. 'risk_assessment_tool' - Quick risk summary
            3. 'policy_rag_tool' - RAG Knowledge Base for Project Names/People
            4. 'decode_obfuscation_skill' - De-obfuscate Base64/Hex hidden payloads
            5. 'analyze_code_skill' - Distinguish Proprietary vs Generic Code
            6. 'scan_metadata_skill' - Extract hidden Author/GPS/Edit History
            7. 'scan_macros_skill' - Detect malicious Macros in Office Docs
            8. 'inspect_zip_skill' - Detect Zip Bombs & Nested Executables
            9. 'scan_ocr_skill' - Extract text from Images
            10. 'scan_dependencies_skill' - Audit package.json/requirements.txt for Vulnerabilities (OSV)
            11. 'scan_secrets_skill' - Recursive TruffleHog scan for ZIP Codebases
            
            RECOMMENDED WORKFLOW:
            1. CHECK FILE FORENSICS (If file context exists):
               - If ZIP -> 'inspect_zip_skill' AND 'scan_secrets_skill' (if code)
               - If OFFICE DOC -> 'scan_macros_skill'
               - If IMAGE -> 'scan_ocr_skill'
               - If MANIFEST (package.json/requirements.txt) -> 'scan_dependencies_skill'
               - ALWAYS check 'scan_metadata_skill' for hidden info.
               - ALWAYS check 'scan_metadata_skill' for hidden info (Author, GPS).
            2. CHECK OBFUSCATION: 'decode_obfuscation_skill'.
            3. ANALYZE CONTENT:
               - If text is CODE: Call 'analyze_code_skill'.
               - If text is PLAINTEXT: Call 'pattern_scanner_tool'.
            4. CONTEXT CHECK: Identify proper nouns (Projects, People) and check 'policy_rag_tool'.
            5. VERDICT: Combine findings.
            
            RISK CATEGORIES:
            
            1. [CRITICAL] SECRETS & INFRASTRUCTURE:
               - API Keys (AWS, OpenAI, GitHub, Stripe), Private Keys, Tokens, JWT
               - Database credentials or connection strings (PostgreSQL, MySQL, MongoDB)
               - Internal IP Addresses (10.x.x.x, 192.168.x.x)
               - SSH keys, PGP keys, Bearer tokens

               - Decoded Payloads containing secrets (Verified by 'decode_obfuscation_skill')
               - Malicious Macros (Verified by 'scan_macros_skill')
               - Zip Bombs (Verified by 'inspect_zip_skill')
               
            2. [CRITICAL] FINANCIAL & PII:
               - Credit Cards (Luhn validated), SSN, Bank Accounts, IBAN
               - Passport Numbers, Medical Records
               - Cryptocurrency wallet addresses
               
            3. [HIGH] INTELLECTUAL PROPERTY (IP):
               - Proprietary Source Code (Verified by 'analyze_code_skill' to be PROPRIETARY)
               - Unreleased Product Codenames (Verified by 'policy_rag_tool')
               - Trade secrets marked "confidential", "proprietary"
               
            4. [HIGH] FINANCIAL & LEGAL:
               - Insider Trading signals ("buy stock", "merger talks")
               - Non-public earnings data ("Q4 revenue is up 20%")
               - Active Lawsuit strategy or Attorney-Client privileged info
               
            5. [MEDIUM] SENSITIVE BUSINESS DATA:
               - Salary discussions ("Bob makes $150k")
               - Layoff rumors or termination lists
               - Private medical info (HIPAA) or employee home addresses
               - Driver's licenses, phone numbers, email addresses

            COMPLIANCE MAPPING:
            - HIPAA: Medical/Health records, patient data → Tag as [HIPAA]
            - PCI-DSS: Credit card numbers, payment data → Tag as [PCI-DSS]
            - SOC2: Cloud credentials, AWS keys, infrastructure secrets → Tag as [SOC2]
            - GDPR: EU personal data, European PII → Tag as [GDPR]
            - CCPA: California resident data, consumer privacy → Tag as [CCPA]
            - PIPL: China personal information → Tag as [PIPL]
            - GLBA: Banking/insurance customer data → Tag as [GLBA]
            - SOX: Corporate financial records, audit data → Tag as [SOX]
            - FINRA: Securities trading data, broker records → Tag as [FINRA]
            - ITAR: Defense/export controlled technical data → Tag as [ITAR]
            - FedRAMP: US government cloud data → Tag as [FedRAMP]
            - FERPA: Student education records → Tag as [FERPA]
            - ACP: Attorney-client privileged communications → Tag as [ACP]
            - HR-SENSITIVE: Salary data, DEI information, performance reviews → Tag as [HR-SENSITIVE]
            
            OUTPUT FORMAT (STRICT):
            "VERDICT: [BLOCK/ALLOW] | SCORE: [0-100] | CATEGORY: [Category Name] | REASON: [Brief explanation with specific findings and COMPLIANCE TAGS]"
            """

        agent = create_react_agent(llm, tools)

        try:
            # Contextualize input with filename if available
            agent_input = text
            if file_path:
                import os
                filename = os.path.basename(file_path)
                agent_input = f"[FILE CONTEXT: {filename}]\n\n{text}"
            
            if raw_prompt:
                # Direct Chain for Code Security (Bypass ReAct Agent overhead)
                response = await llm.ainvoke(agent_input)
                output = response.content
            else:
                # Standard Agent Loop
                result = await agent.ainvoke({"input": agent_input, "instructions": system_instruction})
                questions = result["messages"][-1].content
                output = questions if isinstance(questions, str) else str(questions)
        except Exception as e:
            return {"verdict": "ALLOW", "score": 0, "category": "None", "reason": f"Agent error: {e}"}

        verdict, score, category, reason = "ALLOW", 0, "None", output
        compliance_alerts = []
        remediation = []

        # 1. Try to parse strict JSON (Code Security / Dependencies often returns this)
        try:
            import json
            # Sanitize minimal markdown if present (e.g. ```json ... ```)
            clean_output = output.strip()
            
            # Regex to find the main JSON object { ... }
            import re
            json_match = re.search(r'\{.*\}', clean_output, re.DOTALL)
            if json_match:
                clean_output = json_match.group(0)
            elif "```" in clean_output:
                # Fallback to fence splitting if regex failed (unlikely for valid JSON)
                clean_output = clean_output.split("```")[-2] if "```json" in clean_output else clean_output.split("```")[1]
            
            if clean_output.strip().lower().startswith("json"):
                 clean_output = clean_output.strip()[4:]
            
            try:
                data = json.loads(clean_output.strip())
            except json.JSONDecodeError:
                # Try correcting single quotes to double quotes (common LLM error)
                try:
                    import ast
                    data = ast.literal_eval(clean_output.strip())
                except:
                    raise ValueError("Failed to parse JSON")
            
                if isinstance(data, dict):
                    verdict = data.get('verdict', verdict)
                    score = data.get('score', score)
                    category = data.get('category', category)
                    reason = data.get('reason', reason)
                    
                    # Handle flat or nested remediation (Code Security uses nested)
                    remediation = data.get('remediation', [])
                    if not remediation and isinstance(data.get('ai_analysis'), dict):
                        remediation = data['ai_analysis'].get('remediation', [])
                        
                    compliance_alerts = data.get('compliance_alerts', [])
                    output = reason # For fallback if needed
        except Exception:
            # Not JSON, proceed to text parsing
            pass

        try:
            # 2. Text Parsing (Fallback or if JSON failed)
            # Only run if we didn't get a clean JSON reason yet, OR if output is still the raw string
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
                        
            # Extract Compliance Tags from Reason
            # Pattern: [TAG] e.g. [GDPR], [PCI-DSS]
            import re
            tag_matches = re.findall(r'\[([A-Z0-9\-_]+)\]', reason)
            known_tags = ['HIPAA', 'PCI', 'PCI-DSS', 'GDPR', 'SOC2', 'ISO27001', 'CCPA', 'PIPL', 'GLBA', 'SOX', 'FINRA', 'ITAR', 'FedRAMP', 'FERPA', 'ACP', 'HR-SENSITIVE']
            compliance_alerts = [tag for tag in tag_matches if tag in known_tags or any(k in tag for k in known_tags)]
            
        except Exception:
            pass

        # Final Sanitization of Verdict
        if isinstance(verdict, str):
            clean_verdict = verdict.strip()
            
            # 1. Strip common prefixes
            if clean_verdict.upper().startswith("VERDICT:"):
                clean_verdict = clean_verdict[8:].strip()
            if clean_verdict.upper().startswith("VERDICT_"):
                clean_verdict = clean_verdict[8:].strip()
            
            # 2. Aggressive Check for JSON or Complexity
            if "{" in clean_verdict or "}" in clean_verdict or len(clean_verdict) > 40:
                # Fallback based on content keywords
                if "BLOCK" in clean_verdict.upper(): verdict = "BLOCK"
                elif "MALWARE" in clean_verdict.upper(): verdict = "MALWARE DETECTED"
                elif "SAFE" in clean_verdict.upper(): verdict = "SAFE"
                else: verdict = "REVIEW" # Default
            else:
                verdict = clean_verdict

            # 3. Canonicalize
            if "SAFE" in verdict.upper(): verdict = "SAFE"
            elif "BLOCK" in verdict.upper(): verdict = "BLOCK"
            elif "REVIEW" in verdict.upper(): verdict = "REVIEW"
            elif "MALWARE" in verdict.upper(): verdict = "MALWARE DETECTED"
        
        return {"verdict": verdict, "score": score, "category": category, "reason": reason, "compliance_alerts": compliance_alerts, "remediation": remediation}

    def _generate_verdict(self, findings: List[Dict], ai_verdict: Any = None) -> str:
        """Generate human-readable verdict"""
        
        # 1. Calculate Findings Summary first (User prefers this text)
        findings_text = ""
        finding_types = []
        if findings:
            finding_types = [f['type'] for f in findings]
            # De-duplicate types for brevity
            unique_types = sorted(list(set(finding_types)))
            # Limit to 10 types in summary to prevent excessive UI bloat, but handle 'fully'
            # Most scans have < 10 unique types.
            types_str = ", ".join(unique_types[:12])
            if len(unique_types) > 12: types_str += f" +{len(unique_types)-12} more"
            
            total_matches = sum(f.get('count', 1) for f in findings)
            findings_text = f"{total_matches} instance(s) of {types_str}"

        # 2. Determine Verdict Status (BLOCK/REVIEW/ALLOW)
        status = "REVIEW" # Default to caution
        
        # Check AI Verdict
        if ai_verdict and isinstance(ai_verdict, dict):
             v = ai_verdict.get('verdict')
             if v == "BLOCK": status = "BLOCK"
             elif v == "ALLOW": status = "ALLOW"
             elif v == "SAFE": status = "ALLOW"

        # Check Regex/Hyperscan Severity (Override AI "ALLOW" only if CRITICAL findings exist)
        if any(t in finding_types for t in ['credit_card', 'ssn', 'aws_key', 'passport', 'private_key', 'us_bank_number', 'us_driver_license']):
            status = "BLOCK"
        
        # 3. Construct Final String
        if findings:
             if status == "BLOCK":
                 prefix = "Critical sensitive data detected"
             elif status == "REVIEW":
                 prefix = "Potentially sensitive data detected"
             else: # ALLOW
                 prefix = "Low-risk data detected (Allowed)"
             
             return f"{status}: {prefix} - {findings_text}"
        
        # 4. Fallback to AI Reason
        if ai_verdict and isinstance(ai_verdict, dict):
            return f"{status}: {ai_verdict.get('reason', 'AI Assessment')}"

        if not findings:
            return "ALLOW: No sensitive data detected"
            
        return f"{status}: Check findings"
