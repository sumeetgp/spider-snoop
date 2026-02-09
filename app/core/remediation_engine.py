
"""
Remediation Engine
Provides fix suggestions for detected security issues.
"""
from typing import Dict, Any

class RemediationEngine:
    def __init__(self):
        self.kb = {
            "aws_access_key": "Rotate credential immediately. Use AWS Secrets Manager or Environment Variables.",
            "hardcoded_password": "Store passwords in environment variables (os.getenv) or a vault.",
            "vulnerable_logic": "Avoid using dangerous functions like eval() or exec(). Use safer alternatives.",
            "sql_injection": "Use parameterized queries (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))",
            "cross_site_scripting": "Sanitize user input before rendering. Use frameworks that auto-escape (React/Jinja2).",
            "command_injection": "Avoid shell=True in subprocess. Use a list of arguments instead.",
            "insecure_deserialization": "Do not verify untrusted data with pickle.load(). Use json.loads() instead.",
            "default": "Review code security best practices."
        }

    def get_remediation(self, issue_type: str) -> str:
        """
        Returns a remediation string for the given issue type.
        """
        # Normalize keys 
        key = issue_type.lower()
        if "password" in key: return self.kb["hardcoded_password"]
        if "sql" in key: return self.kb["sql_injection"]
        if "xss" in key or "script" in key: return self.kb["cross_site_scripting"]
        if "command" in key or "shell" in key: return self.kb["command_injection"]
        if "pickle" in key or "serial" in key: return self.kb["insecure_deserialization"]
        if "eval" in key or "exec" in key: return self.kb["vulnerable_logic"]
        
        return self.kb.get(key, self.kb.get("default"))
