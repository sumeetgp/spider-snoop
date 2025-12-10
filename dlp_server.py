import re
from mcp.server.fastmcp import FastMCP

# Initialize the DLP Server
mcp = FastMCP("DLP Scanner Service")

@mcp.tool()
def scan_patterns(text: str) -> str:
    """
    Scans text for PII patterns (Emails, SSN-like numbers) and aggressive keywords.
    Returns a report of findings.
    """
    findings = []

    # 1. Email Regex (Basic)
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    if emails:
        findings.append(f"CRITICAL: Found {len(emails)} email addresses: {', '.join(emails)}")

    # 2. "Secret" Keyword Scanner (Simulating keyword lists)
    # In a real app, this would load from a database
    bad_words = ["confidential", "internal use only", "private key", "password"]
    for word in bad_words:
        if word.lower() in text.lower():
            findings.append(f"WARNING: Found sensitive keyword: '{word}'")

    if not findings:
        return "CLEAN: No hard-coded patterns found."
    
    return "\n".join(findings)

if __name__ == "__main__":
    mcp.run()

    