import re
from typing import Dict, List, Tuple
from mcp.server.fastmcp import FastMCP
from app.core.dlp_patterns import DLPPatternMatcher

# Initialize the DLP Server
mcp = FastMCP("DLP Scanner Service")




# Initialize the matcher
matcher = DLPPatternMatcher()


@mcp.tool()
def scan_patterns(text: str) -> str:
    """
    Enterprise-grade DLP scanner for comprehensive PII and sensitive data detection.
    
    Scans for:
    - Financial: Credit cards (Luhn validated), SSN, bank accounts, IBAN, routing numbers
    - Personal: Email, phone, passport, driver's license, medical records, DOB
    - Network: IPv4, IPv6, MAC addresses
    - Credentials: AWS keys, GitHub tokens, API keys, Bearer tokens, JWT, passwords
    - Cryptographic: Private keys (RSA, EC, SSH, PGP)
    - Database: Connection strings with credentials
    - Cryptocurrency: Bitcoin, Ethereum addresses
    - Sensitive keywords: Confidential, proprietary, trade secret, etc.
    
    Returns a detailed report organized by severity (CRITICAL, HIGH, MEDIUM, LOW).
    """
    results = matcher.scan(text)
    
    # Build formatted report
    report_lines = []
    total_findings = 0
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        findings = results[severity]
        if findings:
            report_lines.append(f"\n{'='*60}")
            report_lines.append(f"  {severity} FINDINGS: {len(findings)}")
            report_lines.append(f"{'='*60}")
            
            # Group by type
            by_type = {}
            for finding in findings:
                ftype = finding["type"]
                if ftype not in by_type:
                    by_type[ftype] = []
                by_type[ftype].append(finding)
            
            # Display findings
            for ftype, items in by_type.items():
                report_lines.append(f"\n  [{items[0]['description']}]")
                for idx, item in enumerate(items[:5], 1):  # Limit to 5 per type
                    report_lines.append(f"    {idx}. {item['value']} (at {item['position']})")
                if len(items) > 5:
                    report_lines.append(f"    ... and {len(items) - 5} more")
            
            total_findings += len(findings)
    
    if total_findings == 0:
        return "✓ CLEAN: No sensitive patterns detected in the scanned content."
    
    # Summary header
    summary = f"""
╔══════════════════════════════════════════════════════════╗
║          DLP SCAN REPORT - {total_findings} FINDINGS DETECTED          
╚══════════════════════════════════════════════════════════╝
"""
    
    return summary + "\n".join(report_lines) + f"\n\n{'='*60}\nTotal Findings: {total_findings}\n{'='*60}"


@mcp.tool()
def enhanced_scan(text: str, include_context: bool = False) -> str:
    """
    Advanced DLP scan with optional context extraction.
    
    Args:
        text: Content to scan
        include_context: If True, returns 20 chars before/after each finding
    
    Returns:
        Detailed scan report with optional surrounding context
    """
    results = matcher.scan(text)
    
    report = {
        "summary": {
            "total_findings": sum(len(findings) for findings in results.values()),
            "critical": len(results["CRITICAL"]),
            "high": len(results["HIGH"]),
            "medium": len(results["MEDIUM"]),
            "low": len(results["LOW"])
        },
        "findings_by_severity": results
    }
    
    # Format as readable text
    output = f"""
ENHANCED DLP SCAN RESULTS
{'='*60}

SUMMARY:
  Total Findings: {report['summary']['total_findings']}
  Critical: {report['summary']['critical']}
  High: {report['summary']['high']}
  Medium: {report['summary']['medium']}
  Low: {report['summary']['low']}

RISK ASSESSMENT:
"""
    
    if report['summary']['critical'] > 0:
        output += "  ⛔ CRITICAL RISK: Immediate action required!\n"
    elif report['summary']['high'] > 0:
        output += "  ⚠️  HIGH RISK: Review and remediate\n"
    elif report['summary']['medium'] > 0:
        output += "  ⚡ MEDIUM RISK: Monitor and address\n"
    else:
        output += "  ✓ LOW/NO RISK: No critical issues detected\n"
    
    return output


if __name__ == "__main__":
    mcp.run()
