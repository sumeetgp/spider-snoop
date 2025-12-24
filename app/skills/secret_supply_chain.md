# Secret & Supply Chain Security Skills

## Overview
These skills provide the CISO Agent with the ability to audit codebases for security vulnerabilities.
- **Supply Chain**: Checks `package.json` and `requirements.txt` against the OSV.dev vulnerability database.
- **Secret Scanning**: Recursively scans files (Zip or Git) for hardcoded secrets, mimicking TruffleHog.

## Tools

### `scan_dependencies`
*   **Description**: Analyzes dependency manifest files for known vulnerabilities (CVEs).
*   **Input**: `manifest_content` (The content of the file) OR `file_path` (Path to the file).
*   **Engine**: Queries OSV.dev API (`https://api.osv.dev/v1/querybatch`).
*   **Supported Formats**:
    *   `requirements.txt` (Python)
    *   `package.json` (Node.js)

### `scan_secrets_codebase`
*   **Description**: Deep scan of a codebase (Zip archive) for hardcoded secrets.
*   **Input**: `file_path` (Path to .zip file).
*   **Engine**: `DLPPatternMatcher` with enhanced regex for:
    *   AWS, Stripe, Google, Azure, GitHub, Slack tokens.
    *   Private Keys (RSA, SSH, PGP).
    *   Database Connection Strings.
*   **Behavior**: Extracts zip to temp dir, iterates all files, runs regex, cleans up.

## Integration
These tools are exposed via `mcp_server.py` and consumed by `dlp_engine.py`'s `_ai_analyze_ciso_langchain` method.
