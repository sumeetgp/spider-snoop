"""
Scan curated public GitHub repos to generate training data for CodeRiskClassifier.

Strategy:
  - Vulnerable repos  → VULNERABLE_LOGIC / REAL_SECRET
  - Test fixture repos → TEST_MOCK
  - Clean prod repos  → SAFE_CODE / SECURE_CODE

Run from repo root:
  python scripts/scan_public_repos.py

Output: code_risk_training_data.csv
  columns: text, label, repo, file, issue_type, notes

Then fine-tune:
  python scripts/train_code_risk_classifier.py
"""

import asyncio
import csv
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

OUTPUT_FILE = "code_risk_training_data.csv"
CLONE_DIR = tempfile.mkdtemp(prefix="spidercob_repos_")

# ── Curated repo list ─────────────────────────────────────────────────────────
# Each entry: (repo_url, default_label, notes)
# default_label is the fallback — the scanner may override based on finding type.

REPOS = [
    # ── Intentionally vulnerable (VULNERABLE_LOGIC / REAL_SECRET) ────────────
    ("https://github.com/WebGoat/WebGoat",              "VULNERABLE_LOGIC", "OWASP WebGoat — intentionally vulnerable Java app"),
    ("https://github.com/digininja/DVWA",               "VULNERABLE_LOGIC", "Damn Vulnerable Web App — PHP"),
    ("https://github.com/vulhub/vulhub",                "VULNERABLE_LOGIC", "Docker vuln environments with CVE examples"),
    ("https://github.com/trufflesecurity/trufflehog",   "REAL_SECRET",      "TruffleHog test corpus — confirmed leaked secrets"),
    ("https://github.com/OWASP/NodeGoat",               "VULNERABLE_LOGIC", "OWASP NodeGoat — intentionally vulnerable Node.js"),
    ("https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application", "VULNERABLE_LOGIC", "DVGA — GraphQL injection examples"),

    # ── Test fixture heavy repos (TEST_MOCK) ──────────────────────────────────
    ("https://github.com/FactoryBoy/factory_boy",       "TEST_MOCK",        "factory_boy — Python test fixture library"),
    ("https://github.com/joke2k/faker",                 "TEST_MOCK",        "Faker — fake data generator for tests"),
    ("https://github.com/pytest-dev/pytest",            "TEST_MOCK",        "pytest — test fixtures and mock data throughout"),
    ("https://github.com/model-bakers/model_bakery",    "TEST_MOCK",        "Django model bakery — test data factories"),

    # ── Clean production code (SAFE_CODE / SECURE_CODE) ──────────────────────
    ("https://github.com/django/django",                "SAFE_CODE",        "Django — well-maintained production Python"),
    ("https://github.com/tiangolo/fastapi",             "SAFE_CODE",        "FastAPI — production Python web framework"),
    ("https://github.com/psf/requests",                 "SAFE_CODE",        "requests — clean Python HTTP library"),
    ("https://github.com/pallets/flask",                "SAFE_CODE",        "Flask — production Python web framework"),
    ("https://github.com/encode/httpx",                 "SAFE_CODE",        "httpx — modern async HTTP client"),

    # ── Ruby ──────────────────────────────────────────────────────────────────
    ("https://github.com/OWASP/railsgoat",              "VULNERABLE_LOGIC", "OWASP Railsgoat — intentionally vulnerable Rails app"),
    ("https://github.com/heartcombo/devise",            "SAFE_CODE",        "Devise — secure Rails authentication library"),
    ("https://github.com/sinatra/sinatra",              "SAFE_CODE",        "Sinatra — clean Ruby web framework"),

    # ── TypeScript / JavaScript ───────────────────────────────────────────────
    ("https://github.com/juice-shop/juice-shop",        "VULNERABLE_LOGIC", "OWASP Juice Shop — intentionally vulnerable Node/TS"),

    # ── Go ────────────────────────────────────────────────────────────────────
    ("https://github.com/gin-gonic/gin",                "SAFE_CODE",        "Gin — clean Go web framework"),
    ("https://github.com/golang/vulndb",                "VULNERABLE_LOGIC", "Go vulnerability database — CVE examples"),

    # ── C / C++ ───────────────────────────────────────────────────────────────
    ("https://github.com/nist-software/juliet-test-suite-c", "VULNERABLE_LOGIC", "Juliet Test Suite — labeled C/C++ CWE vulnerability examples"),
]

# Extensions to scan
CODE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".yaml", ".yml", ".env.example", ".tf", ".c", ".cpp", ".h"}

# Max files per repo (avoid enormous repos taking forever)
MAX_FILES_PER_REPO = 200
MAX_CONTENT_CHARS = 2000

# ── Heuristic label overrides ─────────────────────────────────────────────────

SECRET_KEYWORDS = re.compile(
    r"(AKIA[0-9A-Z]{16}"                               # AWS key
    r"|sk[-_](test|live)_\w{10,}"                       # Stripe key
    r"|-----BEGIN (RSA |EC )?PRIVATE KEY"               # PEM key
    r"|['\"](?:[A-Za-z0-9+/]{40,})['\"]"               # long base64 token
    r"|(?:api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[=:]\s*['\"][^'\"]{8,}['\"])",  # key=value with real value
    re.IGNORECASE,
)

TEST_KEYWORDS = re.compile(
    r"(test_|_test|\bfixture\b|\bfactory\b|\bfaker\b|\bmock\b|\bdummy\b|\bsandbox\b"
    r"|\bexample\b|\bplaceholder\b|fake_|stub_|@example\.com|testuser"
    r"|test123|changeme|password123|withwebgoat|customuser|createuser)",
    re.IGNORECASE,
)

VULN_PATTERNS = re.compile(
    r"(\beval\s*\(|\bexec\s*\(|pickle\.load|shell\s*=\s*True"
    r"|\.innerHTML\s*=|dangerouslySetInnerHTML"
    r"|os\.system\s*\(|subprocess\.call.*shell"
    r"|yaml\.load\s*\([^,)]+\)"
    r"|\bmd5\s*\(|\bSHA1\s*\("
    r"|jwt\.decode.*verify.*False"
    # PHP specific
    r"|\$_GET\s*\[|\$_POST\s*\[|\$_REQUEST\s*\["    # unsanitized input
    r"|mysql_query\s*\(|mysqli_query\s*\(\s*\$"      # raw SQL
    r"|\beval\s*\(\s*\$"                              # PHP eval
    r"|system\s*\(\s*\$|passthru\s*\(\s*\$"          # PHP shell exec
    # Java specific
    r"|Statement\.execute\s*\(|createStatement\s*\(\)" # raw JDBC
    r"|Runtime\.getRuntime\(\)\.exec"                  # Java shell exec
    r"|new\s+ProcessBuilder"                           # Java process
    r"|@CrossOrigin\s*\(\s*origins\s*=\s*[\"']\*"    # CORS wildcard
    r")",
    re.IGNORECASE,
)

SECURE_PATTERNS = re.compile(
    r"(bcrypt\.hashpw|bcrypt\.checkpw|argon2\.hash"
    r"|\.prepareStatement\s*\(|PreparedStatement"     # parameterized SQL
    r"|parameterize|bind_param|execute\s*\(\s*\["     # parameterized queries
    r"|secrets\.token_|os\.urandom\s*\("              # secure random
    r"|hashlib\.pbkdf2_hmac|werkzeug\.security"       # secure hashing
    r"|CSRFProtect|@csrf_protect|verify_jwt_token"    # CSRF/JWT protection
    r"|escape\s*\(|bleach\.clean|html\.escape)",      # output escaping
    re.IGNORECASE,
)


def clone_repo(url: str, dest: str) -> bool:
    """Shallow clone a repo. Returns True on success."""
    try:
        subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", url, dest],
            timeout=120,
            check=True,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  SKIP: clone failed — {e}")
        return False


def iter_code_files(repo_dir: str):
    """Yield (path, content) for scannable files in the repo."""
    count = 0
    for root, dirs, files in os.walk(repo_dir):
        # Skip hidden dirs, vendor, node_modules
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d not in ("node_modules", "vendor", "__pycache__", ".git", "dist", "build")
        ]
        for fname in files:
            if count >= MAX_FILES_PER_REPO:
                return
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in CODE_EXTENSIONS:
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                if len(content) < 50:
                    continue
                yield str(fpath), content[:MAX_CONTENT_CHARS]
                count += 1
            except Exception:
                continue


def extract_findings(content: str, file_path: str, default_label: str) -> list[dict]:
    """
    Extract labelled training examples from a file.
    Each finding = one context window around the matched line.
    """
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        line_stripped = line.strip()
        if len(line_stripped) < 10:
            continue

        # Build context window (3 lines before + 3 after)
        ctx_start = max(0, i - 3)
        ctx_end = min(len(lines), i + 4)
        context = "\n".join(lines[ctx_start:ctx_end]).strip()[:400]

        label = None
        issue_type = None
        notes = None

        in_test_context = bool(TEST_KEYWORDS.search(context))

        # 1. Confirmed hardcoded secret (real key/token pattern)
        if SECRET_KEYWORDS.search(line_stripped):
            if in_test_context:
                label = "TEST_MOCK"
                issue_type = "credential_in_test"
                notes = f"real secret pattern in test context — {default_label} repo"
            else:
                label = "REAL_SECRET"
                issue_type = "hardcoded_secret"
                notes = f"confirmed secret pattern — {default_label} repo"

        # 2. Secure implementation patterns → SAFE_CODE
        elif SECURE_PATTERNS.search(line_stripped):
            label = "SAFE_CODE"
            issue_type = "secure_implementation"
            notes = f"secure coding pattern — {default_label} repo"

        # 3. Vulnerability patterns
        elif VULN_PATTERNS.search(line_stripped):
            if in_test_context:
                label = "TEST_MOCK"
                issue_type = "vuln_pattern_in_test"
                notes = f"vuln pattern in test context — {default_label} repo"
            else:
                # In vulnerable repos these are real vulns; in clean repos they're examples
                label = "VULNERABLE_LOGIC" if default_label == "VULNERABLE_LOGIC" else "SAFE_CODE"
                issue_type = "vulnerable_pattern"
                notes = f"vuln pattern — {default_label} repo"

        # 4. Clean lines in clean repos (sampled)
        elif default_label in ("SAFE_CODE", "SECURE_CODE") and len(line_stripped) > 30:
            if i % 20 == 0:
                label = "SAFE_CODE"
                issue_type = "clean_code"
                notes = f"clean code sample — {default_label} repo"

        # 5. Test fixture lines in test repos
        elif default_label == "TEST_MOCK" and TEST_KEYWORDS.search(line_stripped):
            label = "TEST_MOCK"
            issue_type = "test_fixture"
            notes = "test fixture pattern"

        if label and context:
            fname = Path(file_path).name
            text = f"Analyze this {issue_type}: {context}"
            findings.append({
                "text": text[:600],
                "label": label,
                "repo": "",  # filled in by caller
                "file": fname,
                "issue_type": issue_type,
                "notes": notes,
            })

    return findings


def main():
    print(f"Scanning {len(REPOS)} public repos for CodeRiskClassifier training data...")
    print(f"Cloning to: {CLONE_DIR}\n")

    all_examples = []
    from collections import Counter
    label_counts = Counter()

    try:
        for repo_url, default_label, description in REPOS:
            repo_name = repo_url.rstrip("/").split("/")[-1]
            dest = os.path.join(CLONE_DIR, repo_name)

            print(f"[{default_label}] {repo_name} — {description}")
            if not clone_repo(repo_url, dest):
                continue

            repo_examples = []
            for fpath, content in iter_code_files(dest):
                findings = extract_findings(content, fpath, default_label)
                for f in findings:
                    f["repo"] = repo_name
                repo_examples.extend(findings)

            # Cap per repo to keep dataset balanced
            MAX_PER_REPO = 300
            if len(repo_examples) > MAX_PER_REPO:
                import random
                random.shuffle(repo_examples)
                repo_examples = repo_examples[:MAX_PER_REPO]

            all_examples.extend(repo_examples)
            dist = Counter(e["label"] for e in repo_examples)
            print(f"  → {len(repo_examples)} examples: {dict(dist)}")

            # Clean up cloned repo to save disk
            shutil.rmtree(dest, ignore_errors=True)

    finally:
        shutil.rmtree(CLONE_DIR, ignore_errors=True)

    if not all_examples:
        print("\nERROR: No examples collected. Check network access and repo URLs.")
        sys.exit(1)

    # Deduplicate on text
    seen = set()
    unique = []
    for e in all_examples:
        if e["text"] not in seen:
            seen.add(e["text"])
            unique.append(e)

    label_counts = Counter(e["label"] for e in unique)

    print(f"\nTotal unique examples: {len(unique)}")
    print("\nLabel distribution:")
    for label in ["REAL_SECRET", "VULNERABLE_LOGIC", "TEST_MOCK", "SAFE_CODE", "SECURE_CODE"]:
        count = label_counts.get(label, 0)
        bar = "█" * min(count // 10, 50)
        print(f"  {label:20s}: {count:5d}  {bar}")

    fields = ["text", "label", "repo", "file", "issue_type", "notes"]
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(unique)

    print(f"\nSaved to {OUTPUT_FILE}")
    print("\nNext steps:")
    print("  1. Review and spot-check: head -50 code_risk_training_data.csv")
    print("  2. Train: python scripts/train_code_risk_classifier.py")


if __name__ == "__main__":
    main()
