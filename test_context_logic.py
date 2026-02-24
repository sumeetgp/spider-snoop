import json
import re
from typing import Dict, List

# --- MOCKING YOUR KNOWLEDGE BASE (Paste your Enhanced JSON here) ---
# In production, this loads from your json file
KNOWLEDGE_BASE = {
    "terms": {
        "Project Skylark": {
            "risk": "CRITICAL",
            "category": "Intellectual Property",
            "description": "Next-gen quantum encryption protocol.",
            "action": "BLOCK",
            "positive_context": ["quantum", "encryption", "protocol", "v2", "latency"],
            "negative_context": ["bird", "species", "migration", "nature", "flying"]
        },
        "Titan Alloy": {
            "risk": "HIGH",
            "category": "Trade Secret",
            "action": "ALERT",
            "positive_context": ["formula", "composite", "melt", "strength"],
            "negative_context": ["mythology", "greek", "clash of titans"]
        }
    },
    "regex_patterns": {
        "SKY-\\d{4}": {"desc": "Skylark Prototype Serial", "risk": "HIGH"},
        "https://hooks.sl" + "ack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Z0-9]+": {"desc": "Slack Webhook Secret", "risk": "CRITICAL"},
        "(?:4242\s?){4}": {"desc": "Stripe TEST Card (Safe)", "risk": "LOW", "action": "IGNORE"}
    }
}

# --- YOUR LOGIC (The function you wrote) ---
def consult_policy_db(query: str) -> str:
    query_lower = query.lower()
    matches = []
    
    # 1. Term Logic with Context
    for term, policy in KNOWLEDGE_BASE.get("terms", {}).items():
        if term.lower() in query_lower:
            # Negative Context (The "Bird" Filter)
            neg_ctx = policy.get("negative_context", [])
            if any(neg in query_lower for neg in neg_ctx):
                # Use set intersectionsafe logic for display
                found_neg = [n for n in neg_ctx if n in query_lower]
                matches.append(f"🟢 IGNORED FALSE POSITIVE: Found '{term}' but context suggests it's safe (matched '{found_neg}').")
                continue
            
            # Positive Context (The "Relevance" Booster)
            pos_ctx = policy.get("positive_context", [])
            has_context = any(pos in query_lower for pos in pos_ctx)
            
            if has_context:
                matches.append(f"🔴 CRITICAL MATCH: '{term}' found with risky context!\n   Action: {policy.get('action')}")
            else:
                matches.append(f"🟡 POTENTIAL MATCH: '{term}' found (No specific context). Risk: {policy['risk']}")

    # 2. Regex Logic
    for pattern, details in KNOWLEDGE_BASE.get("regex_patterns", {}).items():
        if re.search(pattern, query, re.IGNORECASE):
            matches.append(f"🔍 PATTERN: {details['desc']} (Risk: {details.get('risk')})")

    return "\n".join(matches) if matches else "✅ CLEAN"

# --- THE TEST RUNNER ---
test_cases = [
    {
        "name": "False Positive Trap (Nature)",
        "content": "I went hiking yesterday and saw a beautiful Project Skylark flying above the trees. It is a rare species in this region."
    },
    {
        "name": "True Positive (The Leak)",
        "content": "Update on Project Skylark: The quantum encryption module v2 has high latency. We need to fix the protocol."
    },
    {
        "name": "The Developer Test (Safe Data)",
        "content": "Guys, use this card for staging: 4242 4242 4242 4242. Do not use real cards!"
    },
    {
        "name": "The DevOps Leak (Unsafe)",
        "content": "I pushed the hotfix. Here is the webhook: https://hooks.sl" + "ack.com/services/T12345678/B12345678/ABC12345678"
    },
    {
        "name": "Ambiguous Context (Titan)",
        "content": "The durability of the Titan Alloy is amazing, but we need to check the melt point formula again."
    }
]

print(f"{'='*60}\nRUNNING SPIDERCOB LOGIC TESTS\n{'='*60}")

for i, test in enumerate(test_cases, 1):
    print(f"\n🧪 TEST #{i}: {test['name']}")
    print(f"📄 Content: \"{test['content'][:60]}...\"")
    print(f"🛡️  RESULT:")
    print(consult_policy_db(test['content']))
    print("-" * 60)
