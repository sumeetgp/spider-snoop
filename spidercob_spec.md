# Spidercob.com | Full Technical Specification (v2.0)

## 1. Brand Identity & Aesthetic
* **Theme Name:** Obsidian Glass
* **Core Philosophy:** **Contextual Disclosure.** Complexity is hidden until a file is uploaded to prevent "HUD Fatigue."
* **Visual Style:** Dark-mode Industrial. Matte Black backgrounds with semi-transparent "Glassmorphism" cards.
* **Color Palette:**
    * **Background:** `#0D1117`
    * **Brand Neon:** `#88FFFF` (Primary buttons/links/glows)
    * **Success Green:** `#238636` (Clean files)
    * **Warning Orange:** `#D29922` (DLP Leaks/PII)
    * **Alert Red:** `#F85149` (Malware/Critical threats)
* **Typography:** Sans-serif (Inter/Geist) for UI; Monospace (JetBrains Mono) for hashes, code snippets, and terminal logs.

---

## 2. Service Architecture (The 3 Pillars)
The backend is divided into three specialized "Scan Tracks."

| Track Name | Technical Action | Primary Use Case |
| :--- | :--- | :--- |
| **Sentinel** | Signature + Heuristic Malware Analysis | Rapid file clearing (Executables, PDFs, Zips). |
| **Guardian** | PII, Secret Key, & Financial DLP Regex/ML | Compliance, HR, and Developer Secret Leak prevention. |
| **Vision** | Frame-by-frame OCR + Object detection | Security audits for screen-shares or demo recordings. |

---

## 3. Anti-DoS & Resource Governance
To protect infrastructure from high-volume attacks and expensive GPU compute costs.

### A. Credit-Based Throttling
Every scan consumes "Credits" based on computational intensity:
* **Sentinel Scan:** 1 Credit
* **Guardian Scan:** 2 Credits
* **Vision (Video) Scan:** 10 Credits

### B. Tiered Usage Limits (Authenticated Users)
* **Standard Limit:** 50 Credits per 60-minute sliding window.
* **Hard Limit:** HTTP 429 triggered at 51+ credits.
* **File Size Caps:**
    * **Unauthenticated:** 2MB (Docs) / 10MB (Video).
    * **Authenticated:** 50MB (Docs) / 500MB (Video).

### C. Technical Guardrails
* **Edge Protection:** Cloudflare Turnstile integration for suspicious IP bursts.
* **Magic Byte Validation:** Backend verifies file headers match extensions before processing.
* **Worker Isolation:** Every scan executes in a stateless, ephemeral Docker container.
* **Auto-Deletion:** All uploaded files are purged from storage within 24 hours (or immediately for guests).



---

## 4. User Journey & UI Interactions

### A. Landing Page (The Hook)
* **Interaction:** User drops a file into a central "Instant Scan" zone.
* **Logic:** A "Surface Scan" (Hash lookup) is performed instantly.
* **The Gate:** Results show high-level threats (e.g., "PII Detected"), but specific data and timestamps are blurred.
* **CTA:** "Register to unlock the full report."

### B. Workspace Dashboard (The Hub)
* **Sidebar Usage Gauge:** A real-time progress bar showing `$X/50` credits used this hour.
* **Service Toggles:** Visual buttons to switch between Sentinel, Guardian, and Vision tracks.

### C. Analysis Report (The Deep Dive)
* **Risk Score Gauge:** A large circular visualization (0-100).
* **Video Timeline (Vision Only):** A horizontal heatmap with red/orange markers indicating leak timestamps.
* **Evidence Gallery:** Snapshots of frames containing visual leaks (e.g., a visible password).
* **API Bridge:** A "View as Code" toggle that provides the `curl` command to replicate the scan.



---

## 5. API Integration Specifications
* **Authentication:** `X-Spider-Key` Header (JWT or API Key).
* **Standard Response Format:**
    ```json
    {
      "scan_id": "cob-uuid-123",
      "threat_score": 82,
      "summary": "Critical DLP Leak Found",
      "findings": {
        "malware": [],
        "dlp_matches": [{"type": "AWS_KEY", "confidence": 0.98}],
        "timestamps": ["00:12", "01:45"]
      },
      "credits_remaining": 38
    }
    ```
* **Webhooks:** Asynchronous `POST` to user-defined `callback_url` for heavy Video tasks.

---

## 6. Implementation Roadmap
1.  **Phase 1:** Build the "Obsidian Glass" UI Shell with Tailwind.
2.  **Phase 2:** Implement the "Credit-Weighting" Middleware to handle the 50-request limit.
3.  **Phase 3:** Integrate Cloudflare for Edge DoS protection and MIME validation.
4.  **Phase 4:** Develop the Video OCR queue using Celery/Redis for the "Vision" track.