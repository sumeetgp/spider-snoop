# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spider-Snoop is an enterprise **Data Loss Prevention (DLP)** system that scans files and content for sensitive data (PII, secrets, malware, vulnerable dependencies). It exposes a FastAPI backend, a React 19 frontend, an ICAP server for transparent proxy integration, and a Celery worker for async heavy scans.

## Development Commands

### Backend

```bash
# Create and activate virtualenv (uses uv or pip)
python -m venv venv && source venv/bin/activate

# Install dependencies (prefer uv)
uv sync
# or: pip install -r requirements.txt

# Copy env and configure
cp .env.example .env

# Initialize database (creates tables + default users)
python scripts/init_db.py

# Run dev server (from repo root)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# or: python -m app.main

# Run Alembic migrations
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "description"

# Run Celery worker (requires Redis running)
python -m celery -A app.worker.celery_app worker --loglevel=info
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # Dev server at http://localhost:5173
npm run build      # Build to frontend/dist/
npm run lint       # ESLint
npm run preview    # Preview production build
```

### Tests

```bash
# Run all tests (from repo root)
pytest tests/

# Run a single test file
pytest tests/test_dlp_integration.py

# Run a specific test
pytest tests/test_dlp_integration.py::test_function_name -v

# Dev dependencies needed: httpx, pytest, pytest-asyncio, starlette
```

### Docker (full stack)

```bash
# Start all services (Postgres, Redis, ClamAV, API, Celery, Frontend, Nginx, OPA)
docker-compose up -d --build

# Or use the automated deploy script
chmod +x deploy.sh && ./deploy.sh

# Services exposed:
# API:      http://localhost:8000
# Frontend: http://localhost:8080
# Nginx:    http://localhost:80 (reverse proxy, production)
# OPA:      http://localhost:8181
# ClamAV:   localhost:3310
# Redis:    localhost:6379
```

## Architecture

### Request Flow

```
Browser/Client
  → Nginx (80/443)          # reverse proxy in production
  → Frontend (8080)          # React SPA (Vite/Tailwind)
  → API (8000)               # FastAPI
  → Scanning Engines         # in-process, or delegated to Celery worker
  → PostgreSQL (5432)        # scan records, users, audit logs
  → Redis (6379)             # Celery task queue + results

Corporate Proxy → ICAP Server (1344) → same API scanning logic
```

### Backend Structure (`app/`)

| Path | Role |
|---|---|
| `app/main.py` | FastAPI factory: mounts routers, starts ICAP server and MCP client in `lifespan` |
| `app/config.py` | `Settings` via pydantic-settings; reads `.env`. Key flags: `SERVICE_ROLE`, `USE_LOCAL_ML`, `USE_LANGCHAIN_CISO` |
| `app/database.py` | SQLAlchemy engine + session factory; Alembic manages migrations |
| `app/worker.py` | Celery app config; tasks live in `app/tasks/scan_tasks.py` |
| `app/icap_server.py` | Async ICAP server (port 1344); forwards scans to the DLP engine |
| `app/mcp_server.py` | MCP server that exposes DLP tools to LLMs; connected to `DLPEngine` at startup |

**Routes** (`app/routes/`): `auth`, `users`, `scans`, `dashboard`, `cdr`, `code_security`, `enterprise`, `proxy`

**Scanning Engines** (`app/core/`):

| Engine | What it does |
|---|---|
| `dlp_engine.py` | Orchestrator: runs pattern matching + intent classifier + Presidio; main entry point for text/file scans |
| `dlp_patterns.py` | Regex catalog (CC, SSN, API keys, AWS keys, emails, IPs, etc.) |
| `dlp_intent_classifier.py` | ML model to distinguish real sensitive data from false positives |
| `file_security_engine.py` | Orchestrates ClamAV + YARA + static analysis + metadata + context classifier for file uploads |
| `file_guard.py` | ClamAV (`clamd`) + YARA wrapper |
| `static_analyzer.py` | Entropy, magic byte validation, packed binary detection |
| `metadata_extractor.py` | EXIF, OLE, PDF metadata inspection |
| `context_classifier.py` | ML risk scoring for file context |
| `presidio_engine.py` | Microsoft Presidio PII/anonymization |
| `code_scanner.py` | Dependency manifest parsing + OSV vulnerability lookup |
| `code_risk_classifier.py` | ML severity assessment for code CVEs |
| `cdr_engine.py` | Content Disarm & Reconstruction (strips macros, scripts, metadata from PDFs, Office docs, images) |

**Models** (`app/models/`): `User` (roles: admin/analyst/viewer), `DLPScan` (findings, risk_level, verdict), `ProxyLog` (AI firewall audit)

### ML Models in the DLP Scan Flow

All ML inference routes through the singleton `LocalMLEngine` (`app/core/ml_engine.py`). Models are lazy-loaded on first use and cached. Runs on CPU only (`torch.set_num_threads(2)`). If `torch`/`transformers`/`sentence-transformers` are not installed, a `MockMLEngine` keyword-heuristic fallback is used automatically.

Local offline copies are loaded from `models/<model_name_with_slashes_replaced_by_underscores>/` if that directory exists, otherwise downloaded from HuggingFace.

| Task key | Model | Library | Used by |
|---|---|---|---|
| `zero_shot` | `all-MiniLM-L6-v2` | `sentence-transformers` | **All three classifiers below** via `compute_similarity()` (cosine similarity zero-shot) |
| `dlp` | `distilbert-base-uncased` | `transformers` | Reserved for fine-tuned DLP head (not wired into current scan flow) |
| `malware` | `distilbert-base-uncased` | `transformers` | Reserved for fine-tuned malware head (not wired into current scan flow) |
| `code` | `microsoft/codebert-base` | `transformers` | Reserved for fine-tuned code risk head (not wired into current scan flow) |
| NER (Presidio) | `en_core_web_sm` | `spaCy` | `PresidioEngine` — named entity recognition for persons, locations, etc. |

**How `compute_similarity` works**: encodes the input text and each candidate label as sentence embeddings using `all-MiniLM-L6-v2`, then picks the label with the highest cosine similarity. This is the zero-shot classification mechanism used by all three classifiers.

**Classifier → label sets:**

- `DLPIntentClassifier` (`dlp_intent_classifier.py`) — 4 labels: `REAL_DATA`, `TEST_DATA`, `DOCUMENTATION`, `NOISE`. Decides whether a regex hit is genuine PII or a false positive. Threshold: BLOCK if `REAL_DATA` confidence > 0.7; ALLOW if `TEST_DATA` confidence > 0.8.
- `ContextClassifier` (`context_classifier.py`) — 6 labels: `RANSOMWARE`, `BANKING_TROJAN`, `BACKDOOR`, `BENIGN_DOC`, `BENIGN_EXE`, `BENIGN_TXT`. Used inside `FileSecurityEngine` to assign a threat family to uploaded files.
- `CodeRiskClassifier` (`code_risk_classifier.py`) — 5 labels: `REAL_SECRET`, `VULNERABLE_LOGIC`, `TEST_MOCK`, `SAFE_CODE`, `SECURE_CODE`. Reduces false positives from `CodeScanner` dependency/secret findings.

**OpenAI** (`gpt-*` via `openai` SDK) is used for enhanced analysis when `USE_LOCAL_ML=False` or `USE_LANGCHAIN_CISO=True` in config. Falls back to local ML when the API key is absent.

**Auth**: JWT via `python-jose`, passwords hashed with `bcrypt`. Tokens expire per `ACCESS_TOKEN_EXPIRE_MINUTES`. Rate limiting via `SlowAPI` + credit-based `limiter`.

**Middleware**: `SecurityHeadersMiddleware` injects CSP nonces per request; nonce is accessed as `request.state.nonce` in templates and route handlers.

### Frontend Structure (`frontend/src/`)

React 19 SPA with React Router v6. Tailwind CSS ("Obsidian Glass" dark theme — primary `#88FFFF` cyan on `#0D1117` bg). Lucide icons, React Dropzone, Axios, tsParticles.

**Routing** (`App.jsx`):

| Route | Page |
|---|---|
| `/` | `Home` (landing) |
| `/login`, `/register`, `/forgot-password`, `/reset-password` | Auth pages |
| `/dashboard` | Main dashboard |
| `/results/:id` | Offline scan detail |
| `/about`, `/enterprise`, `/api/docs`, `/firewall/onboarding` | Info pages |
| `/admin/users`, `/admin/firewall` | Admin pages |

**Layouts**: `LandingLayout` (landing + particles + footer) wraps public pages; `MainLayout` (Navbar + Sidebar + ParticlesBackground) wraps the dashboard.

**Sidebar tracks** → each tab renders a track component inside the dashboard:

| Track Component | Scanning purpose | API endpoint used |
|---|---|---|
| `OverviewTrack` | KPI cards, threat charts, recent activity log | `/api/dashboard/overview`, `/api/scans/` |
| `SentinelTrack` | File Guard — malware + optional CDR "Safe Wash" | `POST /api/scans/upload_file?track=sentinel` |
| `GuardianTrack` | DLP — docs, images, video/audio; auto-routes media to vision track | `POST /api/scans/upload_file?track=guardian` or `upload_video` |
| `SecurityTrack` | Supply chain — package manifests, zip archives | `POST /api/security/scan` |
| `OfflineTrack` | Async job queue for large files (>10 MB); auto-refreshes every 15 s | `/api/scans/?source=OFFLINE` |

**Shared scan UI flow**: `InputZone` (drag-drop upload) → `StagingArea` (review before scan) → `ScanResults` (findings table, AI insights, threat score). `CodeSecurityReport` is a specialised results component for supply-chain CVEs with remediation links.

**PipelineVisualizer**: polls `/api/scans/{id}` every 5 s and renders pipeline stage progress: `UPLOADED → MALWARE_SCANNING → EXTRACTING → CONTENT_SCANNING → AI_ANALYSIS → POLICY_EVAL → COMPLETED`.

**Auth** (`hooks/useAuth.js`): fetches `/api/users/me` on mount using the token from `localStorage`; clears token and logs out on 401.

**API client** (`services/api.js`): all authenticated requests send `Authorization: Bearer {token}`. `uploadFile(file, track, opts)` routes to the correct endpoint based on `track` (`sentinel`, `guardian`, `vision`, `security`). Pass `correct=true` for CDR/Safe Wash.

### Database Migrations

- Schema changes must go through Alembic (`alembic/versions/`)
- `Base.metadata.create_all()` is intentionally commented out in `main.py` — always use `alembic upgrade head`
- SQLite is used for local dev (default); PostgreSQL in Docker/production

### MCP Integration

At startup, `main.py` launches `mcp_server.py` as a subprocess and injects the MCP `ClientSession` into `DLPEngine.mcp_session`. If MCP fails to connect within 5 seconds, scanning continues without it.

### Key Environment Variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy URL (default: SQLite) |
| `SECRET_KEY` | JWT signing key |
| `OPENAI_API_KEY` | Required for LLM-enhanced analysis |
| `SERVICE_ROLE` | `MONOLITH` (default) / `API` / `SCANNER` |
| `REDIS_URL` | Celery broker (default: `redis://localhost:6379/0`) |
| `DO_SPACES_*` | DigitalOcean Spaces for file storage |
| `USE_LOCAL_ML` | Use local Transformers models instead of OpenAI |

### Default Users (after `init_db.py`)

| Username | Password | Role |
|---|---|---|
| admin | admin123 | Admin |
| analyst | analyst123 | Analyst |
| viewer | viewer123 | Viewer |

### Ports Summary

| Service | Port |
|---|---|
| FastAPI API | 8000 |
| ICAP Server | 1344 |
| React Frontend | 8080 (Docker) / 5173 (dev) |
| Nginx | 80 / 443 |
| PostgreSQL | 5432 |
| Redis | 6379 |
| ClamAV | 3310 |
| OPA | 8181 |
