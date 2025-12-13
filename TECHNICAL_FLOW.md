# Spider-Snoop DLP System - Technical Flow Documentation

## 🏗️ System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ Web Browser  │  │ Proxy/ICAP   │  │ API Client   │              │
│  │ (Dashboard)  │  │ Client       │  │ (curl/http)  │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
└─────────┼──────────────────┼──────────────────┼──────────────────────┘
          │                  │                  │
          │ HTTP/REST        │ ICAP Protocol    │ HTTP/REST
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                               │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │               FastAPI Application (app/main.py)               │  │
│  │  • CORS Middleware                                            │  │
│  │  • Lifespan Manager (startup/shutdown)                        │  │
│  │  • Route Handlers                                             │  │
│  └────┬─────────────────────────────────────────────────┬────────┘  │
│       │                                                  │            │
│  ┌────▼─────────────┐                          ┌────────▼─────────┐ │
│  │  ICAP Server     │                          │   API Routes     │ │
│  │ (icap_server.py) │                          │  /auth, /scans,  │ │
│  │  Port: 1344      │                          │  /users, /dash   │ │
│  └────┬─────────────┘                          └────────┬─────────┘ │
└───────┼──────────────────────────────────────────────────┼──────────┘
        │                                                  │
        │                                                  │
        ▼                                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       BUSINESS LOGIC LAYER                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                  DLP Engine (dlp_engine.py)                   │  │
│  │  ┌───────────────┐  ┌────────────────┐  ┌─────────────────┐ │  │
│  │  │ Pattern Match │  │  AI Analysis   │  │ LangChain CISO  │ │  │
│  │  │ (Regex)       │  │  (OpenAI)      │  │ Agent + MCP     │ │  │
│  │  └───────────────┘  └────────────────┘  └─────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                       │
│                              │ Uses MCP Protocol                     │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │        MCP Server (dlp_server.py)                             │  │
│  │  Tools: scan_patterns, enhanced_scan                          │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       DATA ACCESS LAYER                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │          Database (SQLAlchemy ORM)                            │  │
│  │  • database.py - Session management                           │  │
│  │  • Models: User, Scan                                         │  │
│  │  • Schemas: Pydantic validation                               │  │
│  └────────────────────────────┬─────────────────────────────────┘  │
└────────────────────────────────┼────────────────────────────────────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │  SQLite DB    │
                         │ dlp_data.db   │
                         └───────────────┘
```

---

## 📊 Detailed Flow Diagrams

### 1️⃣ User Authentication Flow

```
Client                  API Route               Utils/Auth          Database
  │                        │                        │                  │
  │─ POST /api/auth/login ─▶                       │                  │
  │  {username, password}  │                        │                  │
  │                        │                        │                  │
  │                        │─ verify_password() ───▶                  │
  │                        │                        │                  │
  │                        │                        │─ SELECT user ───▶
  │                        │                        │  WHERE username  │
  │                        │                        │◀─ User object ───│
  │                        │                        │                  │
  │                        │◀─ password_match ──────│                  │
  │                        │                        │                  │
  │                        │─ create_access_token()─▶                  │
  │                        │                        │                  │
  │                        │◀─ JWT token ───────────│                  │
  │                        │                        │                  │
  │◀─ {access_token, ...} ─│                        │                  │
  │                        │                        │                  │
```

**Database Tables Used:**
- `users` table: id, username, email, hashed_password, role, is_active, created_at

**Key Operations:**
1. Query user by username: `SELECT * FROM users WHERE username = ?`
2. Verify password hash using bcrypt
3. Generate JWT token with user claims

---

### 2️⃣ DLP Scan Flow (API Endpoint)

```
Client          API Route       DLP Engine       AI/LangChain      MCP Server      Database
  │                │                │                  │                │              │
  │─ POST /scan ──▶               │                  │                │              │
  │  {text: "..."}│                │                  │                │              │
  │                │                │                  │                │              │
  │                │─ engine.scan()─▶                  │                │              │
  │                │                │                  │                │              │
  │                │                │─ Pattern Match   │                │              │
  │                │                │  (Regex on text) │                │              │
  │                │                │                  │                │              │
  │                │                │  Found: email,   │                │              │
  │                │                │  credit_card     │                │              │
  │                │                │                  │                │              │
  │                │                │  IF use_ai=True & │                │              │
  │                │                │  USE_LANGCHAIN_CISO=True          │              │
  │                │                │                  │                │              │
  │                │                │─ _ai_analyze_ciso_langchain() ───▶              │
  │                │                │                  │                │              │
  │                │                │                  │─ ChatOpenAI    │              │
  │                │                │                  │  creates agent │              │
  │                │                │                  │                │              │
  │                │                │                  │─ pattern_scanner_tool()      │
  │                │                │                  │                │              │
  │                │                │                  │                │─ scan_patterns()
  │                │                │                  │                │  (MCP call)│
  │                │                │                  │                │              │
  │                │                │                  │                │◀─ findings ─│
  │                │                │                  │                │              │
  │                │                │                  │◀─ tool result ─│              │
  │                │                │                  │                │              │
  │                │                │                  │─ Agent reasoning              │
  │                │                │                  │  (CISO analysis)              │
  │                │                │                  │                │              │
  │                │                │◀─ verdict dict ──│                │              │
  │                │                │  {verdict, category, reason}      │              │
  │                │                │                  │                │              │
  │                │                │─ _generate_verdict()              │              │
  │                │                │                  │                │              │
  │                │                │─ INSERT scan ────────────────────────────────────▶
  │                │                │                  │                │  INSERT INTO scans
  │                │                │                  │                │  (content_hash,
  │                │                │                  │                │   risk_level,
  │                │                │                  │                │   findings_json,
  │                │                │                  │                │   verdict, ...)
  │                │                │                  │                │              │
  │                │◀─ scan_result ─│                  │                │              │
  │                │  {risk_level,  │                  │                │              │
  │                │   findings,    │                  │                │              │
  │                │   verdict,     │                  │                │              │
  │                │   ai_analysis} │                  │                │              │
  │                │                │                  │                │              │
  │◀─ JSON result ─│                │                  │                │              │
  │                │                │                  │                │              │
```

**Database Tables Used:**
- `scans` table: id, content_hash, risk_level, verdict, findings_json, ai_analysis, scan_duration_ms, scanned_at, scanned_by

**Key Operations:**
1. Pattern matching (in-memory, no DB)
2. AI analysis via LangChain + MCP (external API calls)
3. Insert scan result: `INSERT INTO scans (...) VALUES (...)`

---

### 3️⃣ ICAP Server Flow (Transparent Proxy Scanning)

```
Proxy/Client    ICAP Server     DLP Engine      AI/LangChain     Database
     │              │                │                │              │
     │─ RESPMOD ───▶               │                │              │
     │ (HTTP Response)              │                │              │
     │              │                │                │              │
     │              │─ Parse ICAP   │                │              │
     │              │  headers       │                │              │
     │              │                │                │              │
     │              │─ Extract HTTP  │                │              │
     │              │  body content  │                │              │
     │              │                │                │              │
     │              │─ engine.scan()─▶                │              │
     │              │                │                │              │
     │              │                │─ Pattern Match │              │
     │              │                │                │              │
     │              │                │─ AI Analysis ──▶              │
     │              │                │                │              │
     │              │                │◀─ verdict ─────│              │
     │              │                │                │              │
     │              │                │─ INSERT scan ──────────────▶
     │              │                │                │              │
     │              │◀─ scan result ─│                │              │
     │              │                │                │              │
     │              │─ Decision:     │                │              │
     │              │  if HIGH/CRITICAL:               │              │
     │              │    BLOCK (403) │                │              │
     │              │  else:         │                │              │
     │              │    ALLOW (204) │                │              │
     │              │                │                │              │
     │◀─ ICAP Response─              │                │              │
     │  204 No Modifications         │                │              │
     │  OR 403 Forbidden             │                │              │
     │              │                │                │              │
```

**ICAP Protocol Methods Supported:**
- `OPTIONS` - Server capabilities
- `RESPMOD` - Response modification (scan HTTP responses)
- `REQMOD` - Request modification (scan HTTP requests)

**Blocking Logic:**
- CRITICAL/HIGH risk → Return 403 Forbidden
- MEDIUM/LOW risk → Return 204 No Modifications (allow)

---

### 4️⃣ Dashboard Data Retrieval Flow

```
Client          API Route       Database
  │                │                │
  │─ GET /api/scans/ ─────────────▶
  │  ?skip=0&limit=10              │
  │                │                │
  │                │─ SELECT scans ─▶
  │                │  ORDER BY scanned_at DESC
  │                │  LIMIT 10 OFFSET 0
  │                │                │
  │                │◀─ Scan list ───│
  │                │                │
  │◀─ JSON array ──│                │
  │  [{id, risk,   │                │
  │    findings,   │                │
  │    verdict}]   │                │
  │                │                │
  │─ GET /api/scans/stats ────────▶
  │                │                │
  │                │─ SELECT COUNT(*),
  │                │  SUM(CASE risk_level...),
  │                │  AVG(scan_duration_ms)
  │                │  FROM scans    │
  │                │                │
  │                │◀─ Stats ───────│
  │                │                │
  │◀─ {total,      │                │
  │    by_risk,    │                │
  │    avg_duration}                │
  │                │                │
```

**Database Queries:**
1. List scans: `SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ? OFFSET ?`
2. Get stats: Aggregation queries (COUNT, SUM, AVG)
3. Filter by user: `WHERE scanned_by = ?`
4. Filter by date: `WHERE scanned_at BETWEEN ? AND ?`

---

### 5️⃣ LangChain CISO Agent Flow (Detailed)

```
DLP Engine              LangChain Agent           MCP Session        OpenAI API
    │                        │                         │                  │
    │─ _ai_analyze_ciso_langchain(text)               │                  │
    │                        │                         │                  │
    │─ Create ChatOpenAI ───▶                         │                  │
    │  model=gpt-4o-mini     │                         │                  │
    │                        │                         │                  │
    │─ Define @tool          │                         │                  │
    │  pattern_scanner_tool()│                         │                  │
    │                        │                         │                  │
    │─ create_react_agent() ─▶                         │                  │
    │  (llm, tools)          │                         │                  │
    │                        │                         │                  │
    │─ agent.ainvoke() ──────▶                         │                  │
    │  {input: text,         │                         │                  │
    │   instructions: CISO prompt}                     │                  │
    │                        │                         │                  │
    │                        │─ Step 1: Thought        │                  │
    │                        │  "I should scan for     │                  │
    │                        │   PII patterns first"   │                  │
    │                        │                         │                  │
    │                        │─ Step 2: Action         │                  │
    │                        │  Use pattern_scanner_tool                  │
    │                        │                         │                  │
    │                        │─ call_tool() ──────────▶                  │
    │                        │  scan_patterns(text)    │                  │
    │                        │                         │                  │
    │                        │                         │─ Regex matching  │
    │                        │                         │  on text         │
    │                        │                         │                  │
    │                        │◀─ findings ─────────────│                  │
    │                        │  "Found: 2 emails,      │                  │
    │                        │   1 credit card"        │                  │
    │                        │                         │                  │
    │                        │─ Step 3: Observation    │                  │
    │                        │  "Tool found sensitive  │                  │
    │                        │   data patterns"        │                  │
    │                        │                         │                  │
    │                        │─ Step 4: Thought        │                  │
    │                        │  "Credit card = CRITICAL│                  │
    │                        │   Must analyze context" │                  │
    │                        │                         │                  │
    │                        │─ LLM Call ──────────────────────────────▶
    │                        │  System: CISO prompt    │                  │
    │                        │  Messages: [...reasoning]                  │
    │                        │                         │                  │
    │                        │◀─ AI Response ──────────────────────────────│
    │                        │  Analysis of risk       │                  │
    │                        │                         │                  │
    │                        │─ Step 5: Final Answer   │                  │
    │                        │  "VERDICT: BLOCK |      │                  │
    │                        │   CATEGORY: CRITICAL |  │                  │
    │                        │   REASON: Credit card   │                  │
    │                        │   detected..."          │                  │
    │                        │                         │                  │
    │◀─ {verdict, category, reason} ────────────────────────────────────│
    │                        │                         │                  │
```

**LangChain Components:**
- `ChatOpenAI`: LLM interface
- `create_react_agent`: ReAct (Reasoning + Acting) agent
- `@tool decorator`: Defines callable functions for agent
- Agent loop: Thought → Action → Observation → repeat until answer

---

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR UNIQUE NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    role VARCHAR NOT NULL,  -- ADMIN, ANALYST, VIEWER
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Scans Table
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash VARCHAR NOT NULL,
    risk_level VARCHAR NOT NULL,  -- LOW, MEDIUM, HIGH, CRITICAL
    verdict TEXT NOT NULL,
    findings_json TEXT,  -- JSON array of findings
    ai_analysis TEXT,
    scan_duration_ms INTEGER,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    scanned_by INTEGER,  -- Foreign key to users.id
    FOREIGN KEY (scanned_by) REFERENCES users(id)
);
```

**Indexes:**
- `idx_scans_scanned_at` on `scanned_at` (for sorting)
- `idx_scans_risk_level` on `risk_level` (for filtering)
- `idx_scans_scanned_by` on `scanned_by` (for user queries)

---

## 🔄 Component Interactions Summary

### 1. **Startup Sequence**
```
1. app/main.py lifespan starts
2. Create database tables (Base.metadata.create_all)
3. Start ICAP server in background (asyncio.create_task)
4. Initialize MCP client session (if using main.py MCP flow)
5. Build LangChain agent with tools
6. Store in app.state for request handlers
7. FastAPI ready to accept requests
```

### 2. **Request Processing Paths**

**Path A: API Endpoint**
```
HTTP Request → FastAPI Route → Auth Middleware → 
DLP Engine → Database Insert → JSON Response
```

**Path B: ICAP Proxy**
```
ICAP Request → ICAP Server → DLP Engine → 
Database Insert → ICAP Response (BLOCK/ALLOW)
```

### 3. **Data Flow**
```
Text Input → Regex Patterns → Findings →
AI Analysis (Optional) → Verdict → Database Record → Response
```

---

## 🧩 Key Technologies

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Web Framework | FastAPI | REST API, async support |
| ORM | SQLAlchemy | Database abstraction |
| Validation | Pydantic | Request/response schemas |
| AI/LLM | OpenAI GPT-4o-mini | Context-aware analysis |
| Agent Framework | LangChain | ReAct agent orchestration |
| Protocol | MCP (Model Context Protocol) | Tool calling interface |
| Database | SQLite | Persistent storage |
| Auth | JWT + bcrypt | Secure authentication |
| Networking | ICAP Protocol | Proxy integration |

---

## 🚀 Performance Considerations

### Caching Strategy
- Pattern regex compiled once at startup
- Database sessions pooled
- JWT tokens cached until expiry

### Async Operations
- All I/O is async (database, AI API calls)
- ICAP server handles multiple connections concurrently
- MCP tool calls are async

### Rate Limiting (Recommended)
- Add Redis-based rate limiting for API endpoints
- Throttle AI API calls to prevent cost overruns
- ICAP connection limits

---

## 🔐 Security Flow

### Authentication Chain
```
1. User login → credentials validated
2. Password hashed with bcrypt
3. JWT token generated (includes user_id, role, exp)
4. Token sent to client
5. Subsequent requests include: Authorization: Bearer <token>
6. Middleware validates JWT signature
7. Extract user context from token
8. Authorize based on role (RBAC)
```

### Data Protection
- Passwords: bcrypt hashed, never stored plain
- Secrets: Environment variables (.env)
- Database: Local SQLite (production should use PostgreSQL with TLS)
- API Keys: Never logged or returned in responses

---

## 📈 Monitoring & Logging

### What Gets Logged
```
✅ Scan requests (anonymized content hash)
✅ Risk levels detected
✅ AI analysis calls (no content logged)
✅ Authentication attempts
✅ ICAP connections
✅ Errors and exceptions
```

### What Doesn't Get Logged
```
❌ Raw scanned content (privacy)
❌ User passwords
❌ Full API keys
```

---

## 🎯 Optimization Opportunities

1. **Database Indexes**: Add composite indexes for common queries
2. **Connection Pooling**: Use SQLAlchemy pool_size and max_overflow
3. **Caching**: Redis for scan result caching (based on content hash)
4. **Batch Processing**: Queue scans for bulk processing
5. **AI Cost Control**: Implement token counting and budget limits

---

