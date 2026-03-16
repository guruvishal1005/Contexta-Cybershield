# Contexta — SOC Platform

Contexta is an enterprise Security Operations Centre (SOC) platform with AI-powered multi-agent threat analysis (Google Gemini), Business-Weighted Vulnerability Score (BWVS), Digital Twin network simulation, blockchain audit ledger, playbook-driven incident response, and CVE intelligence from CISA KEV and NVD.

**Stack:** Backend (FastAPI, PostgreSQL, SQLAlchemy 2.0 async, NetworkX, APScheduler) · Frontend (Next.js 14, React, TypeScript, Tailwind)

---

## Prerequisites

| Requirement | Version / notes |
|-------------|------------------|
| **Python** | 3.11+ |
| **Node.js** | 18+ (for frontend) |
| **PostgreSQL** | 15+ |
| **Docker** (optional) | For running Postgres and/or the full stack |

---

## Repository structure

```
Cybershield/
├── backend/                 # FastAPI application
│   ├── app/
│   │   ├── api/             # Route handlers (incidents, risks, twin, ledger, playbooks, assets, dashboard)
│   │   ├── agents/          # Gemini SOC agents + orchestrator
│   │   ├── risk_engine/     # BWVS calculator, priority ranker
│   │   ├── twin/            # Digital Twin (NetworkX)
│   │   ├── ledger/          # Blockchain audit chain
│   │   ├── ingestion/       # CVE collector (CISA + NVD)
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Pydantic schemas
│   │   └── services/        # Incident, playbook, asset services
│   ├── playbooks/           # JSON playbook definitions
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── frontend/                # Next.js 14 app
│   ├── app/
│   ├── components/
│   ├── lib/api/             # API client
│   └── .env.example
├── docker-compose.yml       # Postgres + backend
├── FRONTEND_BACKEND_GAPS.md # API/frontend alignment report
└── README.md
```

---

## Quick start (Docker Compose)

From the **repository root**:

```bash
# 1. Copy backend env and add your Gemini key if you want agent analysis
cp backend/.env.example backend/.env

# 2. Start Postgres and backend
docker compose up -d

# 3. Backend: http://localhost:8000  |  API docs: http://localhost:8000/docs
#    Postgres: localhost:5432 (user: contexta, password: contexta, db: contexta)
```

Then run the frontend locally (see [Frontend](#frontend) below).

---

## Setup and run (manual)

### 1. PostgreSQL

Create a database and user (or use Docker):

```bash
# Example: run Postgres in Docker
docker run -d --name contexta-pg -p 5432:5432 \
  -e POSTGRES_USER=contexta \
  -e POSTGRES_PASSWORD=contexta \
  -e POSTGRES_DB=contexta \
  postgres:15-alpine
```

Or install Postgres 15+ locally and create:

- Database: `contexta`
- User: `contexta` / Password: `contexta` (or set `DATABASE_URL` accordingly)

---

### 2. Backend

```bash
cd backend

# Virtual environment and dependencies
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Environment
cp .env.example .env
# Edit .env: set DATABASE_URL if needed; set GEMINI_API_KEY for AI agent analysis.

# Run
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Verify:**

- Health: `curl http://localhost:8000/health`
- API docs: open **http://localhost:8000/docs**

**Backend env vars** (see `backend/.env.example`):

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | `postgresql+asyncpg://user:pass@host:5432/contexta` |
| `GEMINI_API_KEY` | Google Gemini API key (for SOC agents) |
| `CVE_COLLECTION_INTERVAL_HOURS` | CVE sync interval (default: 6) |
| `LOG_LEVEL` | DEBUG, INFO, WARNING, ERROR |
| `ENVIRONMENT` | development or production |

---

### 3. Frontend

```bash
cd frontend

# Dependencies
npm install

# Environment: point to backend API
cp .env.example .env.local
# Ensure .env.local has: NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1

# Run
npm run dev
```

Open **http://localhost:3000**.

**Frontend env** (see `frontend/.env.example`):

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_API_URL` | Backend API base, e.g. `http://localhost:8000/api/v1` |
| `NEXT_PUBLIC_API_BASE_URL` | Backend root, e.g. `http://localhost:8000` |
| `NEXT_PUBLIC_TOKEN_KEY` | LocalStorage key for access token (auth is optional in this build) |
| `NEXT_PUBLIC_REFRESH_TOKEN_KEY` | LocalStorage key for refresh token |

---

## Running tests

Backend tests (no database required for the current suite):

```bash
cd backend
source .venv/bin/activate
pytest tests/ -v --tb=short
```

Expected: **16 tests** (BWVS, ledger, Digital Twin, orchestrator).

---

## API overview

| Area | Base path | Examples |
|------|-----------|----------|
| Health | `/health` | `GET /health` |
| Incidents | `/api/v1/incidents` | CRUD, `POST …/analyze`, `GET …/timeline` |
| Risks / CVEs | `/api/v1/risks` | `GET /top10`, `GET /summary`, `GET /cves`, `POST /calculate` |
| Digital Twin | `/api/v1/twin` | `GET /topology`, `POST /simulate` |
| Ledger | `/api/v1/ledger` | `GET /chain`, `GET /verify`, `GET /events/{id}` |
| Playbooks | `/api/v1/playbooks` | List, execute, executions, step complete |
| Assets | `/api/v1/assets` | CRUD, `GET …/incidents`, `GET …/risk` |
| Dashboard | `/api/v1/dashboard` | summary, incident-trend, severity-distribution, recent-activity, risk-heatmap |
| Executive | `/api/v1/executive` | summary, kpis |

Interactive docs: **http://localhost:8000/docs** when the backend is running.

---

## Optional: Auth and frontend gaps

- **Auth:** This build has no backend auth. The frontend login/auth context is present but not wired to real auth; see `FRONTEND_BACKEND_GAPS.md` for details.
- **Frontend–backend alignment:** Endpoints, schemas, and placeholders are documented in **`FRONTEND_BACKEND_GAPS.md`**.

---

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| Backend won’t start | Postgres running? `DATABASE_URL` correct? Port 8000 free? |
| `Connection refused` to DB | Start Postgres; ensure host/port/user/password/db name match `DATABASE_URL`. |
| Frontend 404/422 to API | Backend running? `NEXT_PUBLIC_API_URL` is `http://localhost:8000/api/v1` (with `/api/v1`). |
| Agent analysis fails | Set `GEMINI_API_KEY` in `backend/.env`. |
| Docker networking errors | Try running Postgres and backend manually (see [Setup and run](#setup-and-run-manual)). |

For more run/test options (e.g. run script, test DB), see **`RUN_AND_TEST.md`**.
