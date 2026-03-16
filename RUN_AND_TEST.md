# Run and Test — Contexta

## Test suite (no database required)

From the repo root:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
pytest tests/ -v --tb=short
```

All 16 tests should pass (BWVS, ledger, twin, orchestrator).

## Backend with database

1. **Start PostgreSQL** (pick one):

   - Docker (if your environment supports it):
     ```bash
     docker run -d --name contexta-pg -p 5432:5432 \
       -e POSTGRES_USER=contexta -e POSTGRES_PASSWORD=contexta -e POSTGRES_DB=contexta \
       postgres:15-alpine
     ```
   - Or use a local Postgres 15+ and create database `contexta` and user `contexta`/password `contexta`.

2. **Configure and run backend**:

   ```bash
   cd backend
   cp .env.example .env
   # Edit .env and set DATABASE_URL if different; add GEMINI_API_KEY for agent analysis.
   source .venv/bin/activate
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Check**:

   - Health: `curl http://localhost:8000/health` → `{"status":"ok","db_connected":true,...}`
   - API docs: open http://localhost:8000/docs

## Full stack (backend + frontend)

- Terminal 1: start Postgres (see above), then backend (see above).
- Terminal 2:
  ```bash
  cd frontend
  npm install
  npm run dev
  ```
- Open http://localhost:3000. Set `NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1` in `.env.local` so the frontend talks to the backend.

## Docker Compose (when Docker networking works)

From repo root:

```bash
cp backend/.env.example backend/.env
docker compose up -d
# Backend: http://localhost:8000  |  Docs: http://localhost:8000/docs
# Postgres: localhost:5432
```
