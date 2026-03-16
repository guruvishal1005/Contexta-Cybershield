# Frontend-Backend Gap Report — Contexta
Generated: 2026-03-15
Build: Hackathon — no auth, no Redis

## Summary
| Metric | Count |
|--------|-------|
| Total frontend API calls found | 18 |
| Fully connected + schema matching | 12 |
| Schema mismatches | 3 |
| Missing backend endpoints | 2 |
| Placeholders needing backend | 7 |
| Auth components (intentionally unwired) | 3 |
| Missing frontend components for backend features | 6 |

## Missing backend endpoints

| Frontend call | File | Expected method+path | Response shape |
|---|---|---|---|
| ML Health GET | `components/ContexaSOC.jsx:805` | `GET /api/ml/health` | `{status, model_version, accuracy, f1Score, auc, drift, note, series}` |
| Agent analysis (hardcoded URL) | `components/RisksView.tsx:343` | `POST /api/agents/analyze/demo?risk_title=...&agents=...` | `{discussion: AgentMessage[]}` |

**Notes:**
- The backend route prefix is `/api/v1/`, but `ContexaSOC.jsx` and `RisksView.tsx` call `/api/agents/analyze/demo` and `/api/ml/health` directly (no `/v1/` prefix). Fix: update frontend hardcoded URLs to use `/api/v1/` prefix, or add a redirect/alias at the backend.
- ML Health endpoint is not in the new spec (no ML microservice). Consider adding a stub `GET /api/v1/ml/health` returning static metrics, or update the frontend to remove the call.
- Agent analysis endpoint exists at `POST /api/v1/incidents/{id}/analyze` but the frontend calls a different path (`/api/agents/analyze/demo`). Consider adding a compatibility alias or updating the frontend.

## Schema mismatches

| Endpoint | Frontend field | Frontend type | Backend field | Backend type | Fix |
|---|---|---|---|---|---|
| `GET /risks/top10` | `risks` (wrapper) | `TopRisksResponse.risks: Risk[]` | Top-level array | `list[CVEOut]` | Frontend expects `{risks: [...]}` but backend returns `[...]`. Wrap backend response or update frontend hook. |
| Assets list | `vulnerabilitiesCount` | `number` | N/A | Not in Asset model | Backend Asset model uses `criticality: int` instead. Remove field from frontend type or add to backend. |
| Incidents list | `incidentType` | `string` | N/A | Not in Incident model | Backend uses `source` field. Map or rename in frontend. |

## Placeholders needing backend

| Component | Description | Endpoint to wire |
|---|---|---|
| `components/ContexaSOC.jsx` — `genThreat()` | Random threat generator | `GET /api/v1/dashboard/recent-activity` |
| `components/ContexaSOC.jsx` — `genCVE()` | Random CVE generator | `GET /api/v1/risks/cves` |
| `components/ContexaSOC.jsx` — `genBlock()` | Random blockchain block generator | `GET /api/v1/ledger/chain` |
| `components/ContexaSOC.jsx` — `STATIC_ML_HEALTH` | Static ML health metrics | Stub `GET /api/v1/ml/health` if needed |
| `components/ContexaSOC.jsx` — inline playbooks | Hardcoded 4 playbook objects | `GET /api/v1/playbooks` |
| `components/ReportsView.tsx` | Fully hardcoded charts and data | `GET /api/v1/dashboard/incident-trend`, `GET /api/v1/dashboard/severity-distribution` |
| `components/ExecutiveView.tsx` | Fully hardcoded KPI and executive data | `GET /api/v1/executive/summary`, `GET /api/v1/executive/kpis` |

## Auth components — intentionally unwired

| Component/File | What it does | Status |
|---|---|---|
| `app/login/page.tsx` | Login form with email/password, demo login button | Unwired — no auth in backend. Direct fetch to `/auth/login` will 404. Intentional. |
| `contexts/AuthContext.tsx` | Manages user state, login/register/logout/refreshUser | Unwired — `authApi` methods target non-existent auth endpoints. AuthProvider is not mounted in layout. Intentional. |
| `lib/api/index.ts` — `authApi` | API client for auth endpoints (login, register, getMe, logout) | Unwired — backend has no auth routes. Intentional. |

## Missing frontend components

| Backend capability | Suggested component | Priority |
|---|---|---|
| `POST /api/v1/incidents/{id}/analyze` — Full multi-agent analysis pipeline | IncidentAnalysisPanel — trigger analysis and display agent outputs | High |
| `GET /api/v1/incidents/{id}/timeline` — Blockchain audit trail | IncidentTimeline — chronological ledger events | High |
| `POST /api/v1/twin/simulate` — BFS/DFS/Blast/Lateral simulations | SimulationPanel — run simulations with type selector | High |
| `GET /api/v1/ledger/chain` + `GET /api/v1/ledger/verify` — Full audit chain | LedgerView — paginated chain browser with integrity verification | Medium |
| `GET /api/v1/dashboard/risk-heatmap` — Asset risk heatmap | RiskHeatmap — visual heatmap of asset risk scores | Medium |
| `GET /api/v1/assets/{id}/risk` — Per-asset risk score | AssetRiskBadge — inline risk indicator on asset cards | Low |

## Environment variable mapping

| Frontend variable | In backend .env.example? | Notes |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | N/A (frontend only) | Points to `http://localhost:8000/api/v1` |
| `NEXT_PUBLIC_API_BASE_URL` | N/A (frontend only) | Defined in .env.example but unused in code |
| `NEXT_PUBLIC_TOKEN_KEY` | N/A (frontend only) | Token storage key — auth is disabled |
| `NEXT_PUBLIC_REFRESH_TOKEN_KEY` | N/A (frontend only) | Refresh token key — auth is disabled |
| `NEXT_PUBLIC_MODEL_HEALTH_API` | Not in backend | ML health endpoint — no backend equivalent in spec |
| `DATABASE_URL` | Yes | Backend only |
| `GEMINI_API_KEY` | Yes | Backend only |
| `CVE_COLLECTION_INTERVAL_HOURS` | Yes | Backend only |
