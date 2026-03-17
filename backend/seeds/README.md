# Contexta Database Seed

Deterministic seed script that populates the database with realistic security operations data for demo and development purposes.

## What gets seeded

| Entity              | Count | Notes                                                    |
|---------------------|-------|----------------------------------------------------------|
| Network Topology    | 1     | 12 nodes, 15 edges — "Horizon Corp Primary Network"     |
| Assets              | 12    | Mapped 1:1 to topology nodes                             |
| Incidents           | 20    | Spread across last 30 days, mixed severities and statuses|
| CVEs                | 15    | Real CVE IDs with BWVS scores calculated at insert time  |
| Playbook Executions | 5     | Linked to incidents — completed, running, escalated, pending |
| Ledger Blocks       | ~30   | SHA-256 hash chain covering all seeded events            |

## Prerequisites

- PostgreSQL running with the `contexta` database created
- Database tables created (via Alembic or auto-migrate)
- Working directory: `backend/`

## Usage

```bash
# Navigate to the backend directory
cd backend

# First-time seed
python -m seeds.seed

# Force reseed (drops all seed data first, then re-inserts)
python -m seeds.seed --force

# Verify the ledger chain integrity without inserting anything
python -m seeds.seed --verify-only
```

## Idempotency

The script checks if any assets already exist in the database. If they do, it prints a message and exits unless `--force` is passed. With `--force`, all seeded entity types are deleted in reverse dependency order before re-inserting.

## BWVS Scores

CVE scores are **not hardcoded**. The script imports and uses the actual `BWVSCalculator` and `PriorityRanker` classes from `app.risk_engine`, ensuring scores match what the API would compute.

## Ledger Chain

Ledger blocks are inserted with a proper SHA-256 hash chain. After insertion the script verifies every block's hash and prev_hash. If verification fails, the script raises an exception and rolls back.
