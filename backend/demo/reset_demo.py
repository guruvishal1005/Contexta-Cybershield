"""
Reset the CVE-2024-6387 demo — removes all demo-created data.
Run from the backend/ directory:

    python -m demo.reset_demo
"""

import sys
import httpx

BASE = "http://localhost:8000"
API = f"{BASE}/api/v1"
CVE_ID = "CVE-2024-6387"

C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


def ok(msg: str):
    print(f"  {C_GREEN}✓{C_RESET} {msg}")


def warn(msg: str):
    print(f"  {C_YELLOW}⚠{C_RESET} {msg}")


def fail(msg: str):
    print(f"  {C_RED}✗{C_RESET} {msg}")


def main():
    client = httpx.Client(timeout=15.0)

    print(f"\n{C_BOLD}Resetting CVE-2024-6387 demo...{C_RESET}\n")

    # Health check
    try:
        r = client.get(f"{BASE}/health")
        if r.status_code != 200:
            fail("Backend is not healthy.")
            sys.exit(1)
    except httpx.ConnectError:
        fail("Cannot connect to backend at localhost:8000.")
        fail("Start it first:  cd backend && uvicorn app.main:app --port 8000 --reload")
        sys.exit(1)

    # Find and delete incidents matching the demo
    r = client.get(f"{API}/incidents", params={"limit": 100})
    if r.status_code == 200:
        incidents = r.json().get("items", [])
        demo_incidents = [
            i for i in incidents
            if "CVE-2024-6387" in (i.get("title") or "") or "regreSSHion" in (i.get("title") or "")
        ]
        if demo_incidents:
            for inc in demo_incidents:
                inc_id = inc["id"]
                dr = client.delete(f"{API}/incidents/{inc_id}")
                if dr.status_code == 204:
                    ok(f"Deleted incident: {inc.get('title', inc_id)[:60]}")
                else:
                    warn(f"Could not delete incident {inc_id}: {dr.status_code}")
        else:
            ok("No demo incidents found — already clean.")
    else:
        warn(f"Could not list incidents: {r.status_code}")

    # Delete the CVE
    r = client.delete(f"{API}/risks/cves/{CVE_ID}")
    if r.status_code == 204:
        ok(f"Deleted {CVE_ID}")
    elif r.status_code == 404:
        ok(f"{CVE_ID} not found — already clean.")
    else:
        warn(f"Could not delete {CVE_ID}: {r.status_code}")

    print(f"\n{C_BOLD}{C_GREEN}  Demo reset complete — ready for next run.{C_RESET}\n")


if __name__ == "__main__":
    main()
