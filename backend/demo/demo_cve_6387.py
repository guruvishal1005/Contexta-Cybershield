"""
CVE-2024-6387 (regreSSHion) — Live Demo Script
================================================
Run from the backend/ directory:

    python -m demo.demo_cve_6387

Requires: the backend running on localhost:8000 and the seed data loaded.
"""

import sys
import time
import json

import httpx

BASE = "http://localhost:8000"
API = f"{BASE}/api/v1"
CVE_ID = "CVE-2024-6387"
TIMEOUT = 120.0

C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


def header(step: int, title: str):
    print(f"\n{'═' * 60}")
    print(f"{C_BOLD}{C_CYAN}  STEP {step} — {title}{C_RESET}")
    print(f"{'═' * 60}")


def ok(msg: str):
    print(f"  {C_GREEN}✓{C_RESET} {msg}")


def warn(msg: str):
    print(f"  {C_YELLOW}⚠{C_RESET} {msg}")


def fail(msg: str):
    print(f"  {C_RED}✗{C_RESET} {msg}")


def main():
    client = httpx.Client(timeout=TIMEOUT)

    # ── STEP 1: Health check ────────────────────────────────────────────
    header(1, "Health check")
    try:
        r = client.get(f"{BASE}/health")
    except httpx.ConnectError:
        fail("Cannot connect to the backend at localhost:8000.")
        fail("Start it with:  cd backend && uvicorn app.main:app --port 8000 --reload")
        sys.exit(1)

    if r.status_code != 200:
        fail(f"Backend returned {r.status_code}. Is it healthy?")
        sys.exit(1)

    data = r.json()
    ok(f"Backend is up — DB connected: {data.get('db_connected')}")
    ok(f"Ledger block count: {data.get('ledger_block_count', '?')}")
    ok(f"Uptime: {data.get('uptime_seconds', '?')}s")
    time.sleep(1)

    # ── STEP 2: Check if CVE already exists ─────────────────────────────
    header(2, f"Check if {CVE_ID} already exists")
    r = client.get(f"{API}/risks/cves/{CVE_ID}")
    cve_existed = r.status_code == 200
    if cve_existed:
        cve_data = r.json()
        warn(f"{CVE_ID} already exists (BWVS: {cve_data.get('bwvsScore', '?')}). Skipping creation.")
    else:
        ok(f"{CVE_ID} not found — will create in Step 3.")
    time.sleep(1)

    # ── STEP 3: Create CVE-2024-6387 ───────────────────────────────────
    header(3, f"Create {CVE_ID}")
    if cve_existed:
        warn("Skipped — CVE already exists from a previous run.")
    else:
        payload = {
            "id": CVE_ID,
            "description": (
                "Race condition in OpenSSH's sshd signal handler on glibc-based Linux "
                "systems allows unauthenticated remote code execution as root. "
                "Regression of CVE-2006-5051, hence the name 'regreSSHion'."
            ),
            "cvssScore": 8.1,
            "cvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epssScore": 0.68,
            "isKev": False,
            "exploitAvailable": True,
            "exploitMaturity": "proof-of-concept",
            "publishedDate": "2024-07-01T00:00:00Z",
            "affectedProducts": {
                "vendor": "OpenBSD",
                "product": "OpenSSH",
                "versions_affected": "< 4.4p1 and 8.5p1 <= version < 9.8p1",
            },
            "cweIds": {"primary": "CWE-362"},
        }
        r = client.post(f"{API}/risks/cves", json=payload)
        if r.status_code == 201:
            cve_data = r.json()
            bwvs = cve_data.get("bwvsScore", "?")
            ok(f"Created {CVE_ID}")
            ok(f"BWVS score: {bwvs}  |  Risk level: {cve_data.get('riskLevel', '?')}")
            print()
            print(f"  {C_YELLOW}Key talking point:{C_RESET}")
            print(f"    CVSS alone says 8.1 (High) — network-exploitable RCE as root.")
            print(f"    But BWVS gives {bwvs} because it factors in that the exploit")
            print(f"    is still at proof-of-concept stage (not weaponised) and uses")
            print(f"    default asset context. This is why BWVS > raw CVSS for prioritisation.")
        elif r.status_code == 409:
            warn("CVE already exists (409). Continuing.")
        else:
            fail(f"Failed to create CVE: {r.status_code} — {r.text}")
            sys.exit(1)
    time.sleep(1)

    # ── STEP 4: Find the Application Server asset ──────────────────────
    header(4, "Find the Application Server asset")
    r = client.get(f"{API}/assets", params={"limit": 100})
    if r.status_code != 200:
        fail(f"Failed to list assets: {r.status_code}")
        sys.exit(1)

    assets = r.json().get("items", [])
    app_server = None
    for a in assets:
        if a.get("name") == "Application Server":
            app_server = a
            break

    if not app_server:
        fail("Asset 'Application Server' not found.")
        fail("Run the seed script first:  cd backend && python -m seeds.seed")
        sys.exit(1)

    asset_id = app_server["id"]
    ok(f"Found: {app_server['name']}  (ID: {asset_id})")
    ok(f"Criticality: {app_server.get('criticality', '?')}  |  Internet-facing: {app_server.get('isInternetFacing', '?')}")
    time.sleep(1)

    # ── STEP 5: Create the incident ────────────────────────────────────
    header(5, "Create incident — regreSSHion exploit attempt")
    incident_payload = {
        "title": "CVE-2024-6387 regreSSHion exploit attempt on Application Server",
        "description": (
            "Anomalous SSH connection pattern detected on port 22 of the Application "
            "Server (192.168.2.10). 10,000 connection attempts over 120 seconds with "
            "timing characteristics consistent with the regreSSHion race condition exploit "
            "(CVE-2024-6387 / CVE-2006-5051 regression)."
        ),
        "severity": "high",
        "status": "open",
        "source": "siem",
        "assetId": asset_id,
        "rawLog": {
            "src_ip": "45.33.32.156",
            "dst_ip": "192.168.2.10",
            "dst_port": 22,
            "protocol": "ssh",
            "connection_attempts": 10000,
            "timespan_seconds": 120,
            "timing_anomaly": "signal_handler_race_pattern",
            "failed_auths": 9997,
            "alert_rule": "CVE_2024_6387_REGRESSHION",
            "cve_reference": "CVE-2024-6387",
            "openssh_version_detected": "OpenSSH_9.2p1",
            "is_vulnerable_version": True,
        },
    }
    r = client.post(f"{API}/incidents", json=incident_payload)
    if r.status_code != 201:
        fail(f"Failed to create incident: {r.status_code} — {r.text}")
        sys.exit(1)

    incident = r.json()
    incident_id = incident["id"]
    ok(f"Incident created: {incident_id}")
    ok(f"Severity: {incident.get('severity', '?').upper()}  |  Status: {incident.get('status', '?')}")
    print(f"\n  {C_YELLOW}Note this ID for the dashboard → {C_BOLD}{incident_id}{C_RESET}")
    time.sleep(1)

    # ── STEP 6: Trigger multi-agent analysis ───────────────────────────
    header(6, "Trigger multi-agent analysis")
    print(f"  Launching 5 AI agents simultaneously:")
    print(f"    {C_CYAN}Analyst{C_RESET}    — threat classification, IOCs, MITRE mapping")
    print(f"    {C_CYAN}Intel{C_RESET}      — CVE correlation, threat actor attribution")
    print(f"    {C_CYAN}Forensics{C_RESET}  — timeline reconstruction, lateral movement")
    print(f"    {C_CYAN}Business{C_RESET}   — financial impact, compliance risk")
    print(f"    {C_CYAN}Response{C_RESET}   — containment actions, playbook recommendation")
    print()
    print(f"  {C_YELLOW}Running analysis... (15–30 seconds){C_RESET}")

    r = client.post(f"{API}/incidents/{incident_id}/analyze", timeout=TIMEOUT)
    if r.status_code != 200:
        fail(f"Analysis failed: {r.status_code} — {r.text[:300]}")
        sys.exit(1)

    analysis = r.json()
    consensus = analysis.get("consensus") or {}
    blast = analysis.get("blastRadius") or {}

    print()
    ok("Analysis complete!")
    print()
    print(f"  ┌─────────────────────────────────────────────────────┐")
    print(f"  │  {C_BOLD}BWVS Score:{C_RESET}       {analysis.get('bwvsScore', '?'):<10}                     │")
    print(f"  │  {C_BOLD}Consensus:{C_RESET}        {consensus.get('severity', '?'):<10}                     │")
    print(f"  │  {C_BOLD}Confidence:{C_RESET}       {consensus.get('confidence', '?')}                        │")
    print(f"  └─────────────────────────────────────────────────────┘")

    techniques = consensus.get("mitre_techniques") or consensus.get("mitreTechniques") or []
    if techniques:
        print(f"\n  MITRE ATT&CK: {', '.join(techniques[:3])}")

    iocs = consensus.get("merged_iocs") or consensus.get("mergedIocs") or []
    if iocs:
        print(f"  IOCs ({len(iocs)} total): {', '.join(i.get('value', '?') for i in iocs[:2])}")

    if blast:
        affected = blast.get("affected_nodes") or blast.get("affectedNodes") or []
        critical = [n for n in affected if (n.get("criticality") or 0) >= 8]
        print(f"  Blast radius: {len(affected)} nodes reachable, {len(critical)} critical")

    narrative = consensus.get("consensus_narrative") or consensus.get("consensusNarrative") or ""
    if narrative:
        print(f"\n  {C_BOLD}Narrative:{C_RESET}")
        print(f"  {narrative[:400]}{'...' if len(narrative) > 400 else ''}")

    print(f"\n{'═' * 60}")
    print(f"{C_BOLD}{C_GREEN}  DEMO COMPLETE{C_RESET}")
    print(f"{'═' * 60}")
    print(f"  Incident ID: {C_BOLD}{incident_id}{C_RESET}")
    print(f"  Dashboard:   {C_BOLD}http://localhost:3000{C_RESET}")
    print(f"  API docs:    {C_BOLD}http://localhost:8000/docs{C_RESET}")
    print()


if __name__ == "__main__":
    main()
