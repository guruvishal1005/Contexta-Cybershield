"""
CVE-2024-6387 Full Demo — Reset → Run → Verify → Highlight
=============================================================
Single command:

    cd backend && python -m demo.full_demo

Cleans any previous demo traces, runs the entire CVE-2024-6387
(regreSSHion) flow, and prints all key talking points.
"""

import sys
import time
import json
from datetime import datetime, timezone
import httpx

BASE = "http://localhost:8000"
API = f"{BASE}/api/v1"
CVE_ID = "CVE-2024-6387"
TIMEOUT = 120.0

# ANSI colours
G = "\033[92m"   # green
Y = "\033[93m"   # yellow
R = "\033[91m"   # red
C = "\033[96m"   # cyan
M = "\033[95m"   # magenta
B = "\033[1m"    # bold
D = "\033[2m"    # dim
X = "\033[0m"    # reset


def banner(text: str):
    w = 64
    print(f"\n{B}{C}{'━' * w}")
    print(f"  {text}")
    print(f"{'━' * w}{X}")


def step(n: int, title: str):
    print(f"\n{B}{M}{'─' * 64}")
    print(f"  STEP {n} │ {title}")
    print(f"{'─' * 64}{X}")


def ok(msg: str):
    print(f"  {G}✓{X} {msg}")


def warn(msg: str):
    print(f"  {Y}⚠{X} {msg}")


def fail(msg: str):
    print(f"  {R}✗{X} {msg}")


def point(msg: str):
    print(f"  {Y}★ HIGHLIGHT:{X} {msg}")


def detail(label: str, value):
    print(f"    {D}├─{X} {B}{label}:{X} {value}")


def main():
    client = httpx.Client(timeout=TIMEOUT)

    banner("CVE-2024-6387 (regreSSHion) — FULL DEMO")
    print(f"  This script will: clean previous traces → create CVE →")
    print(f"  create incident → run 5 AI agents → verify ledger →")
    print(f"  check risk ranking → query ML service")

    # ══════════════════════════════════════════════════════════════
    # PHASE 1: RESET
    # ══════════════════════════════════════════════════════════════
    step(0, "RESET — Cleaning previous demo traces")

    try:
        r = client.get(f"{BASE}/health")
        if r.status_code != 200:
            fail("Backend is not healthy.")
            sys.exit(1)
    except httpx.ConnectError:
        fail("Cannot connect to backend at localhost:8000")
        fail("Start it:  cd backend && uvicorn app.main:app --port 8000 --reload")
        sys.exit(1)

    ok("Backend is reachable")

    r = client.get(f"{API}/incidents", params={"limit": 100})
    cleaned = 0
    if r.status_code == 200:
        incidents = r.json().get("items", [])
        for inc in incidents:
            title = inc.get("title") or ""
            if "CVE-2024-6387" in title or "regreSSHion" in title:
                dr = client.delete(f"{API}/incidents/{inc['id']}")
                if dr.status_code == 204:
                    ok(f"Removed incident: {title[:55]}")
                    cleaned += 1

    r = client.delete(f"{API}/risks/cves/{CVE_ID}")
    if r.status_code == 204:
        ok(f"Removed {CVE_ID}")
        cleaned += 1
    elif r.status_code == 404:
        ok(f"{CVE_ID} not present — clean slate")

    if cleaned == 0:
        ok("Nothing to clean — fresh start")
    else:
        ok(f"Cleaned {cleaned} item(s)")

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 2: HEALTH & ML STATUS
    # ══════════════════════════════════════════════════════════════
    step(1, "PLATFORM HEALTH CHECK")

    r = client.get(f"{BASE}/health")
    h = r.json()
    detail("Database", f"{'Connected' if h.get('db_connected') else 'DISCONNECTED'}")
    detail("Ledger blocks", h.get("ledger_block_count", "?"))
    detail("Uptime", f"{h.get('uptime_seconds', '?')}s")

    point("Platform health shows DB connection, blockchain ledger integrity,")
    print(f"           and uptime — proving the system is production-ready.")

    ml_status = "unavailable"
    try:
        r = client.get(f"{BASE}/api/ml/health")
        if r.status_code == 200:
            ml = r.json()
            ml_status = ml.get("status", "unknown")
            detail("ML Service", f"{ml.get('note', ml_status)}")
            detail("ML Accuracy", f"{ml.get('accuracy', '?')}  |  F1: {ml.get('f1Score', '?')}  |  AUC: {ml.get('auc', '?')}")
            point("ML microservice uses LSTM Autoencoder + Isolation Forest ensemble")
            print(f"           trained on CIC-IDS2017 network flow data.")
    except Exception:
        warn("ML service not reachable — demo continues without ML scoring")

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 3: CREATE CVE
    # ══════════════════════════════════════════════════════════════
    step(2, f"CREATE {CVE_ID} (regreSSHion)")

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
        "publishedDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "affectedProducts": {
            "vendor": "OpenBSD",
            "product": "OpenSSH",
            "versions_affected": "< 4.4p1 and 8.5p1 <= version < 9.8p1",
        },
        "cweIds": {"primary": "CWE-362"},
    }

    r = client.post(f"{API}/risks/cves", json=payload)
    if r.status_code == 201:
        cve = r.json()
        bwvs = cve.get("bwvsScore", "?")
        risk = cve.get("riskLevel", "?")
        ok(f"Created {CVE_ID}")
        detail("CVSS Score", "8.1 (High) — network-exploitable, no auth required, RCE as root")
        detail("EPSS Score", "0.68 — 68% probability of exploitation in the wild")
        detail("BWVS Score", f"{bwvs} ({risk})")
        detail("Exploit Maturity", "proof-of-concept (not yet weaponised)")
        print()
        point("BWVS differs from raw CVSS because it factors in exploit maturity,")
        print(f"           asset criticality, and business impact — giving a more accurate")
        print(f"           prioritisation signal than CVSS alone.")
        point(f"CVSS says 8.1, but BWVS says {bwvs} — showing context-aware scoring.")
    elif r.status_code == 409:
        warn(f"{CVE_ID} already exists. Continuing.")
    else:
        fail(f"Failed: {r.status_code} — {r.text[:200]}")
        sys.exit(1)

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 4: FIND ASSET
    # ══════════════════════════════════════════════════════════════
    step(3, "IDENTIFY TARGET ASSET")

    r = client.get(f"{API}/assets", params={"limit": 100})
    if r.status_code != 200:
        fail(f"Cannot list assets: {r.status_code}")
        sys.exit(1)

    assets = r.json().get("items", [])
    app_server = next((a for a in assets if a.get("name") == "Application Server"), None)

    if not app_server:
        fail("Asset 'Application Server' not found. Run seed:  python -m seeds.seed")
        sys.exit(1)

    asset_id = app_server["id"]
    ok(f"Target: {app_server['name']}")
    detail("Asset ID", asset_id)
    detail("Criticality", f"{app_server.get('criticality', '?')}/10")
    detail("Internet-facing", app_server.get("isInternetFacing", "?"))
    detail("Type", app_server.get("type", "?"))

    point("The Application Server has criticality 8/10 — it hosts the main")
    print(f"           business application. Being internal (not internet-facing) lowers")
    print(f"           the exposure factor in BWVS, but its high criticality keeps the score up.")

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 5: CREATE INCIDENT
    # ══════════════════════════════════════════════════════════════
    step(4, "SIMULATE ATTACK — Create regreSSHion incident")

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
        fail(f"Failed: {r.status_code} — {r.text[:200]}")
        sys.exit(1)

    incident = r.json()
    incident_id = incident["id"]
    ok(f"Incident created")
    detail("Incident ID", incident_id)
    detail("Severity", incident.get("severity", "?").upper())
    detail("Source", "SIEM alert (automated detection)")
    detail("Attack", "10,000 SSH attempts in 120s with race-condition timing pattern")
    detail("Attacker IP", "45.33.32.156")
    detail("Target", "192.168.2.10:22 (OpenSSH 9.2p1 — vulnerable version)")

    point("The raw log contains realistic SIEM telemetry: 10,000 connection")
    print(f"           attempts, signal_handler_race_pattern timing anomaly, and a")
    print(f"           confirmed vulnerable OpenSSH version (9.2p1 < 9.8p1).")
    point("This incident was auto-recorded on the immutable blockchain ledger.")

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 6: MULTI-AGENT AI ANALYSIS
    # ══════════════════════════════════════════════════════════════
    step(5, "MULTI-AGENT AI ANALYSIS (5 specialists)")

    print(f"\n  Deploying five AI agents simultaneously:\n")
    agents = [
        ("Analyst",   "Threat classification, IOC extraction, MITRE ATT&CK mapping"),
        ("Intel",     "CVE correlation, threat actor attribution, campaign tracking"),
        ("Forensics", "Timeline reconstruction, lateral movement analysis"),
        ("Business",  "Financial impact estimation, compliance risk, SLA exposure"),
        ("Response",  "Containment actions, playbook recommendation, remediation plan"),
    ]
    for name, desc in agents:
        print(f"    {C}▸ {name:12s}{X} {D}{desc}{X}")

    print(f"\n  {Y}⏳ Running analysis... this takes 15–45 seconds{X}")

    t0 = time.time()
    r = client.post(f"{API}/incidents/{incident_id}/analyze", timeout=TIMEOUT)
    elapsed = time.time() - t0

    if r.status_code != 200:
        fail(f"Analysis failed: {r.status_code} — {r.text[:300]}")
        warn("This may be due to Gemini API quota. The demo data is still valid.")
        print(f"\n  {D}You can still view the incident on the dashboard:{X}")
        print(f"  {B}http://localhost:3000{X}")
    else:
        analysis = r.json()
        consensus = analysis.get("consensus") or {}
        blast = analysis.get("blastRadius") or {}

        ok(f"Analysis complete in {elapsed:.1f}s")

        print(f"\n  {B}┌{'─' * 58}┐{X}")
        print(f"  {B}│  CONSENSUS RESULTS                                       │{X}")
        print(f"  {B}├{'─' * 58}┤{X}")
        print(f"  {B}│{X}  BWVS Score:       {B}{str(analysis.get('bwvsScore', '?')):<38}{X}{B}│{X}")
        print(f"  {B}│{X}  Severity:         {B}{str(consensus.get('severity', '?')).upper():<38}{X}{B}│{X}")
        print(f"  {B}│{X}  Confidence:       {B}{str(consensus.get('confidence', '?')):<38}{X}{B}│{X}")
        print(f"  {B}│{X}  Analysis Time:    {B}{f'{elapsed:.1f}s':<38}{X}{B}│{X}")
        print(f"  {B}└{'─' * 58}┘{X}")

        techniques = consensus.get("mitre_techniques") or consensus.get("mitreTechniques") or []
        if techniques:
            print(f"\n    {B}MITRE ATT&CK:{X} {', '.join(techniques[:5])}")

        iocs = consensus.get("merged_iocs") or consensus.get("mergedIocs") or []
        if iocs:
            print(f"    {B}IOCs found:{X} {len(iocs)}")
            for ioc in iocs[:3]:
                print(f"      {C}•{X} {ioc.get('type', '?')}: {ioc.get('value', '?')}")

        if blast:
            affected = blast.get("affected_nodes") or blast.get("affectedNodes") or []
            critical = [n for n in affected if (n.get("criticality") or 0) >= 8]
            print(f"    {B}Blast Radius:{X} {len(affected)} nodes reachable, {R}{len(critical)} critical{X}")

        narrative = consensus.get("consensus_narrative") or consensus.get("consensusNarrative") or ""
        if narrative:
            print(f"\n    {B}Consensus Narrative:{X}")
            lines = narrative[:500].split(". ")
            for line in lines[:4]:
                if line.strip():
                    print(f"    {D}▸{X} {line.strip()}.")

        print()
        point("Five AI agents ran in parallel using Gemini, each with a different")
        print(f"           security perspective. The consensus merges all five views into")
        print(f"           a unified assessment with MITRE mapping, IOCs, and blast radius.")
        point("The Digital Twin simulated attack propagation through the network")
        print(f"           graph to calculate blast radius — showing which nodes are reachable")
        print(f"           from the compromised Application Server.")

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 7: VERIFY LEDGER
    # ══════════════════════════════════════════════════════════════
    step(6, "BLOCKCHAIN AUDIT LEDGER — Verify integrity")

    r = client.get(f"{API}/ledger/chain", params={"limit": 10})
    if r.status_code == 200:
        blocks = r.json()
        if isinstance(blocks, dict):
            blocks = blocks.get("items", blocks.get("blocks", []))
        ok(f"Ledger has {len(blocks)} recent blocks")
        demo_blocks = [b for b in blocks if CVE_ID in json.dumps(b.get("payload", {})) or
                       "regreSSHion" in json.dumps(b.get("payload", {}))]
        if demo_blocks:
            ok(f"Found {len(demo_blocks)} ledger entries for this demo")
            for blk in demo_blocks[:3]:
                detail("Event", f"{blk.get('eventType', '?')} → entity {str(blk.get('entityId', '?'))[:8]}")
                detail("Hash", f"{blk.get('blockHash', '?')[:16]}...")

        point("Every action is recorded on an immutable SHA-256 hash chain.")
        print(f"           Each block's hash includes the previous block's hash, making")
        print(f"           tampering detectable — like a mini blockchain for audit compliance.")
    else:
        warn(f"Could not fetch ledger: {r.status_code}")

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 8: ML SCORING (if available)
    # ══════════════════════════════════════════════════════════════
    if ml_status != "unavailable":
        step(7, "ML ANOMALY SCORING — Demonstrate threat detection")

        try:
            ml_url = "http://localhost:8001"

            benign_features = {
                "Dst Port": 80, "Protocol": 6, "Flow Duration": 5000,
                "Tot Fwd Pkts": 10, "Tot Bwd Pkts": 8,
                "TotLen Fwd Pkts": 5000, "TotLen Bwd Pkts": 3000,
                "Fwd Pkt Len Max": 1400, "Fwd Pkt Len Min": 40,
                "Fwd Pkt Len Mean": 500, "Flow Bytes/s": 1600,
                "Flow Pkts/s": 3.6, "SYN Flag Cnt": 1, "ACK Flag Cnt": 15,
            }
            anomalous_features = {
                "Dst Port": 22, "Protocol": 6, "Flow Duration": 120,
                "Tot Fwd Pkts": 10000, "Tot Bwd Pkts": 2,
                "TotLen Fwd Pkts": 1000000, "TotLen Bwd Pkts": 100,
                "Fwd Pkt Len Max": 100, "Fwd Pkt Len Min": 0,
                "Fwd Pkt Len Mean": 100, "Flow Bytes/s": 8333333,
                "Flow Pkts/s": 83333, "SYN Flag Cnt": 10000, "ACK Flag Cnt": 0,
            }

            r_benign = client.post(f"{ml_url}/score", json={"features": benign_features}, timeout=10)
            r_attack = client.post(f"{ml_url}/score", json={"features": anomalous_features}, timeout=10)

            if r_benign.status_code == 200 and r_attack.status_code == 200:
                b = r_benign.json()
                a = r_attack.json()

                ok("ML scoring comparison:")
                print()
                print(f"    {B}{'Traffic Type':<20} {'Score':>8} {'Confidence':>12} {'Suppressed':>12} {'Cluster':>10}{X}")
                print(f"    {'─' * 62}")
                print(f"    {G}{'Normal HTTP':<20} {b['score']:>8.4f} {b['confidence']:>12.4f} {str(b['suppressed']):>12} {str(b.get('cluster_id','?')):>10}{X}")
                print(f"    {R}{'SSH Attack (CVE)':<20} {a['score']:>8.4f} {a['confidence']:>12.4f} {str(a['suppressed']):>12} {str(a.get('cluster_id','?')):>10}{X}")
                print()

                score_diff = ((a["score"] - b["score"]) / max(b["score"], 0.001)) * 100
                point(f"Attack traffic scores {score_diff:.0f}% higher than benign ({a['score']:.2f} vs {b['score']:.2f})")
                if b["suppressed"]:
                    point(f"Benign traffic is suppressed (low confidence) — no false alarm")
                else:
                    point(f"Benign traffic scored low ({b['score']:.2f}) — minimal threat")
                if not a["suppressed"]:
                    point(f"Attack traffic is NOT suppressed — correctly flagged for action")
                else:
                    point(f"Attack traffic has confidence {a['confidence']:.2f}")
                point("The ensemble uses Isolation Forest + LSTM Autoencoder, trained on")
                print(f"           CIC-IDS2017 network flow data, with KMeans cluster-aware scoring.")
        except Exception as e:
            warn(f"ML direct scoring test skipped: {e}")

    time.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # PHASE 9: TOP RISKS
    # ══════════════════════════════════════════════════════════════
    step(8, "RISK RANKING — Top 10 CVEs by BWVS priority")

    r = client.get(f"{API}/risks/top10")
    if r.status_code == 200:
        data = r.json()
        risks = data.get("risks", data) if isinstance(data, dict) else data
        if isinstance(risks, list) and risks:
            ok(f"Top risks ({len(risks)} CVEs ranked):")
            print()
            print(f"    {B}{'#':>3} {'CVE ID':<20} {'BWVS':>6} {'Risk':>10} {'CVSS':>6}{X}")
            print(f"    {'─' * 50}")
            for i, cve in enumerate(risks[:10], 1):
                cid = cve.get("id", "?")
                bwvs_val = cve.get("bwvsScore", "?")
                risk_val = cve.get("riskLevel", "?")
                cvss_val = cve.get("cvssScore", "?")
                marker = f" {Y}← DEMO{X}" if CVE_ID in str(cid) else ""
                print(f"    {i:>3}. {str(cid):<20} {str(bwvs_val):>6} {str(risk_val):>10} {str(cvss_val):>6}{marker}")
            print()
            point("Ranking uses BWVS × Freshness × EPSS, not just raw CVSS score.")
            print(f"           This means an old CVE with high CVSS can rank lower than a")
            print(f"           recent CVE with moderate CVSS but active exploitation.")
        else:
            warn("No CVEs in the risk ranking yet.")
    else:
        warn(f"Could not fetch top risks: {r.status_code}")

    # ══════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════
    banner("DEMO COMPLETE — KEY TAKEAWAYS")

    takeaways = [
        f"BWVS > CVSS: Context-aware scoring (exploit maturity + asset criticality + business impact)",
        f"Multi-Agent AI: 5 Gemini-powered specialists deliver consensus in seconds",
        f"Digital Twin: Network graph simulates blast radius of real attacks",
        f"Blockchain Ledger: SHA-256 hash chain for tamper-proof audit trail",
        f"ML Anomaly Detection: LSTM + Isolation Forest ensemble on CIC-IDS2017 data",
        f"Full Platform: CVE ingest → Incident → AI Analysis → Risk Ranking → Audit",
    ]
    for i, t in enumerate(takeaways, 1):
        print(f"  {G}{i}.{X} {t}")

    print(f"\n  {B}Quick links:{X}")
    print(f"    Dashboard:     {C}http://localhost:3000{X}")
    print(f"    API docs:      {C}http://localhost:8000/docs{X}")
    print(f"    Incident ID:   {C}{incident_id}{X}")
    print(f"\n  {D}To reset:  cd backend && python -m demo.reset_demo{X}\n")


if __name__ == "__main__":
    main()
