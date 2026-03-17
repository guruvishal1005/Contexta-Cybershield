# CVE-2024-6387 Demo — curl Cheat Sheet

Run each command from any terminal. All output is piped through `python3 -m json.tool` for readable formatting.

---

## 1. Health Check

Point out: backend health, DB connection status, current ledger block count.

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

---

## 2. Create CVE-2024-6387

Point out: BWVS score differs from raw CVSS 8.1 because it factors in exploit maturity (proof-of-concept) and default asset context. This is why BWVS is a better prioritisation signal than CVSS alone.

```bash
curl -s -X POST http://localhost:8000/api/v1/risks/cves \
  -H "Content-Type: application/json" \
  -d '{
    "id": "CVE-2024-6387",
    "description": "Race condition in OpenSSH sshd signal handler on glibc-based Linux systems allows unauthenticated remote code execution as root. Regression of CVE-2006-5051 (regreSSHion).",
    "cvssScore": 8.1,
    "cvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epssScore": 0.68,
    "isKev": false,
    "exploitAvailable": true,
    "exploitMaturity": "proof-of-concept",
    "publishedDate": "2024-07-01T00:00:00Z",
    "affectedProducts": {"vendor": "OpenBSD", "product": "OpenSSH", "versions_affected": "< 4.4p1 and 8.5p1 <= version < 9.8p1"},
    "cweIds": {"primary": "CWE-362"}
  }' | python3 -m json.tool
```

---

## 3. Find the Application Server Asset

Point out: the Application Server has criticality 8/10 and is NOT internet-facing — this affects the BWVS calculation.

```bash
curl -s "http://localhost:8000/api/v1/assets?limit=100" | python3 -m json.tool | grep -A5 '"Application Server"'
```

Or get the full list:

```bash
curl -s "http://localhost:8000/api/v1/assets?limit=100" | python3 -m json.tool
```

Copy the `id` field of the Application Server for the next step. Replace `<ASSET_ID>` below.

---

## 4. Create the Incident

Point out: realistic SIEM alert data in raw_log — 10,000 SSH connection attempts in 120 seconds with signal_handler_race_pattern timing anomaly.

```bash
curl -s -X POST http://localhost:8000/api/v1/incidents \
  -H "Content-Type: application/json" \
  -d '{
    "title": "CVE-2024-6387 regreSSHion exploit attempt on Application Server",
    "description": "Anomalous SSH connection pattern detected on port 22 of Application Server (192.168.2.10). 10,000 connection attempts over 120 seconds with timing characteristics consistent with the regreSSHion race condition exploit.",
    "severity": "high",
    "status": "open",
    "source": "siem",
    "assetId": "<ASSET_ID>",
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
      "is_vulnerable_version": true
    }
  }' | python3 -m json.tool
```

Copy the `id` from the response for the next steps. Replace `<INCIDENT_ID>` below.

---

## 5. Trigger Multi-Agent Analysis

Point out: five AI agents (Analyst, Intel, Forensics, Business, Response) run simultaneously. Takes 15–30 seconds. The consensus combines all five perspectives into a unified assessment.

```bash
curl -s -X POST "http://localhost:8000/api/v1/incidents/<INCIDENT_ID>/analyze" \
  --max-time 120 | python3 -m json.tool
```

---

## 6. Check Ledger Events for This Incident

Point out: immutable blockchain-backed audit trail. Every action — creation, analysis start, consensus, risk calculation — is a signed ledger block.

```bash
curl -s "http://localhost:8000/api/v1/incidents/<INCIDENT_ID>/timeline" | python3 -m json.tool
```

---

## 7. Verify Full Ledger Chain

Point out: the ledger is a hash chain (like a mini blockchain). Each block's hash includes the previous block's hash, making tampering detectable.

```bash
curl -s "http://localhost:8000/api/v1/ledger/chain?limit=10" | python3 -m json.tool
```

---

## 8. Check Top 10 Risks

Point out: CVE-2024-6387 should appear in the ranked list. Ranking uses BWVS × freshness × EPSS trend factor, not just CVSS score.

```bash
curl -s http://localhost:8000/api/v1/risks/top10 | python3 -m json.tool
```

---

## Reset (between demo runs)

```bash
# Delete the incident (replace <INCIDENT_ID>)
curl -s -X DELETE "http://localhost:8000/api/v1/incidents/<INCIDENT_ID>"

# Delete the CVE
curl -s -X DELETE "http://localhost:8000/api/v1/risks/cves/CVE-2024-6387"
```

Or use the automated reset script:

```bash
cd backend && python -m demo.reset_demo
```
