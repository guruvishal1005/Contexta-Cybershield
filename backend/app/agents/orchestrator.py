"""Consensus engine — pure Python, no Gemini calls.

When Gemini agents return errors (quota/network), fallback logic extracts
meaningful results from the incident context (raw_log, severity, CVEs).
"""

import logging

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
REVERSE_SEVERITY = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}

_SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def _severity_to_num(s: str) -> int:
    return SEVERITY_WEIGHTS.get(s.title(), 2)


def _num_to_severity(n: float) -> str:
    rounded = round(n)
    return REVERSE_SEVERITY.get(max(0, min(4, rounded)), "Medium")


def _normalise_business_impact_to_severity(score: float) -> str:
    if score >= 8.0:
        return "Critical"
    if score >= 6.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _is_agent_error(result: dict) -> bool:
    if result.get("error"):
        return True
    meaningful = {k: v for k, v in result.items() if k not in ("error", "raw_response") and v}
    return len(meaningful) == 0


def _analyst_fallback(ctx: dict) -> dict:
    """Infer analyst output from incident context."""
    incident = ctx.get("incident", {})
    raw = incident.get("raw_log") or {}
    sev = incident.get("severity", "medium")

    attack_type = "Unknown"
    indicators: list[str] = []
    mitre: list[str] = []
    confidence = 0.75

    src_ip = raw.get("src_ip", "")
    dst_ip = raw.get("dst_ip", "")
    dst_port = raw.get("dst_port")
    protocol = str(raw.get("protocol", "")).lower()
    cve_ref = raw.get("cve_reference", "") or raw.get("cve_id", "")

    if src_ip:
        indicators.append(src_ip)
    if dst_ip and dst_port:
        indicators.append(f"{dst_ip}:{dst_port}")

    if protocol == "ssh" or dst_port == 22:
        attack_type = "SSH Exploitation"
        mitre = ["T1021.004", "T1190"]
        if "race" in str(raw.get("timing_anomaly", "")):
            attack_type = "SSH Race Condition RCE (regreSSHion)"
            mitre.append("T1210")
        conn_attempts = raw.get("connection_attempts", 0)
        if conn_attempts > 1000:
            mitre.append("T1110.001")
            confidence = 0.90
    elif "sql" in str(raw.get("uri", "")).lower():
        attack_type = "SQL Injection"
        mitre = ["T1190", "T1059.001"]
    elif raw.get("alert_rule", "").startswith("BRUTE_FORCE"):
        attack_type = "Brute Force Authentication"
        mitre = ["T1110"]
    elif "lateral" in str(raw.get("alert_rule", "")).lower():
        attack_type = "Lateral Movement"
        mitre = ["T1021", "T1071"]
    elif "ransomware" in str(raw.get("alert_rule", "")).lower():
        attack_type = "Ransomware Precursor"
        mitre = ["T1486", "T1490"]
    elif "exfiltration" in str(raw.get("alert_rule", "")).lower():
        attack_type = "Data Exfiltration"
        mitre = ["T1041", "T1048"]
    elif raw.get("anomaly") == "heap_overflow_pattern":
        attack_type = "Zero-Day Exploitation"
        mitre = ["T1190", "T1203"]

    if cve_ref:
        indicators.append(cve_ref)

    return {
        "attack_type": attack_type,
        "attack_vector": "Network",
        "severity_assessment": _SEV_MAP.get(sev, "High"),
        "confidence": confidence,
        "indicators": indicators,
        "mitre_techniques": sorted(set(mitre)),
        "triage_notes": f"Context-derived: {incident.get('title', '')}",
    }


def _intel_fallback(ctx: dict) -> dict:
    incident = ctx.get("incident", {})
    raw = incident.get("raw_log") or {}
    cves = ctx.get("top_cves", [])

    cve_ref = raw.get("cve_reference", "") or raw.get("cve_id", "")
    cve_refs = [cve_ref] if cve_ref else [c["id"] for c in cves[:3]]

    exploit_available = raw.get("is_vulnerable_version", False) or bool(cve_ref)
    openssh_ver = raw.get("openssh_version_detected", "")

    actors: list[str] = []
    if raw.get("alert_rule", "").startswith("CVE_2024_6387"):
        actors = ["APT groups targeting SSH infrastructure", "Opportunistic scanners"]

    iocs = []
    src_ip = raw.get("src_ip", "")
    if src_ip:
        iocs.append({"type": "ipv4", "value": src_ip, "confidence": 0.9})
    if openssh_ver:
        iocs.append({"type": "software", "value": f"OpenSSH {openssh_ver}", "confidence": 1.0})

    return {
        "threat_actors": actors,
        "ttps": ["T1190", "T1210"] if cve_ref else [],
        "iocs": iocs,
        "exploit_available": exploit_available,
        "exploit_maturity": "proof-of-concept" if exploit_available else "unknown",
        "cve_references": cve_refs,
        "threat_context": f"Context-derived intel for {cve_ref or 'incident'}.",
    }


def _forensics_fallback(ctx: dict) -> dict:
    incident = ctx.get("incident", {})
    raw = incident.get("raw_log") or {}

    timeline = []
    if raw.get("connection_attempts"):
        timeline.append({
            "timestamp": "T+0s",
            "event": f"{raw['connection_attempts']} connection attempts detected on port {raw.get('dst_port', '?')}",
            "significance": "high",
        })
    if raw.get("timing_anomaly"):
        timeline.append({
            "timestamp": "T+1s",
            "event": f"Timing anomaly: {raw['timing_anomaly']}",
            "significance": "high",
        })
    if raw.get("failed_auths"):
        timeline.append({
            "timestamp": "T+2s",
            "event": f"{raw['failed_auths']} failed authentication attempts",
            "significance": "high",
        })

    return {
        "timeline": timeline or [{"timestamp": "T+0s", "event": incident.get("title", ""), "significance": "high"}],
        "artifacts": [],
        "persistence_mechanisms": [],
        "lateral_movement_evidence": "lateral" in incident.get("title", "").lower(),
        "data_exfiltration_evidence": "exfil" in str(raw.get("alert_rule", "")).lower(),
        "forensic_summary": f"Context-derived forensics for: {incident.get('title', '')}",
    }


def _business_fallback(ctx: dict) -> dict:
    asset = ctx.get("asset", {})
    criticality = asset.get("criticality", 5)
    sev = ctx.get("incident", {}).get("severity", "medium")

    sev_multiplier = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 2)
    base = criticality * 5000 * sev_multiplier

    return {
        "financial_impact_estimate": {"low": base, "mid": base * 3, "high": base * 8},
        "affected_systems_count": max(1, criticality // 2),
        "data_types_at_risk": ["credentials", "configuration", "system access"],
        "compliance_frameworks_affected": ["PCI-DSS", "SOC2"] if criticality >= 7 else ["SOC2"],
        "regulatory_notification_required": criticality >= 8,
        "notification_deadline_hours": 72 if criticality >= 8 else None,
        "stakeholders_to_notify": ["CISO", "Engineering Lead"],
        "business_impact_score": min(10.0, criticality * 1.1),
        "impact_narrative": f"Asset criticality {criticality}/10. Context-derived business impact.",
    }


def _response_fallback(ctx: dict) -> dict:
    incident = ctx.get("incident", {})
    raw = incident.get("raw_log") or {}
    protocol = str(raw.get("protocol", "")).lower()

    if protocol == "ssh" or raw.get("dst_port") == 22:
        playbook = "ssh_exploitation_response"
        actions = [
            {"priority": 1, "action": "Block attacker IP at perimeter firewall", "responsible_team": "Network Ops", "estimated_duration_minutes": 5},
            {"priority": 2, "action": "Isolate affected SSH server from network", "responsible_team": "SOC", "estimated_duration_minutes": 10},
            {"priority": 3, "action": "Rotate SSH host keys and credentials", "responsible_team": "SysAdmin", "estimated_duration_minutes": 30},
            {"priority": 4, "action": "Patch OpenSSH to >= 9.8p1", "responsible_team": "SysAdmin", "estimated_duration_minutes": 60},
            {"priority": 5, "action": "Conduct forensic analysis of SSH logs", "responsible_team": "DFIR", "estimated_duration_minutes": 120},
        ]
        containment = "Network isolation of affected server + IP block at firewall"
        eradication = ["Update OpenSSH to patched version", "Verify no unauthorized SSH keys added", "Review sshd_config hardening"]
    else:
        playbook = "lateral_movement"
        actions = [
            {"priority": 1, "action": "Isolate affected system", "responsible_team": "SOC", "estimated_duration_minutes": 10},
            {"priority": 2, "action": "Block attacker indicators", "responsible_team": "Network Ops", "estimated_duration_minutes": 15},
            {"priority": 3, "action": "Credential rotation", "responsible_team": "IAM", "estimated_duration_minutes": 60},
        ]
        containment = "System isolation and network segmentation"
        eradication = ["Remove unauthorized access", "Patch vulnerable software", "Review access controls"]

    return {
        "immediate_actions": actions,
        "containment_strategy": containment,
        "eradication_steps": eradication,
        "recovery_steps": ["Restore from verified backup", "Monitor for re-compromise", "Post-incident review"],
        "recommended_playbook": playbook,
        "estimated_resolution_hours": 8,
        "response_narrative": f"Context-derived response plan for: {incident.get('title', '')}",
    }


class Orchestrator:
    def generate_consensus(
        self,
        analyst: dict,
        intel: dict,
        forensics: dict,
        business: dict,
        response: dict,
        ctx: dict | None = None,
    ) -> dict:
        if ctx and _is_agent_error(analyst):
            logger.warning("Analyst agent failed — using context fallback")
            analyst = _analyst_fallback(ctx)
        if ctx and _is_agent_error(intel):
            logger.warning("Intel agent failed — using context fallback")
            intel = _intel_fallback(ctx)
        if ctx and _is_agent_error(forensics):
            logger.warning("Forensics agent failed — using context fallback")
            forensics = _forensics_fallback(ctx)
        if ctx and _is_agent_error(business):
            logger.warning("Business agent failed — using context fallback")
            business = _business_fallback(ctx)
        if ctx and _is_agent_error(response):
            logger.warning("Response agent failed — using context fallback")
            response = _response_fallback(ctx)

        analyst_sev = _severity_to_num(
            analyst.get("severity_assessment", "Medium")
        )
        intel_sev = _severity_to_num("High" if intel.get("exploit_available") else "Medium")
        biz_score = business.get("business_impact_score", 5.0)
        biz_sev = _severity_to_num(_normalise_business_impact_to_severity(biz_score))

        consensus_sev_num = analyst_sev * 0.4 + intel_sev * 0.3 + biz_sev * 0.3
        consensus_severity = _num_to_severity(consensus_sev_num)

        analyst_iocs = [
            {"type": "indicator", "value": ioc, "confidence": analyst.get("confidence", 0.5)}
            for ioc in analyst.get("indicators", [])
        ]
        intel_iocs = intel.get("iocs", [])
        seen_values: set[str] = set()
        merged_iocs: list[dict] = []
        for ioc in sorted(
            analyst_iocs + intel_iocs,
            key=lambda x: x.get("confidence", 0),
            reverse=True,
        ):
            val = ioc.get("value", "")
            if val and val not in seen_values:
                seen_values.add(val)
                merged_iocs.append(ioc)

        mitre_techniques = sorted(set(
            analyst.get("mitre_techniques", []) +
            intel.get("ttps", [])
        ))

        cve_references = sorted(set(intel.get("cve_references", [])))

        response_actions = sorted(
            response.get("immediate_actions", []),
            key=lambda x: x.get("priority", 99),
        )
        high_sig_events = [
            {"priority": 50, "action": e.get("event", ""), "source": "forensics"}
            for e in forensics.get("timeline", [])
            if e.get("significance", "").lower() == "high"
        ]
        ordered_plan = response_actions + high_sig_events

        attack = analyst.get("attack_type", "Unknown")
        confidence = analyst.get("confidence", 0.0)
        actor_str = ", ".join(intel.get("threat_actors", [])) or "Unknown threat actors"
        exfil = forensics.get("data_exfiltration_evidence", False)
        lateral = forensics.get("lateral_movement_evidence", False)
        fin_mid = business.get("financial_impact_estimate", {}).get("mid", 0)
        playbook = response.get("recommended_playbook", "N/A")

        narrative = (
            f"A {consensus_severity}-severity {attack} attack was identified with "
            f"{confidence:.0%} confidence. Threat intelligence links activity to "
            f"{actor_str}. "
            f"{'Data exfiltration evidence was found. ' if exfil else ''}"
            f"{'Lateral movement was detected. ' if lateral else ''}"
            f"Estimated financial impact is ${fin_mid:,} (mid-range). "
            f"Recommended playbook: {playbook}."
        )

        return {
            "severity": consensus_severity,
            "confidence": confidence,
            "merged_iocs": merged_iocs,
            "mitre_techniques": mitre_techniques,
            "cve_references": cve_references,
            "ordered_response_plan": ordered_plan,
            "consensus_narrative": narrative,
        }
