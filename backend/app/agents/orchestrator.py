"""Consensus engine — pure Python, no Gemini calls."""


SEVERITY_WEIGHTS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
REVERSE_SEVERITY = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}


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


class Orchestrator:
    def generate_consensus(
        self,
        analyst: dict,
        intel: dict,
        forensics: dict,
        business: dict,
        response: dict,
    ) -> dict:
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
