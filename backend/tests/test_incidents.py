"""Integration tests for the analysis pipeline.

Uses respx to mock all Gemini API calls.
NOTE: Requires a running test database (contexta_test) to run.
Skip with `pytest -k 'not integration'` if DB is unavailable.
"""

import json
import pytest
import respx
from httpx import Response as HttpxResponse

from app.agents.orchestrator import Orchestrator


MOCK_ANALYST = {
    "attack_type": "Ransomware",
    "attack_vector": "Network",
    "severity_assessment": "Critical",
    "confidence": 0.92,
    "indicators": ["192.168.1.100", "evil.exe"],
    "mitre_techniques": ["T1486", "T1059.001"],
    "triage_notes": "Active ransomware encryption detected.",
}

MOCK_INTEL = {
    "threat_actors": ["BlackCat"],
    "ttps": ["T1486"],
    "iocs": [{"type": "ip", "value": "10.0.0.99", "confidence": 0.85}],
    "exploit_available": True,
    "exploit_maturity": "weaponised",
    "cve_references": ["CVE-2024-1234"],
    "threat_context": "BlackCat ransomware campaign.",
}

MOCK_FORENSICS = {
    "timeline": [{"timestamp": "2024-01-01T10:00", "event": "Encryption started", "significance": "high"}],
    "artifacts": [{"type": "file", "location": "/tmp/evil.exe", "hash": "abc123", "description": "Ransomware binary"}],
    "persistence_mechanisms": ["Scheduled task"],
    "lateral_movement_evidence": True,
    "data_exfiltration_evidence": False,
    "forensic_summary": "Active ransomware with lateral movement.",
}

MOCK_BUSINESS = {
    "financial_impact_estimate": {"low": 100000, "mid": 500000, "high": 2000000},
    "affected_systems_count": 15,
    "data_types_at_risk": ["PII", "Financial"],
    "compliance_frameworks_affected": ["PCI-DSS", "GDPR"],
    "regulatory_notification_required": True,
    "notification_deadline_hours": 72,
    "stakeholders_to_notify": ["CISO", "Legal"],
    "business_impact_score": 8.5,
    "impact_narrative": "Significant financial exposure.",
}

MOCK_RESPONSE = {
    "immediate_actions": [
        {"priority": 1, "action": "Isolate systems", "responsible_team": "Network", "estimated_duration_minutes": 15},
        {"priority": 2, "action": "Block C2", "responsible_team": "SOC", "estimated_duration_minutes": 10},
    ],
    "containment_strategy": "Network segmentation",
    "eradication_steps": ["Remove malware", "Patch vulnerability"],
    "recovery_steps": ["Restore from backup"],
    "recommended_playbook": "ransomware_response",
    "estimated_resolution_hours": 24,
    "response_narrative": "Immediate isolation required.",
}


def test_orchestrator_consensus():
    """Test that the orchestrator produces a valid consensus from agent outputs."""
    orch = Orchestrator()
    result = orch.generate_consensus(
        analyst=MOCK_ANALYST,
        intel=MOCK_INTEL,
        forensics=MOCK_FORENSICS,
        business=MOCK_BUSINESS,
        response=MOCK_RESPONSE,
    )

    assert result["severity"] in ("Critical", "High", "Medium", "Low")
    assert result["confidence"] == 0.92
    assert len(result["merged_iocs"]) > 0
    assert "T1486" in result["mitre_techniques"]
    assert "CVE-2024-1234" in result["cve_references"]
    assert len(result["ordered_response_plan"]) > 0
    assert "ransomware_response" in result["consensus_narrative"].lower() or "ransomware" in result["consensus_narrative"].lower()


def test_orchestrator_empty_inputs():
    """Orchestrator handles empty/error agent outputs gracefully."""
    orch = Orchestrator()
    result = orch.generate_consensus(
        analyst={},
        intel={},
        forensics={},
        business={},
        response={},
    )
    assert "severity" in result
    assert "consensus_narrative" in result
