import json

from app.agents.base import BaseAgent


class AnalystAgent(BaseAgent):
    async def analyze(self, context: dict) -> dict:
        prompt = f"""You are a Senior SOC Analyst. Analyze this security incident and return ONLY valid JSON.

Incident: {json.dumps(context.get('incident', {}), default=str)}
Asset: {json.dumps(context.get('asset', {}), default=str)}

Return JSON with exactly these fields:
- attack_type: string (e.g. "Ransomware", "Phishing", "SQL Injection")
- attack_vector: string (one of: "Network", "Adjacent", "Local", "Physical")
- severity_assessment: string (one of: "Critical", "High", "Medium", "Low")
- confidence: float 0.0-1.0
- indicators: array of strings (IOCs found)
- mitre_techniques: array of strings (ATT&CK IDs e.g. "T1059.001")
- triage_notes: string (brief assessment)"""

        return await self._call_gemini(prompt)
