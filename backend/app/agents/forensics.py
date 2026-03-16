import json

from app.agents.base import BaseAgent


class ForensicsAgent(BaseAgent):
    async def analyze(self, context: dict) -> dict:
        prompt = f"""You are a Digital Forensics specialist. Analyze evidence for this incident. Return ONLY valid JSON.

Incident: {json.dumps(context.get('incident', {}), default=str)}
Asset: {json.dumps(context.get('asset', {}), default=str)}
Raw logs: {json.dumps(context.get('incident', {}).get('raw_log', {}), default=str)}

Return JSON with exactly these fields:
- timeline: array of objects with fields: timestamp (string), event (string), significance (string: "high"/"medium"/"low")
- artifacts: array of objects with fields: type (string), location (string), hash (string), description (string)
- persistence_mechanisms: array of strings
- lateral_movement_evidence: boolean
- data_exfiltration_evidence: boolean
- forensic_summary: string"""

        return await self._call_gemini(prompt)
