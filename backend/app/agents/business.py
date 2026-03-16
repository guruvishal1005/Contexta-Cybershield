import json

from app.agents.base import BaseAgent


class BusinessAgent(BaseAgent):
    async def analyze(self, context: dict) -> dict:
        prompt = f"""You are a Business Risk Assessment specialist. Evaluate business impact. Return ONLY valid JSON.

Incident: {json.dumps(context.get('incident', {}), default=str)}
Asset: {json.dumps(context.get('asset', {}), default=str)}

Return JSON with exactly these fields:
- financial_impact_estimate: object with fields: low (integer USD), mid (integer USD), high (integer USD)
- affected_systems_count: integer
- data_types_at_risk: array of strings
- compliance_frameworks_affected: array of strings
- regulatory_notification_required: boolean
- notification_deadline_hours: integer or null
- stakeholders_to_notify: array of strings
- business_impact_score: float 0.0-10.0
- impact_narrative: string"""

        return await self._call_gemini(prompt)
