import json

from app.agents.base import BaseAgent


class ResponseAgent(BaseAgent):
    async def analyze(self, context: dict) -> dict:
        prompt = f"""You are an Incident Response Orchestrator. Create a response plan. Return ONLY valid JSON.

Incident: {json.dumps(context.get('incident', {}), default=str)}
Asset: {json.dumps(context.get('asset', {}), default=str)}

Available playbooks: ransomware_response, data_exfiltration, lateral_movement

Return JSON with exactly these fields:
- immediate_actions: array of objects with fields: priority (integer 1-5), action (string), responsible_team (string), estimated_duration_minutes (integer)
- containment_strategy: string
- eradication_steps: array of strings
- recovery_steps: array of strings
- recommended_playbook: string (playbook ID from available list)
- estimated_resolution_hours: integer
- response_narrative: string"""

        return await self._call_gemini(prompt)
