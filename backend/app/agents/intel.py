import json

from app.agents.base import BaseAgent


class IntelAgent(BaseAgent):
    async def analyze(self, context: dict) -> dict:
        cves = context.get("top_cves", [])
        prompt = f"""You are a Threat Intelligence analyst. Provide threat context for this incident. Return ONLY valid JSON.

Incident: {json.dumps(context.get('incident', {}), default=str)}
Known CVEs in environment: {json.dumps(cves[:10], default=str)}

Return JSON with exactly these fields:
- threat_actors: array of strings (known groups)
- ttps: array of strings (tactics, techniques, procedures)
- iocs: array of objects with fields: type (string), value (string), confidence (float 0-1)
- exploit_available: boolean
- exploit_maturity: string (one of: "proof-of-concept", "functional", "weaponised", "unknown")
- cve_references: array of strings (CVE IDs)
- threat_context: string (narrative)"""

        return await self._call_gemini(prompt)
