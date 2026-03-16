"""Demo agent analysis endpoint — matches frontend path /api/agents/analyze/demo (no /v1/)."""

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Query

from app.agents import (
    AnalystAgent,
    IntelAgent,
    ForensicsAgent,
    BusinessAgent,
    ResponseAgent,
)

VALID_AGENTS = {"analyst", "intel", "forensics", "business", "response"}
AGENT_CLASSES = {
    "analyst": AnalystAgent,
    "intel": IntelAgent,
    "forensics": ForensicsAgent,
    "business": BusinessAgent,
    "response": ResponseAgent,
}

router = APIRouter(prefix="/api/agents", tags=["demo"])


def _summary_from_output(out: dict) -> str:
    if out.get("error"):
        return "Agent encountered an error: " + out.get("raw_response", "Unknown error")
    parts = []
    for k, v in out.items():
        if k in ("error", "raw_response") or v is None:
            continue
        if isinstance(v, list) and v:
            parts.append(f"{k}: {', '.join(str(x) for x in v[:5])}")
        elif isinstance(v, dict):
            parts.append(f"{k}: {v}")
        else:
            parts.append(f"{k}: {v}")
    return " ".join(parts) if parts else "No summary available."


@router.post("/analyze/demo")
async def analyze_demo(
    risk_title: str = Query(..., description="Title of the risk to analyze"),
    agents: str = Query(
        default="analyst,intel,forensics,business,response",
        description="Comma-separated agent names",
    ),
):
    agent_names = [a.strip().lower() for a in agents.split(",") if a.strip()]
    agent_names = [a for a in agent_names if a in VALID_AGENTS]
    if not agent_names:
        agent_names = ["analyst"]

    context = {
        "incident": {
            "title": risk_title,
            "severity": "high",
            "source": "demo",
            "description": "",
            "status": "open",
        },
        "asset": {},
        "top_cves": [],
    }

    instances = [AGENT_CLASSES[name]() for name in agent_names]
    results = await asyncio.gather(
        *[agent.analyze(context) for agent in instances]
    )

    discussion = []
    now_iso = datetime.now(timezone.utc).isoformat()
    for name, out in zip(agent_names, results):
        discussion.append({
            "agent": name,
            "content": _summary_from_output(out),
            "timestamp": now_iso,
        })

    return {"discussion": discussion}
