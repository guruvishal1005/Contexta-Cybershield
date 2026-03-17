"""Orchestrates the full analysis pipeline (section 4.2 of the spec)."""

import asyncio
import logging
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.incident import Incident
from app.models.analysis import Analysis
from app.models.cve import CVE
from app.models.network_topology import NetworkTopology
from app.agents import (
    AnalystAgent,
    IntelAgent,
    ForensicsAgent,
    BusinessAgent,
    ResponseAgent,
    Orchestrator,
)
from app.risk_engine.bwvs import BWVSCalculator
from app.twin import digital_twin
from app.ledger import ledger

logger = logging.getLogger(__name__)


def _resolve_topology_node(asset) -> str | None:
    """Map an Asset ORM object to its corresponding topology node ID via IP address."""
    if not asset or not asset.ip_address:
        return None
    graph = digital_twin._graph
    for node_id, data in graph.nodes(data=True):
        if data.get("ip_address") == asset.ip_address:
            return node_id
    return None


analyst_agent = AnalystAgent()
intel_agent = IntelAgent()
forensics_agent = ForensicsAgent()
business_agent = BusinessAgent()
response_agent = ResponseAgent()
orchestrator = Orchestrator()
bwvs_calc = BWVSCalculator()


async def run_analysis(
    incident_id: str,
    db: AsyncSession,
    force_refresh: bool = False,
) -> Analysis:
    # 1. Load incident with related asset
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.asset), selectinload(Incident.analysis))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    if incident.analysis and not force_refresh:
        return incident.analysis

    # 2. Build shared context
    cve_result = await db.execute(
        select(CVE).order_by(CVE.bwvs_score.desc().nullslast()).limit(20)
    )
    top_cves = [
        {"id": c.id, "cvss_score": c.cvss_score, "bwvs_score": c.bwvs_score}
        for c in cve_result.scalars().all()
    ]

    topo_result = await db.execute(
        select(NetworkTopology).where(NetworkTopology.is_active.is_(True)).limit(1)
    )
    topo = topo_result.scalar_one_or_none()

    asset_dict = {}
    if incident.asset:
        asset_dict = {
            "id": incident.asset.id,
            "name": incident.asset.name,
            "asset_type": incident.asset.asset_type,
            "criticality": incident.asset.criticality,
            "is_internet_facing": incident.asset.is_internet_facing,
            "business_unit": incident.asset.business_unit,
            "ip_address": incident.asset.ip_address,
        }

    ctx = {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity.value if incident.severity else "medium",
            "status": incident.status.value if incident.status else "open",
            "source": incident.source,
            "raw_log": incident.raw_log,
        },
        "asset": asset_dict,
        "top_cves": top_cves,
        "topology": {"id": topo.id, "name": topo.name} if topo else None,
    }

    # 3. Append ledger: analysis_started
    await ledger.append("analysis_started", incident.id, {"incident_title": incident.title}, db)

    # 4. Invoke all five agents in parallel
    start_time = time.time()
    analyst_result, intel_result, forensics_result, business_result, response_result = (
        await asyncio.gather(
            analyst_agent.analyze(ctx),
            intel_agent.analyze(ctx),
            forensics_agent.analyze(ctx),
            business_agent.analyze(ctx),
            response_agent.analyze(ctx),
        )
    )

    # 5. Generate consensus (pure Python, with context fallback for agent errors)
    consensus = orchestrator.generate_consensus(
        analyst=analyst_result,
        intel=intel_result,
        forensics=forensics_result,
        business=business_result,
        response=response_result,
        ctx=ctx,
    )

    # 6. Append ledger: consensus_generated
    await ledger.append("consensus_generated", incident.id, {"severity": consensus["severity"]}, db)

    # 7. BWVS calculation
    exploit_maturity = intel_result.get("exploit_maturity", "unknown")
    business_impact = business_result.get("business_impact_score", 5.0)
    asset_criticality = incident.asset.criticality if incident.asset else 5
    exposure = "internet_facing" if (incident.asset and incident.asset.is_internet_facing) else "internal"

    bwvs_result = bwvs_calc.calculate(
        cvss_score=top_cves[0].get("cvss_score", 0.0) if top_cves else 5.0,
        exploit_maturity=exploit_maturity,
        exposure=exposure,
        asset_criticality=asset_criticality,
        business_impact=business_impact,
    )
    bwvs_score = bwvs_result["bwvs_score"]

    # 8. Blast radius if asset linked — resolve asset UUID to topology node via IP
    blast_radius_data = None
    if incident.asset_id:
        topo_node_id = _resolve_topology_node(incident.asset)
        if topo_node_id:
            blast_radius_data = digital_twin.blast_radius(topo_node_id)
        else:
            blast_radius_data = digital_twin.blast_radius(incident.asset_id)

    # 9. Append ledger: risk_calculated
    await ledger.append(
        "risk_calculated",
        incident.id,
        {"bwvs_score": bwvs_score, "risk_level": bwvs_result["risk_level"]},
        db,
    )

    elapsed = round(time.time() - start_time, 2)

    # 10. Persist Analysis record
    if incident.analysis and force_refresh:
        analysis = incident.analysis
        analysis.analyst_output = analyst_result
        analysis.intel_output = intel_result
        analysis.forensics_output = forensics_result
        analysis.business_output = business_result
        analysis.response_output = response_result
        analysis.consensus = consensus
        analysis.bwvs_score = bwvs_score
        analysis.blast_radius = blast_radius_data
        analysis.analysis_duration_seconds = elapsed
    else:
        analysis = Analysis(
            incident_id=incident.id,
            analyst_output=analyst_result,
            intel_output=intel_result,
            forensics_output=forensics_result,
            business_output=business_result,
            response_output=response_result,
            consensus=consensus,
            bwvs_score=bwvs_score,
            blast_radius=blast_radius_data,
            analysis_duration_seconds=elapsed,
        )
        db.add(analysis)

    await db.flush()
    return analysis
