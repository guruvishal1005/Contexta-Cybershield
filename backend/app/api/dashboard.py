from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, cast, Date, case, extract
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.incident import Incident, SeverityEnum, StatusEnum
from app.models.analysis import Analysis
from app.models.cve import CVE
from app.models.asset import Asset
from app.models.playbook_execution import PlaybookExecution, ExecutionStatusEnum
from app.models.ledger_block import LedgerBlock
from app.schemas.dashboard import (
    DashboardSummaryOut,
    IncidentTrendOut,
    SeverityDistributionOut,
    RecentActivityOut,
    RiskHeatmapOut,
    ExecutiveSummaryOut,
    KPIOut,
)

router = APIRouter()


@router.get("/dashboard/summary", response_model=DashboardSummaryOut)
async def dashboard_summary(db: AsyncSession = Depends(get_db)) -> DashboardSummaryOut:
    open_incidents = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.status.notin_([StatusEnum.closed, StatusEnum.resolved])
            )
        )
    ).scalar() or 0

    critical_incidents = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.severity == SeverityEnum.critical,
                Incident.status.notin_([StatusEnum.closed, StatusEnum.resolved]),
            )
        )
    ).scalar() or 0

    active_playbooks = (
        await db.execute(
            select(func.count(PlaybookExecution.id)).where(
                PlaybookExecution.status == ExecutionStatusEnum.running
            )
        )
    ).scalar() or 0

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)
    cves_today = (
        await db.execute(
            select(func.count(CVE.id)).where(CVE.created_at >= today_start)
        )
    ).scalar() or 0

    avg_bwvs = (await db.execute(select(func.avg(CVE.bwvs_score)))).scalar() or 0.0

    return DashboardSummaryOut(
        open_incidents=open_incidents,
        critical_incidents=critical_incidents,
        active_playbooks=active_playbooks,
        cves_ingested_today=cves_today,
        avg_bwvs_score=round(avg_bwvs, 2),
        last_updated=datetime.now(timezone.utc),
    )


@router.get("/dashboard/incident-trend", response_model=list[IncidentTrendOut])
async def incident_trend(db: AsyncSession = Depends(get_db)) -> list[IncidentTrendOut]:
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    result = await db.execute(
        select(
            cast(Incident.created_at, Date).label("date"),
            func.count(Incident.id).label("count"),
            func.count(case((Incident.severity == SeverityEnum.critical, 1))).label("critical"),
            func.count(case((Incident.severity == SeverityEnum.high, 1))).label("high"),
            func.count(case((Incident.severity == SeverityEnum.medium, 1))).label("medium"),
            func.count(case((Incident.severity == SeverityEnum.low, 1))).label("low"),
        )
        .where(Incident.created_at >= thirty_days_ago)
        .group_by(cast(Incident.created_at, Date))
        .order_by(cast(Incident.created_at, Date))
    )
    return [
        IncidentTrendOut(
            date=str(row.date), count=row.count,
            critical=row.critical, high=row.high,
            medium=row.medium, low=row.low,
        )
        for row in result.all()
    ]


@router.get("/dashboard/severity-distribution", response_model=SeverityDistributionOut)
async def severity_distribution(
    db: AsyncSession = Depends(get_db),
) -> SeverityDistributionOut:
    counts = {}
    for sev in SeverityEnum:
        c = (
            await db.execute(
                select(func.count(Incident.id)).where(Incident.severity == sev)
            )
        ).scalar() or 0
        counts[sev.value] = c

    return SeverityDistributionOut(**counts)


@router.get("/dashboard/recent-activity", response_model=list[RecentActivityOut])
async def recent_activity(
    limit_: int = Query(10, alias="limit"),
    db: AsyncSession = Depends(get_db),
) -> list[RecentActivityOut]:
    incidents = await db.execute(
        select(Incident).order_by(Incident.created_at.desc()).limit(limit_)
    )
    items: list[RecentActivityOut] = []
    for inc in incidents.scalars().all():
        items.append(
            RecentActivityOut(
                id=inc.id,
                event_type="incident",
                title=inc.title,
                severity=inc.severity.value if inc.severity else None,
                created_at=inc.created_at,
            )
        )

    ledger_blocks = await db.execute(
        select(LedgerBlock)
        .where(LedgerBlock.event_type.in_(["cve_ingested", "playbook_triggered"]))
        .order_by(LedgerBlock.id.desc())
        .limit(limit_)
    )
    for block in ledger_blocks.scalars().all():
        items.append(
            RecentActivityOut(
                id=str(block.id),
                event_type=block.event_type,
                title=f"{block.event_type}: {block.payload.get('count', '')}",
                created_at=block.created_at,
            )
        )

    items.sort(key=lambda x: x.created_at or datetime.min, reverse=True)
    return items[:limit_]


@router.get("/dashboard/risk-heatmap", response_model=list[RiskHeatmapOut])
async def risk_heatmap(db: AsyncSession = Depends(get_db)) -> list[RiskHeatmapOut]:
    result = await db.execute(
        select(
            Asset.id,
            Asset.name,
            func.avg(Analysis.bwvs_score).label("avg_bwvs"),
            func.count(Incident.id).label("incident_count"),
        )
        .outerjoin(Incident, Incident.asset_id == Asset.id)
        .outerjoin(Analysis, Analysis.incident_id == Incident.id)
        .group_by(Asset.id, Asset.name)
    )

    from app.risk_engine.bwvs import BWVSCalculator

    items = []
    for row in result.all():
        bwvs = round(row.avg_bwvs, 2) if row.avg_bwvs else None
        items.append(
            RiskHeatmapOut(
                asset_id=row.id,
                asset_name=row.name,
                bwvs_score=bwvs,
                risk_level=BWVSCalculator.risk_level(bwvs) if bwvs else "Low",
                incident_count=row.incident_count,
            )
        )
    return items


@router.get("/executive/summary", response_model=ExecutiveSummaryOut)
async def executive_summary(db: AsyncSession = Depends(get_db)) -> ExecutiveSummaryOut:
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_month_start = (month_start - timedelta(days=1)).replace(day=1)

    this_month = (
        await db.execute(
            select(func.count(Incident.id)).where(Incident.created_at >= month_start)
        )
    ).scalar() or 0

    last_month = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.created_at >= last_month_start,
                Incident.created_at < month_start,
            )
        )
    ).scalar() or 0

    resolved = await db.execute(
        select(Incident).where(
            Incident.status == StatusEnum.resolved,
            Incident.closed_at.isnot(None),
        )
    )
    total_hours = 0.0
    resolved_count = 0
    for inc in resolved.scalars().all():
        if inc.closed_at and inc.created_at:
            total_hours += (inc.closed_at - inc.created_at).total_seconds() / 3600
            resolved_count += 1
    mttr = round(total_hours / resolved_count, 2) if resolved_count > 0 else 0.0

    fin_result = await db.execute(select(Analysis.business_output))
    total_mid = 0
    for row in fin_result.scalars().all():
        if row and isinstance(row, dict):
            total_mid += row.get("financial_impact_estimate", {}).get("mid", 0)

    return ExecutiveSummaryOut(
        mttr_hours=mttr,
        incidents_this_month=this_month,
        incidents_last_month=last_month,
        top_threat_categories=[],
        compliance_status="compliant",
        total_financial_exposure={"mid": total_mid},
    )


@router.get("/executive/kpis", response_model=list[KPIOut])
async def executive_kpis(db: AsyncSession = Depends(get_db)) -> list[KPIOut]:
    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    open_incidents = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.status.notin_([StatusEnum.closed, StatusEnum.resolved])
            )
        )
    ).scalar() or 0
    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar() or 0
    total_cves = (await db.execute(select(func.count(CVE.id)))).scalar() or 0
    avg_bwvs = (await db.execute(select(func.avg(CVE.bwvs_score)))).scalar() or 0.0

    return [
        KPIOut(name="Total Incidents", value=total_incidents, unit="count", description="All-time incident count"),
        KPIOut(name="Open Incidents", value=open_incidents, unit="count", trend="up" if open_incidents > 5 else "stable", description="Currently unresolved"),
        KPIOut(name="Monitored Assets", value=total_assets, unit="count", description="Assets in inventory"),
        KPIOut(name="CVEs Tracked", value=total_cves, unit="count", description="Total CVE database entries"),
        KPIOut(name="Avg BWVS Score", value=round(avg_bwvs, 1), unit="score", description="Average risk score across all CVEs"),
    ]
