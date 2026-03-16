"""Asset CRUD and risk aggregation service."""

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.incident import Incident, StatusEnum
from app.models.analysis import Analysis


async def get_asset_risk(asset_id: str, db: AsyncSession) -> dict:
    open_count = (
        await db.execute(
            select(func.count(Incident.id)).where(
                Incident.asset_id == asset_id,
                Incident.status.notin_([StatusEnum.closed, StatusEnum.resolved]),
            )
        )
    ).scalar() or 0

    avg_bwvs = (
        await db.execute(
            select(func.avg(Analysis.bwvs_score)).where(
                Analysis.incident_id.in_(
                    select(Incident.id).where(Incident.asset_id == asset_id)
                )
            )
        )
    ).scalar()

    last_incident = (
        await db.execute(
            select(Incident.created_at)
            .where(Incident.asset_id == asset_id)
            .order_by(Incident.created_at.desc())
            .limit(1)
        )
    ).scalar()

    from app.risk_engine.bwvs import BWVSCalculator
    risk_level = BWVSCalculator.risk_level(avg_bwvs) if avg_bwvs else "Low"

    return {
        "bwvs_score": round(avg_bwvs, 2) if avg_bwvs else None,
        "risk_level": risk_level,
        "open_incidents": open_count,
        "last_incident_date": last_incident,
    }
