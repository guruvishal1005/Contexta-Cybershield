from datetime import datetime

from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks, Response
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.incident import Incident, SeverityEnum, StatusEnum
from app.models.ledger_block import LedgerBlock
from app.schemas.incident import (
    IncidentCreate,
    IncidentOut,
    IncidentDetailOut,
    IncidentUpdate,
    PaginatedIncidentsOut,
    StatusUpdate,
)
from app.schemas.analysis import AnalysisOut
from app.schemas.ledger import LedgerBlockOut
from app.ledger import ledger
from app.services.incident_service import run_analysis
from app.services.playbook_service import auto_select_and_trigger
from app.database import async_session_factory

router = APIRouter()


@router.post("", response_model=IncidentOut, status_code=201)
async def create_incident(
    data: IncidentCreate,
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    incident = Incident(
        title=data.title,
        description=data.description,
        severity=SeverityEnum(data.severity),
        source=data.source,
        raw_log=data.raw_log,
        asset_id=data.asset_id,
    )
    db.add(incident)
    await db.flush()
    await ledger.append(
        "incident_created", incident.id,
        {"title": incident.title, "severity": data.severity}, db,
    )
    return IncidentOut.model_validate(incident)


@router.get("", response_model=PaginatedIncidentsOut)
async def list_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    asset_id: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    db: AsyncSession = Depends(get_db),
) -> PaginatedIncidentsOut:
    query = select(Incident).order_by(Incident.created_at.desc())
    count_query = select(func.count(Incident.id))

    if severity:
        query = query.where(Incident.severity == SeverityEnum(severity))
        count_query = count_query.where(Incident.severity == SeverityEnum(severity))
    if status:
        query = query.where(Incident.status == StatusEnum(status))
        count_query = count_query.where(Incident.status == StatusEnum(status))
    if asset_id:
        query = query.where(Incident.asset_id == asset_id)
        count_query = count_query.where(Incident.asset_id == asset_id)
    if date_from:
        query = query.where(Incident.created_at >= date_from)
        count_query = count_query.where(Incident.created_at >= date_from)
    if date_to:
        query = query.where(Incident.created_at <= date_to)
        count_query = count_query.where(Incident.created_at <= date_to)

    total = (await db.execute(count_query)).scalar() or 0
    query = query.offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)

    return PaginatedIncidentsOut(
        items=[IncidentOut.model_validate(i) for i in result.scalars().all()],
        total=total, page=page, limit=limit,
    )


@router.get("/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: str, db: AsyncSession = Depends(get_db),
) -> IncidentDetailOut:
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.analysis))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")

    out = IncidentDetailOut.model_validate(incident)
    if incident.analysis:
        out.analysis = AnalysisOut.model_validate(incident.analysis)
    return out


@router.put("/{incident_id}", response_model=IncidentOut)
async def update_incident(
    incident_id: str,
    data: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")

    update_data = data.model_dump(exclude_unset=True)
    if "severity" in update_data:
        update_data["severity"] = SeverityEnum(update_data["severity"])
    if "status" in update_data:
        update_data["status"] = StatusEnum(update_data["status"])
    for field, value in update_data.items():
        setattr(incident, field, value)
    await db.flush()

    await ledger.append(
        "incident_updated", incident.id,
        {"updated_fields": list(update_data.keys())}, db,
    )
    return IncidentOut.model_validate(incident)


@router.delete("/{incident_id}", status_code=204)
async def delete_incident(
    incident_id: str, db: AsyncSession = Depends(get_db),
) -> Response:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")

    incident.status = StatusEnum.closed
    incident.closed_at = datetime.utcnow()
    await db.flush()
    await ledger.append("incident_closed", incident.id, {}, db)
    return Response(status_code=204)


@router.post("/{incident_id}/analyze", response_model=AnalysisOut)
async def analyze_incident(
    incident_id: str,
    background_tasks: BackgroundTasks,
    force_refresh: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> AnalysisOut:
    analysis = await run_analysis(incident_id, db, force_refresh=force_refresh)

    # Step 11: fire-and-forget playbook auto-select
    async def _bg_playbook() -> None:
        async with async_session_factory() as bg_db:
            try:
                inc_result = await bg_db.execute(
                    select(Incident).where(Incident.id == incident_id)
                )
                inc = inc_result.scalar_one_or_none()
                if inc and analysis.consensus:
                    await auto_select_and_trigger(inc, analysis.consensus, bg_db)
                    await bg_db.commit()
            except Exception as exc:
                await bg_db.rollback()

    background_tasks.add_task(_bg_playbook)
    return AnalysisOut.model_validate(analysis)


@router.get("/{incident_id}/analysis", response_model=AnalysisOut)
async def get_analysis(
    incident_id: str, db: AsyncSession = Depends(get_db),
) -> AnalysisOut:
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.analysis))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident or not incident.analysis:
        raise HTTPException(404, "Analysis not found")
    return AnalysisOut.model_validate(incident.analysis)


@router.put("/{incident_id}/status", response_model=IncidentOut)
async def update_status(
    incident_id: str,
    data: StatusUpdate,
    db: AsyncSession = Depends(get_db),
) -> IncidentOut:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")

    incident.status = StatusEnum(data.status)
    if data.status == "closed":
        incident.closed_at = datetime.utcnow()
    await db.flush()

    await ledger.append(
        "status_changed", incident.id,
        {"new_status": data.status}, db,
    )
    return IncidentOut.model_validate(incident)


@router.get("/{incident_id}/timeline", response_model=list[LedgerBlockOut])
async def get_timeline(
    incident_id: str, db: AsyncSession = Depends(get_db),
) -> list[LedgerBlockOut]:
    result = await db.execute(
        select(LedgerBlock)
        .where(LedgerBlock.entity_id == incident_id)
        .order_by(LedgerBlock.id.asc())
    )
    return [LedgerBlockOut.model_validate(b) for b in result.scalars().all()]
