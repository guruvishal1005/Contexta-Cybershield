from fastapi import APIRouter, Depends, Query, HTTPException, Response
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import Asset
from app.models.incident import Incident, StatusEnum
from app.schemas.asset import (
    AssetCreate,
    AssetOut,
    AssetDetailOut,
    AssetUpdate,
    PaginatedAssetsOut,
    AssetRiskOut,
)
from app.schemas.incident import PaginatedIncidentsOut, IncidentOut
from app.services.asset_service import get_asset_risk

router = APIRouter()


def _vuln_count_subquery():
    return (
        select(func.count(Incident.id))
        .where(Incident.asset_id == Asset.id)
        .where(Incident.status.notin_([StatusEnum.closed, StatusEnum.resolved]))
        .correlate(Asset)
        .scalar_subquery()
    )


@router.get("", response_model=PaginatedAssetsOut)
async def list_assets(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    asset_type: str | None = None,
    criticality_min: int | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> PaginatedAssetsOut:
    vuln_count = _vuln_count_subquery()
    query = select(Asset, vuln_count.label("vuln_count")).order_by(Asset.criticality.desc())
    count_q = select(func.count(Asset.id))

    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
        count_q = count_q.where(Asset.asset_type == asset_type)
    if criticality_min is not None:
        query = query.where(Asset.criticality >= criticality_min)
        count_q = count_q.where(Asset.criticality >= criticality_min)
    if search:
        query = query.where(Asset.name.ilike(f"%{search}%"))
        count_q = count_q.where(Asset.name.ilike(f"%{search}%"))

    total = (await db.execute(count_q)).scalar() or 0
    result = await db.execute(query.offset((page - 1) * limit).limit(limit))
    items = []
    for row in result.all():
        asset, vc = row[0], row[1]
        out = AssetOut.model_validate(asset)
        out.vulnerabilities_count = vc or 0
        items.append(out)

    return PaginatedAssetsOut(items=items, total=total, page=page, limit=limit)


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(
    data: AssetCreate,
    db: AsyncSession = Depends(get_db),
) -> AssetOut:
    asset = Asset(**data.model_dump())
    db.add(asset)
    await db.flush()
    return AssetOut.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetDetailOut)
async def get_asset(
    asset_id: str, db: AsyncSession = Depends(get_db),
) -> AssetDetailOut:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(404, "Asset not found")
    incident_count = (
        await db.execute(
            select(func.count(Incident.id)).where(Incident.asset_id == asset_id)
        )
    ).scalar() or 0
    open_count = (
        await db.execute(
            select(func.count(Incident.id))
            .where(Incident.asset_id == asset_id)
            .where(Incident.status.notin_([StatusEnum.closed, StatusEnum.resolved]))
        )
    ).scalar() or 0
    out = AssetDetailOut.model_validate(asset)
    out.incident_count = incident_count
    out.vulnerabilities_count = open_count
    return out


@router.put("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: str,
    data: AssetUpdate,
    db: AsyncSession = Depends(get_db),
) -> AssetOut:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(404, "Asset not found")
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    await db.flush()
    return AssetOut.model_validate(asset)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str, db: AsyncSession = Depends(get_db),
) -> Response:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(404, "Asset not found")
    await db.delete(asset)
    await db.flush()
    return Response(status_code=204)


@router.get("/{asset_id}/incidents", response_model=PaginatedIncidentsOut)
async def get_asset_incidents(
    asset_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> PaginatedIncidentsOut:
    query = select(Incident).where(Incident.asset_id == asset_id).order_by(Incident.created_at.desc())
    count_q = select(func.count(Incident.id)).where(Incident.asset_id == asset_id)
    if status:
        from app.models.incident import StatusEnum
        query = query.where(Incident.status == StatusEnum(status))
        count_q = count_q.where(Incident.status == StatusEnum(status))
    total = (await db.execute(count_q)).scalar() or 0
    result = await db.execute(query.offset((page - 1) * limit).limit(limit))
    return PaginatedIncidentsOut(
        items=[IncidentOut.model_validate(i) for i in result.scalars().all()],
        total=total, page=page, limit=limit,
    )


@router.get("/{asset_id}/risk", response_model=AssetRiskOut)
async def asset_risk(
    asset_id: str, db: AsyncSession = Depends(get_db),
) -> AssetRiskOut:
    risk = await get_asset_risk(asset_id, db)
    return AssetRiskOut(**risk)
