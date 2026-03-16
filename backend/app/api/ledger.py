from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.ledger_block import LedgerBlock
from app.ledger import ledger
from app.schemas.ledger import LedgerBlockOut, PaginatedLedgerOut, ChainVerificationOut

router = APIRouter()


@router.get("/chain", response_model=PaginatedLedgerOut)
async def get_chain(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> PaginatedLedgerOut:
    total = (await db.execute(select(func.count(LedgerBlock.id)))).scalar() or 0
    result = await db.execute(
        select(LedgerBlock)
        .order_by(LedgerBlock.id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )
    return PaginatedLedgerOut(
        items=[LedgerBlockOut.model_validate(b) for b in result.scalars().all()],
        total=total, page=page, limit=limit,
    )


@router.get("/chain/{block_id}", response_model=LedgerBlockOut)
async def get_block(
    block_id: int,
    db: AsyncSession = Depends(get_db),
) -> LedgerBlockOut:
    result = await db.execute(select(LedgerBlock).where(LedgerBlock.id == block_id))
    block = result.scalar_one_or_none()
    if not block:
        raise HTTPException(404, "Block not found")
    return LedgerBlockOut.model_validate(block)


@router.get("/verify", response_model=ChainVerificationOut)
async def verify_chain() -> ChainVerificationOut:
    result = await ledger.verify_chain()
    return ChainVerificationOut(**result)


@router.get("/events/{entity_id}", response_model=list[LedgerBlockOut])
async def get_entity_events(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[LedgerBlockOut]:
    result = await db.execute(
        select(LedgerBlock)
        .where(LedgerBlock.entity_id == entity_id)
        .order_by(LedgerBlock.id.asc())
    )
    return [LedgerBlockOut.model_validate(b) for b in result.scalars().all()]
