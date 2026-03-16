from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.playbook_execution import PlaybookExecution
from app.schemas.playbook import (
    PlaybookOut,
    PlaybookExecutionOut,
    PlaybookExecutionDetailOut,
    ExecutePlaybookRequest,
    StepCompleteRequest,
)
from app.services.playbook_service import (
    load_all_playbooks,
    load_playbook,
    execute_playbook,
    complete_step,
)

router = APIRouter()


@router.get("", response_model=list[PlaybookOut])
async def list_playbooks() -> list[PlaybookOut]:
    return [PlaybookOut(**p) for p in load_all_playbooks()]


@router.get("/{playbook_id}", response_model=PlaybookOut)
async def get_playbook(playbook_id: str) -> PlaybookOut:
    pb = load_playbook(playbook_id)
    if not pb:
        raise HTTPException(404, "Playbook not found")
    return PlaybookOut(**pb)


@router.post("/{playbook_id}/execute", response_model=PlaybookExecutionOut, status_code=201)
async def execute(
    playbook_id: str,
    data: ExecutePlaybookRequest,
    db: AsyncSession = Depends(get_db),
) -> PlaybookExecutionOut:
    execution = await execute_playbook(playbook_id, data.incident_id, db)
    return PlaybookExecutionOut.model_validate(execution)


@router.get("/executions", response_model=list[PlaybookExecutionOut])
async def list_executions(
    incident_id: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[PlaybookExecutionOut]:
    query = select(PlaybookExecution).order_by(PlaybookExecution.created_at.desc())
    if incident_id:
        query = query.where(PlaybookExecution.incident_id == incident_id)
    if status:
        query = query.where(PlaybookExecution.status == status)
    result = await db.execute(query)
    return [PlaybookExecutionOut.model_validate(e) for e in result.scalars().all()]


@router.get("/executions/{exec_id}", response_model=PlaybookExecutionDetailOut)
async def get_execution(
    exec_id: str,
    db: AsyncSession = Depends(get_db),
) -> PlaybookExecutionDetailOut:
    result = await db.execute(
        select(PlaybookExecution).where(PlaybookExecution.id == exec_id)
    )
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(404, "Execution not found")

    pb = load_playbook(execution.playbook_id)
    out = PlaybookExecutionDetailOut.model_validate(execution)
    if pb:
        out.playbook = PlaybookOut(**pb)
    return out


@router.put(
    "/executions/{exec_id}/steps/{step_id}/complete",
    response_model=PlaybookExecutionOut,
)
async def complete_execution_step(
    exec_id: str,
    step_id: int,
    data: StepCompleteRequest,
    db: AsyncSession = Depends(get_db),
) -> PlaybookExecutionOut:
    execution = await complete_step(exec_id, step_id, data.result, data.notes, db)
    return PlaybookExecutionOut.model_validate(execution)
