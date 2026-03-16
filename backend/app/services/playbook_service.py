"""Playbook selection and step execution service."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.playbook_execution import PlaybookExecution, ExecutionStatusEnum
from app.models.incident import Incident
from app.ledger import ledger

logger = logging.getLogger(__name__)

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent.parent / "playbooks"


def load_playbook(playbook_id: str) -> dict | None:
    path = PLAYBOOKS_DIR / f"{playbook_id}.json"
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def load_all_playbooks() -> list[dict]:
    playbooks = []
    if PLAYBOOKS_DIR.exists():
        for path in sorted(PLAYBOOKS_DIR.glob("*.json")):
            try:
                with open(path) as f:
                    playbooks.append(json.load(f))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load playbook %s: %s", path.name, exc)
    return playbooks


async def execute_playbook(
    playbook_id: str,
    incident_id: str,
    db: AsyncSession,
) -> PlaybookExecution:
    playbook = load_playbook(playbook_id)
    if not playbook:
        raise ValueError(f"Playbook '{playbook_id}' not found")

    execution = PlaybookExecution(
        playbook_id=playbook_id,
        incident_id=incident_id,
        status=ExecutionStatusEnum.running,
        current_step=0,
        step_results=[],
        started_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    await db.flush()

    await ledger.append(
        "playbook_triggered",
        incident_id,
        {"playbook_id": playbook_id, "execution_id": execution.id},
        db,
    )
    return execution


async def complete_step(
    execution_id: str,
    step_id: int,
    result: str,
    notes: str,
    db: AsyncSession,
) -> PlaybookExecution:
    exec_result = await db.execute(
        select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
    )
    execution = exec_result.scalar_one_or_none()
    if not execution:
        raise ValueError(f"Execution '{execution_id}' not found")

    step_results = list(execution.step_results or [])
    step_results.append({
        "step_id": step_id,
        "result": result,
        "notes": notes,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })
    execution.step_results = step_results
    execution.current_step = step_id

    playbook = load_playbook(execution.playbook_id)
    total_steps = len(playbook.get("steps", [])) if playbook else 0

    await ledger.append(
        "playbook_step_completed",
        execution.incident_id,
        {"execution_id": execution.id, "step_id": step_id},
        db,
    )

    if step_id >= total_steps:
        execution.status = ExecutionStatusEnum.completed
        execution.completed_at = datetime.now(timezone.utc)
        await ledger.append(
            "playbook_completed",
            execution.incident_id,
            {"execution_id": execution.id, "playbook_id": execution.playbook_id},
            db,
        )

    if result == "escalated":
        execution.status = ExecutionStatusEnum.escalated
        await ledger.append(
            "playbook_escalated",
            execution.incident_id,
            {"execution_id": execution.id, "step_id": step_id},
            db,
        )

    await db.flush()
    return execution


async def auto_select_and_trigger(
    incident: Incident,
    consensus: dict,
    db: AsyncSession,
) -> None:
    """Automatically select and trigger the best matching playbook."""
    severity = incident.severity.value if incident.severity else "medium"
    attack_type = consensus.get("severity", "Medium")

    analyst_output = consensus.get("analyst_output", {})
    forensics_data = consensus.get("forensics_output", {})

    for playbook_data in load_all_playbooks():
        conditions = playbook_data.get("trigger_conditions", {})
        sev_match = severity in conditions.get("severity", [])
        type_match = any(
            at.lower() in (analyst_output.get("attack_type", "")).lower()
            for at in conditions.get("attack_types", [])
        )

        if sev_match or type_match:
            try:
                await execute_playbook(playbook_data["id"], incident.id, db)
                logger.info(
                    "Auto-triggered playbook %s for incident %s",
                    playbook_data["id"], incident.id,
                )
                return
            except Exception as exc:
                logger.warning("Failed to auto-trigger playbook: %s", exc)
