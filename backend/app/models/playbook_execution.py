import uuid
import enum
from datetime import datetime

from sqlalchemy import String, Integer, Enum, JSON, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ExecutionStatusEnum(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    escalated = "escalated"


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    playbook_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[ExecutionStatusEnum] = mapped_column(
        Enum(ExecutionStatusEnum, name="execution_status_enum", create_constraint=True),
        default=ExecutionStatusEnum.pending,
    )
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    step_results: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    incident: Mapped["Incident"] = relationship(back_populates="playbook_executions")  # noqa: F821
