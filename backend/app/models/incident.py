import uuid
import enum
from datetime import datetime

from sqlalchemy import String, Text, Enum, JSON, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class SeverityEnum(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class StatusEnum(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[SeverityEnum] = mapped_column(
        Enum(SeverityEnum, name="severity_enum", create_constraint=True),
        default=SeverityEnum.medium,
        index=True,
    )
    status: Mapped[StatusEnum] = mapped_column(
        Enum(StatusEnum, name="status_enum", create_constraint=True),
        default=StatusEnum.open,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(50), default="manual")
    raw_log: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    asset: Mapped["Asset | None"] = relationship(back_populates="incidents")  # noqa: F821
    analysis: Mapped["Analysis | None"] = relationship(  # noqa: F821
        back_populates="incident", uselist=False, cascade="all, delete-orphan"
    )
    playbook_executions: Mapped[list["PlaybookExecution"]] = relationship(  # noqa: F821
        back_populates="incident", cascade="all, delete-orphan"
    )
