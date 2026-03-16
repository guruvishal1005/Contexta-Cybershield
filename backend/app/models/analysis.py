import uuid

from sqlalchemy import String, Float, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    analyst_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    intel_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    forensics_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    business_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    consensus: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    bwvs_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    blast_radius: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    analysis_duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="analysis")  # noqa: F821
