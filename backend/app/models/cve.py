from datetime import datetime

from sqlalchemy import String, Float, Boolean, Text, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class CVE(Base):
    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    published_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    modified_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    affected_products: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cwe_ids: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_maturity: Mapped[str | None] = mapped_column(String(30), nullable=True)
    bwvs_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    priority_rank: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
