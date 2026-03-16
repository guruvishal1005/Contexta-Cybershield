import uuid

from sqlalchemy import String, Integer, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    subnet: Mapped[str | None] = mapped_column(String(45), nullable=True)
    criticality: Mapped[int] = mapped_column(Integer, default=5)
    business_unit: Mapped[str | None] = mapped_column(String(100), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    incidents: Mapped[list["Incident"]] = relationship(  # noqa: F821
        back_populates="asset", cascade="all, delete-orphan",
        passive_deletes=True,
    )
