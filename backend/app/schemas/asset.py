from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class AssetCreate(_CamelBase):
    name: str
    asset_type: str = "web_server"
    ip_address: str | None = None
    subnet: str | None = None
    criticality: int = 5
    business_unit: str | None = None
    owner: str | None = None
    is_internet_facing: bool = False
    tags: dict | None = None


class AssetUpdate(_CamelBase):
    name: str | None = None
    asset_type: str | None = None
    ip_address: str | None = None
    subnet: str | None = None
    criticality: int | None = None
    business_unit: str | None = None
    owner: str | None = None
    is_internet_facing: bool | None = None
    tags: dict | None = None


class AssetOut(_CamelBase):
    id: str
    name: str
    asset_type: str
    ip_address: str | None = None
    subnet: str | None = None
    criticality: int
    business_unit: str | None = None
    owner: str | None = None
    is_internet_facing: bool = False
    tags: dict | None = None
    vulnerabilities_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AssetDetailOut(AssetOut):
    incident_count: int = 0
    avg_bwvs: float | None = None


class PaginatedAssetsOut(_CamelBase):
    items: list[AssetOut]
    total: int
    page: int
    limit: int


class AssetRiskOut(_CamelBase):
    bwvs_score: float | None = None
    risk_level: str = "Low"
    open_incidents: int = 0
    last_incident_date: datetime | None = None
