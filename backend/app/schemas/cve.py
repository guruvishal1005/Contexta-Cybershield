from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class CVEOut(_CamelBase):
    id: str
    description: str = ""
    cvss_score: float | None = None
    is_kev: bool = False
    exploit_available: bool = False
    exploit_maturity: str | None = None
    bwvs_score: float | None = None
    priority_rank: float | None = None
    published_date: datetime | None = None
    modified_date: datetime | None = None
    affected_products: Any = None


class CVEDetailOut(CVEOut):
    cvss_vector: str | None = None
    epss_score: float | None = None
    cwe_ids: Any = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CVECreate(_CamelBase):
    id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    is_kev: bool = False
    published_date: datetime | None = None
    modified_date: datetime | None = None
    affected_products: Any = None
    cwe_ids: Any = None
    exploit_available: bool = False
    exploit_maturity: str | None = None


class CVERiskOut(_CamelBase):
    cve_id: str
    bwvs_score: float
    risk_level: str
    priority_rank: float


class PaginatedCVEOut(_CamelBase):
    items: list[CVEOut]
    total: int
    page: int
    limit: int
