from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from app.schemas.cve import CVERiskOut, CVEOut


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class CVEScoreRequest(_CamelBase):
    cve_id: str
    cvss_score: float = 0.0
    exploit_maturity: str = "unknown"
    exposure: str = "unknown"
    asset_criticality: int = 5
    business_impact: float = 5.0


class BWVSResultOut(_CamelBase):
    cve_id: str
    bwvs_score: float
    risk_level: str
    breakdown: dict = {}


class TopRisksResponse(BaseModel):
    risks: list[CVEOut]


class RiskSummaryOut(_CamelBase):
    total_cves: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    average_bwvs: float = 0.0
