from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class DashboardSummaryOut(_CamelBase):
    open_incidents: int = 0
    critical_incidents: int = 0
    active_playbooks: int = 0
    cves_ingested_today: int = 0
    avg_bwvs_score: float = 0.0
    last_updated: datetime | None = None


class IncidentTrendOut(_CamelBase):
    date: str
    count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class SeverityDistributionOut(_CamelBase):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class RecentActivityOut(_CamelBase):
    id: str
    event_type: str
    title: str
    severity: str | None = None
    created_at: datetime | None = None


class RiskHeatmapOut(_CamelBase):
    asset_id: str
    asset_name: str
    bwvs_score: float | None = None
    risk_level: str = "Low"
    incident_count: int = 0


class ExecutiveSummaryOut(_CamelBase):
    mttr_hours: float = 0.0
    incidents_this_month: int = 0
    incidents_last_month: int = 0
    top_threat_categories: list[dict] = []
    compliance_status: str = "compliant"
    total_financial_exposure: dict = {}


class KPIOut(_CamelBase):
    name: str
    value: float | int | str
    unit: str = ""
    trend: str = "stable"
    delta: float = 0.0
    description: str = ""
