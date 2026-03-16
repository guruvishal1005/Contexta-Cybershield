from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class AnalysisOut(_CamelBase):
    id: str
    incident_id: str
    analyst_output: dict | None = None
    intel_output: dict | None = None
    forensics_output: dict | None = None
    business_output: dict | None = None
    response_output: dict | None = None
    consensus: dict | None = None
    bwvs_score: float | None = None
    blast_radius: dict | None = None
    analysis_duration_seconds: float | None = None
    created_at: datetime | None = None


class ConsensusReportOut(_CamelBase):
    severity: str
    confidence: float
    merged_iocs: list[dict] = []
    mitre_techniques: list[str] = []
    cve_references: list[str] = []
    ordered_response_plan: list[dict] = []
    consensus_narrative: str = ""
    bwvs_score: float | None = None
