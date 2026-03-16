from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class IncidentCreate(_CamelBase):
    title: str
    description: str | None = None
    severity: str = "medium"
    source: str = "manual"
    raw_log: dict | None = None
    asset_id: str | None = None


class IncidentUpdate(_CamelBase):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    source: str | None = None
    asset_id: str | None = None


class IncidentOut(_CamelBase):
    id: str
    title: str
    description: str | None = None
    severity: str
    status: str
    source: str
    incident_type: str | None = None  # serialized as incidentType (camelCase), same value as source
    asset_id: str | None = None
    closed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @model_validator(mode="after")
    def populate_incident_type(self) -> "IncidentOut":
        self.incident_type = self.source
        return self


class IncidentDetailOut(IncidentOut):
    raw_log: dict | None = None
    analysis: "AnalysisOut | None" = None


class StatusUpdate(_CamelBase):
    status: str


class PaginatedIncidentsOut(_CamelBase):
    items: list[IncidentOut]
    total: int
    page: int
    limit: int


from app.schemas.analysis import AnalysisOut  # noqa: E402

IncidentDetailOut.model_rebuild()
