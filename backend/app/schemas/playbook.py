from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class PlaybookStepOut(_CamelBase):
    id: int
    name: str
    type: str = "manual"
    responsible_team: str = ""
    timeout_minutes: int = 30
    escalate_on_timeout: bool = False
    description: str = ""


class PlaybookOut(_CamelBase):
    id: str
    name: str
    description: str = ""
    trigger_conditions: dict = {}
    steps: list[PlaybookStepOut] = []
    estimated_total_minutes: int = 0


class PlaybookExecutionOut(_CamelBase):
    id: str
    playbook_id: str
    incident_id: str
    status: str
    current_step: int = 0
    step_results: list = []
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None


class PlaybookExecutionDetailOut(PlaybookExecutionOut):
    playbook: PlaybookOut | None = None


class ExecutePlaybookRequest(_CamelBase):
    incident_id: str


class StepCompleteRequest(_CamelBase):
    result: str = "success"
    notes: str = ""
