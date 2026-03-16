from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class LedgerBlockOut(_CamelBase):
    id: int
    block_hash: str
    prev_hash: str
    event_type: str
    entity_id: str | None = None
    payload: dict
    created_at: datetime | None = None


class PaginatedLedgerOut(_CamelBase):
    items: list[LedgerBlockOut]
    total: int
    page: int
    limit: int


class ChainVerificationOut(_CamelBase):
    valid: bool
    block_count: int
    first_invalid_block: int | None = None
