from pydantic import BaseModel
from typing import Optional


class ScoreRequest(BaseModel):
    features: dict[str, float]


class ScoreResponse(BaseModel):
    score: float
    confidence: float
    cluster_id: Optional[str]
    suppressed: bool


class HealthResponse(BaseModel):
    status: str
    model_version: str
    accuracy: float
    f1Score: float
    auc: float
    drift: float
    note: str
    series: list
