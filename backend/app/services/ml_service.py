import httpx

from app.config import settings

_FALLBACK = {"score": 0.0, "confidence": 0.0, "cluster_id": None, "suppressed": True}


async def get_ml_threat_score(flow_features: dict) -> dict:
    """Call the ML microservice for anomaly scoring.

    When ML_SERVICE_URL is unset, returns a zero-score fallback so the
    BWVS formula can proceed without the ML component.
    """
    ml_url = settings.ml_service_url
    if not ml_url:
        return dict(_FALLBACK)

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.post(
                f"{ml_url}/score",
                json={"features": flow_features},
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return dict(_FALLBACK)
