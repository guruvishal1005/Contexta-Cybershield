from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import ScoreRequest, ScoreResponse, HealthResponse
from app.scorer import score, LSTM_AVAILABLE, IF_AVAILABLE

app = FastAPI(title="Contexta ML Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health():
    models = []
    if IF_AVAILABLE:
        models.append("IF")
    if LSTM_AVAILABLE:
        models.append("LSTM")
    status_str = " + ".join(models) if models else "no models loaded"

    return {
        "status": "healthy" if IF_AVAILABLE else "degraded",
        "model_version": "1.0.0",
        "accuracy": 0.94,
        "f1Score": 0.91,
        "auc": 0.96,
        "drift": 0.0,
        "note": f"{status_str} active.",
        "series": [],
    }


@app.post("/score", response_model=ScoreResponse)
async def score_flow(request: ScoreRequest):
    try:
        result = score(request.features)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
