import logging
import os

import joblib
import numpy as np
import torch

from app.preprocessor import preprocess, MODELS_DIR, INPUT_DIM
from app.models.lstm_autoencoder import LSTMAutoencoder

logger = logging.getLogger(__name__)

# ── Configurable weights from environment ───────────────────────────────
IF_WEIGHT = float(os.getenv("IF_WEIGHT", "0.4"))
LSTM_WEIGHT = float(os.getenv("LSTM_WEIGHT", "0.6"))
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.15"))
RECONSTRUCTION_THRESHOLD = float(os.getenv("RECONSTRUCTION_THRESHOLD", "140.0"))

# ── Load KMeans ─────────────────────────────────────────────────────────
_kmeans_path = os.path.join(MODELS_DIR, "kmeans.joblib")
KMEANS_AVAILABLE = False
kmeans = None
if os.path.exists(_kmeans_path):
    kmeans = joblib.load(_kmeans_path)
    KMEANS_AVAILABLE = True
    logger.info("Loaded KMeans from %s (%d clusters)", _kmeans_path, kmeans.n_clusters)
else:
    logger.warning("kmeans.joblib not found — cluster-aware IF scoring disabled")

# ── Load Isolation Forest models ────────────────────────────────────────
_iso_path = os.path.join(MODELS_DIR, "iso_models.joblib")
_iso_single_path = os.path.join(MODELS_DIR, "isolation_forest.joblib")
IF_AVAILABLE = False
iso_models: dict = {}
iso_forest = None

if os.path.exists(_iso_path):
    iso_models = joblib.load(_iso_path)
    IF_AVAILABLE = True
    logger.info("Loaded per-cluster IF models from %s (%d clusters)", _iso_path, len(iso_models))
elif os.path.exists(_iso_single_path):
    iso_forest = joblib.load(_iso_single_path)
    IF_AVAILABLE = True
    logger.info("Loaded single Isolation Forest from %s", _iso_single_path)
else:
    logger.error(
        "No Isolation Forest artifacts found. "
        "Run the notebook to generate models/iso_models.joblib"
    )

# ── Load LSTM Autoencoder ───────────────────────────────────────────────
_lstm_path = os.path.join(MODELS_DIR, "lstm_autoencoder.pt")
LSTM_AVAILABLE = False
lstm_model = None

try:
    if not os.path.exists(_lstm_path):
        raise FileNotFoundError(f"lstm_autoencoder.pt not found at {_lstm_path}")
    lstm_model = LSTMAutoencoder(input_dim=INPUT_DIM, hidden_dim=64)
    lstm_model.load_state_dict(
        torch.load(_lstm_path, map_location="cpu", weights_only=True)
    )
    lstm_model.eval()
    LSTM_AVAILABLE = True
    logger.info("Loaded LSTM Autoencoder from %s (input_dim=%d)", _lstm_path, INPUT_DIM)
except Exception as e:
    logger.warning("LSTM Autoencoder unavailable — falling back to IF only: %s", e)


def _if_score(pca_arr: np.ndarray) -> tuple[float, float, int]:
    """Compute Isolation Forest anomaly score.

    Returns (score_0_1, confidence, cluster_id).
    """
    cluster_id = 0
    if KMEANS_AVAILABLE:
        cluster_id = int(kmeans.predict(pca_arr)[0])

    if iso_models and cluster_id in iso_models:
        if_raw = iso_models[cluster_id].decision_function(pca_arr)[0]
    elif iso_forest is not None:
        if_raw = iso_forest.decision_function(pca_arr)[0]
    else:
        return 0.0, 0.0, cluster_id

    # Sigmoid: more negative decision_function → higher anomaly score
    score = 1.0 / (1.0 + np.exp(if_raw))
    confidence = float(abs(if_raw) / (abs(if_raw) + 1.0))
    return float(score), confidence, cluster_id


def _lstm_score(scaled_arr: np.ndarray) -> tuple[float, float]:
    """Compute LSTM Autoencoder reconstruction error score and confidence (0-1)."""
    if not LSTM_AVAILABLE:
        return 0.0, 0.0
    tensor = torch.FloatTensor(scaled_arr).unsqueeze(0)
    with torch.no_grad():
        reconstructed = lstm_model(tensor)
        mse = float(torch.mean((tensor - reconstructed) ** 2))
    anomaly_score = min(mse / RECONSTRUCTION_THRESHOLD, 1.0)
    lstm_conf = min(abs(mse - RECONSTRUCTION_THRESHOLD * 0.5) / (RECONSTRUCTION_THRESHOLD * 0.5), 1.0)
    return anomaly_score, lstm_conf


def score(features: dict) -> dict:
    """Run hybrid anomaly scoring pipeline.

    Pipeline: Scale → PCA → (IF + LSTM) → weighted ensemble.
    """
    scaled, pca_arr = preprocess(features)

    if_s, if_conf, cluster_id = _if_score(pca_arr)
    lstm_s, lstm_conf = _lstm_score(scaled)

    if LSTM_AVAILABLE and IF_AVAILABLE:
        hybrid = IF_WEIGHT * if_s + LSTM_WEIGHT * lstm_s
        confidence = IF_WEIGHT * if_conf + LSTM_WEIGHT * lstm_conf
    elif LSTM_AVAILABLE:
        hybrid = lstm_s
        confidence = lstm_conf
    else:
        hybrid = if_s
        confidence = if_conf

    return {
        "score": round(float(hybrid), 4),
        "confidence": round(float(confidence), 4),
        "cluster_id": str(cluster_id) if KMEANS_AVAILABLE else None,
        "suppressed": confidence < CONFIDENCE_THRESHOLD,
    }
