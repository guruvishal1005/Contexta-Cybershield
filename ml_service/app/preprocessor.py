import json
import logging
import os

import joblib
import numpy as np

logger = logging.getLogger(__name__)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.environ.get("MODEL_PATH", os.path.join(BASE, "models"))

# ── Load feature order ──────────────────────────────────────────────────
_feature_order_path = os.path.join(MODELS_DIR, "feature_order.json")
if os.path.exists(_feature_order_path):
    with open(_feature_order_path) as f:
        FEATURE_ORDER: list[str] = json.load(f)
    logger.info("Loaded feature order from %s (%d features)", _feature_order_path, len(FEATURE_ORDER))
else:
    # Fallback: standard CIC-IDS2017 58-feature set (same order as synthetic_network_flows.csv)
    FEATURE_ORDER = [
        "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min",
        "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min",
        "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s", "Flow Pkts/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s",
        "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
        "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt",
        "Fwd Act Data Pkts", "Fwd Seg Size Min",
        "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ]
    logger.warning(
        "feature_order.json not found — using hardcoded CIC-IDS2017 fallback (%d features). "
        "Run the notebook to generate models/feature_order.json for guaranteed correctness.",
        len(FEATURE_ORDER),
    )

INPUT_DIM = len(FEATURE_ORDER)

# ── Load scaler ─────────────────────────────────────────────────────────
_scaler_path = os.path.join(MODELS_DIR, "scaler.joblib")
if not os.path.exists(_scaler_path):
    raise FileNotFoundError(
        f"scaler.joblib not found at {_scaler_path}. "
        "Run the notebook first to generate model artifacts."
    )
scaler = joblib.load(_scaler_path)
logger.info("Loaded StandardScaler from %s", _scaler_path)

# ── Load PCA ────────────────────────────────────────────────────────────
_pca_path = os.path.join(MODELS_DIR, "pca.joblib")
PCA_AVAILABLE = False
pca = None
if os.path.exists(_pca_path):
    pca = joblib.load(_pca_path)
    PCA_AVAILABLE = True
    logger.info("Loaded PCA from %s (%d components)", _pca_path, pca.n_components_)
else:
    logger.warning("pca.joblib not found — PCA step will be skipped")


def preprocess(features: dict) -> tuple[np.ndarray, np.ndarray]:
    """Scale input features and optionally apply PCA.

    Returns (scaled, pca_transformed).
    If PCA is unavailable, pca_transformed equals scaled.
    """
    row = [float(features.get(col, 0.0)) for col in FEATURE_ORDER]
    arr = np.array(row, dtype=np.float32).reshape(1, -1)
    scaled = scaler.transform(arr)
    pca_arr = pca.transform(scaled) if PCA_AVAILABLE else scaled
    return scaled, pca_arr
