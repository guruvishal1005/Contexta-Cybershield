# ML Service Contract

## Endpoints

### POST /score

Request:
```json
{
  "features": {
    "Dst Port": 80.0,
    "Protocol": 6.0,
    "Flow Duration": 12345.0,
    ...
  }
}
```

Feature names must match CIC-IDS2017 column names exactly (58 features).
Missing features default to 0.0.

Response:
```json
{
  "score": 0.7234,
  "confidence": 0.8100,
  "cluster_id": "2",
  "suppressed": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| score | float | 0.0–1.0 hybrid ensemble anomaly score |
| confidence | float | 0.0–1.0 model confidence from IF decision boundary distance |
| cluster_id | string\|null | KMeans traffic cluster assignment |
| suppressed | bool | true if confidence < CONFIDENCE_THRESHOLD (0.6) |

### GET /health

Response:
```json
{
  "status": "healthy",
  "model_version": "1.0.0",
  "accuracy": 0.94,
  "f1Score": 0.91,
  "auc": 0.96,
  "drift": 0.0,
  "note": "IF + LSTM active.",
  "series": []
}
```

`f1Score` is camelCase — the frontend (`ContexaSOC.jsx`) expects this exact key.

## BWVS Integration

- ML score only enters BWVS when `suppressed=false` AND `confidence >= 0.6`
- When `suppressed=true`, ML_Threat factor is 0.0 and remaining BWVS weights renormalise
- ML_Threat weight in BWVS formula: 0.15

## Model Pipeline

The notebook (`ML_Working.ipynb`) trains the following pipeline:

1. **StandardScaler** (`models/scaler.joblib`) — 58 CIC-IDS2017 features → zero mean, unit variance
2. **PCA** (`models/pca.joblib`) — 58 features → 49 components (95% variance)
3. **KMeans** (`models/kmeans.joblib`) — 6 traffic clusters on PCA space
4. **Per-cluster Isolation Forest** (`models/iso_models.joblib`) — 6 IF models, one per cluster. Weight: 0.4
5. **LSTM Autoencoder** (`models/lstm_autoencoder.pt`) — encoder-decoder on raw scaled features. Weight: 0.6
6. XGBoost + Platt calibration — trained in notebook, reserved for future integration
7. **Confidence gate** — threshold 0.6; below this the score is suppressed

## Artifact Files

| File | Format | Required |
|------|--------|----------|
| `feature_order.json` | JSON list of strings | Recommended (fallback: hardcoded CIC-IDS2017) |
| `scaler.joblib` | sklearn StandardScaler | **Required** |
| `pca.joblib` | sklearn PCA | Optional (skipped if missing) |
| `kmeans.joblib` | sklearn KMeans | Optional (cluster_id=0 if missing) |
| `iso_models.joblib` | dict[int, IsolationForest] | **Required** (one of iso_models or isolation_forest) |
| `lstm_autoencoder.pt` | PyTorch state_dict | Optional (IF-only mode if missing) |
| `xgb_classifier.joblib` | XGBClassifier | Reserved for future use |
| `platt_calibrator.joblib` | LogisticRegression | Reserved for future use |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_PATH` | `./models` | Path to model artifacts directory |
| `RECONSTRUCTION_THRESHOLD` | `0.5` | LSTM MSE normalisation threshold |
| `CONFIDENCE_THRESHOLD` | `0.6` | Minimum confidence to not suppress score |
| `IF_WEIGHT` | `0.4` | Isolation Forest weight in ensemble |
| `LSTM_WEIGHT` | `0.6` | LSTM Autoencoder weight in ensemble |
