from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import psutil
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# Project structure expected:
# Suspicious-Process-Detection/
#   hybrid_process_detector.pkl
#   process_scaler.pkl
#   Obfuscated-MalMem2022.csv
#   backend/
#     main.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "hybrid_process_detector.pkl"
SCALER_PATH = PROJECT_ROOT / "process_scaler.pkl"
DATASET_PATH = PROJECT_ROOT / "Obfuscated-MalMem2022.csv"

CLASS_LABELS = {
    0: "Benign",
    1: "Ransomware",
    2: "Spyware",
    3: "Trojan",
}
SUPPORTED_THREATS = {"Ransomware", "Spyware", "Trojan"}

app = FastAPI(
    title="Sentinel AI - Suspicious Process Detection API",
    description=(
        "Provides live Windows process telemetry and controlled ML simulations "
        "using samples from the project's memory-forensics dataset."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


_model = None
_scaler = None
_dataset = None
_feature_columns: list[str] = []
_load_error: str | None = None


class SimulationRequest(BaseModel):
    threat_type: str = Field(..., description="Ransomware, Spyware, or Trojan")


def _load_artifacts() -> None:
    """Load model, scaler and dataset once, and validate feature compatibility."""
    global _model, _scaler, _dataset, _feature_columns, _load_error

    if _model is not None and _scaler is not None and _dataset is not None:
        return

    try:
        missing = [
            str(path.name)
            for path in (MODEL_PATH, SCALER_PATH, DATASET_PATH)
            if not path.exists()
        ]
        if missing:
            raise FileNotFoundError(
                "Missing project artifact(s): "
                + ", ".join(missing)
                + ". Place these files in the project root folder."
            )

        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        dataset = pd.read_csv(DATASET_PATH)

        # This matches the feature-selection approach used by the training script.
        feature_frame = (
            dataset.drop(columns=["Class", "Category", "Family"], errors="ignore")
            .select_dtypes(include=[np.number])
        )
        feature_columns = feature_frame.columns.tolist()

        if not feature_columns:
            raise ValueError("No numeric model features were found in the dataset.")

        expected_features = getattr(scaler, "n_features_in_", None)
        if expected_features is not None and expected_features != len(feature_columns):
            raise ValueError(
                f"Feature mismatch: scaler expects {expected_features} features, "
                f"but the dataset produced {len(feature_columns)}. "
                "Check that the scaler and dataset come from the same training run."
            )

        model_features = getattr(model, "n_features_in_", None)
        if model_features is not None and model_features != len(feature_columns):
            raise ValueError(
                f"Feature mismatch: model expects {model_features} features, "
                f"but the dataset produced {len(feature_columns)}."
            )

        _model = model
        _scaler = scaler
        _dataset = dataset
        _feature_columns = feature_columns
        _load_error = None

    except Exception as exc:
        _load_error = f"{type(exc).__name__}: {exc}"
        raise


def _display_class(value: Any) -> str:
    """Convert model class values into readable labels."""
    try:
        numeric = int(value)
        if numeric in CLASS_LABELS:
            return CLASS_LABELS[numeric]
    except (TypeError, ValueError):
        pass

    text_value = str(value).strip()
    for label in ("Benign", "Ransomware", "Spyware", "Trojan"):
        if label.lower() in text_value.lower():
            return label
    return text_value


def _find_simulation_rows(threat_type: str) -> tuple[pd.DataFrame, str]:
    """Find rows belonging to the requested class/category in the CSV."""
    assert _dataset is not None
    wanted = threat_type.lower()

    # Prefer descriptive text columns, if present.
    for column in ("Category", "Family", "Class"):
        if column not in _dataset.columns:
            continue
        values = _dataset[column].astype(str)
        mask = values.str.contains(wanted, case=False, na=False)
        matches = _dataset.loc[mask]
        if not matches.empty:
            return matches, column

    # Fallback for datasets whose Class column contains encoded labels.
    encoded_value = {
        "ransomware": 1,
        "spyware": 2,
        "trojan": 3,
    }[wanted]
    if "Class" in _dataset.columns:
        numeric_class = pd.to_numeric(_dataset["Class"], errors="coerce")
        matches = _dataset.loc[numeric_class == encoded_value]
        if not matches.empty:
            return matches, "Class (encoded label)"

    raise HTTPException(
        status_code=404,
        detail=(
            f"No dataset rows were found for {threat_type}. "
            "Check the Class, Category and Family values in the CSV."
        ),
    )


@app.get("/")
def root():
    return {
        "message": "Sentinel AI API is running",
        "health": "/health",
        "model_status": "/api/model-status",
        "processes": "/api/processes",
        "simulation": "/api/simulate",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/model-status")
def model_status():
    """Return whether the trained model artifacts can be loaded."""
    try:
        _load_artifacts()
        classes = getattr(_model, "classes_", [])
        estimators = []
        for item in getattr(_model, "estimators", []) or []:
            if isinstance(item, tuple) and item:
                estimators.append(str(item[0]))
            else:
                estimators.append(type(item).__name__)

        return {
            "status": "ready",
            "model_type": type(_model).__name__,
            "scaler_type": type(_scaler).__name__,
            "feature_count": len(_feature_columns),
            "scaler_feature_count": getattr(_scaler, "n_features_in_", None),
            "classes": [_display_class(value) for value in classes],
            "estimators": estimators,
            "dataset_rows": int(len(_dataset)),
            "dataset_file": DATASET_PATH.name,
            "reported_accuracy_percent": 84.85,
            "accuracy_note": (
                "Reported in the project README; this API does not recompute "
                "the evaluation metric."
            ),
        }
    except Exception as exc:
        return {
            "status": "not_ready",
            "error": _load_error or f"{type(exc).__name__}: {exc}",
            "expected_files": [
                MODEL_PATH.name,
                SCALER_PATH.name,
                DATASET_PATH.name,
            ],
        }


@app.get("/api/processes")
def get_processes():
    """Return live OS process telemetry; it intentionally does not classify them."""
    processes = []

    for proc in psutil.process_iter(
        attrs=["pid", "name", "username", "memory_info", "status"]
    ):
        try:
            info = proc.info
            memory_info = info.get("memory_info")
            memory_mb = (
                round(memory_info.rss / (1024 * 1024), 2)
                if memory_info
                else 0.0
            )
            try:
                cpu_percent = proc.cpu_percent(interval=None)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cpu_percent = 0.0

            processes.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name") or "Unknown process",
                    "username": info.get("username") or "Unknown",
                    "cpu_percent": round(float(cpu_percent), 1),
                    "memory_mb": memory_mb,
                    "os_status": info.get("status") or "Unknown",
                    "status": "Unclassified",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda item: item["cpu_percent"], reverse=True)

    return {
        "count": len(processes),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "classification_note": (
            "Live OS telemetry only. These processes are not ML-classified "
            "because the dataset's 55 memory-forensics features are not "
            "available from ordinary process telemetry."
        ),
        "processes": processes,
    }


@app.post("/api/simulate")
def simulate_threat(request: SimulationRequest):
    """
    Run the trained model on one real dataset row from the requested threat class.
    This is a controlled dataset simulation, not live malware execution/detection.
    """
    threat_type = request.threat_type.strip().title()
    if threat_type not in SUPPORTED_THREATS:
        raise HTTPException(
            status_code=400,
            detail="threat_type must be Ransomware, Spyware, or Trojan.",
        )

    try:
        _load_artifacts()
        matching_rows, source_column = _find_simulation_rows(threat_type)

        # Sample a row from the requested dataset class; never execute malware.
        sample = matching_rows.sample(n=1).iloc[0]
        feature_values = sample[_feature_columns].to_numpy(dtype=float).reshape(1, -1)
        scaled_values = _scaler.transform(feature_values)

        prediction = _model.predict(scaled_values)[0]
        predicted_label = _display_class(prediction)

        confidence = None
        probabilities: dict[str, float] = {}
        if hasattr(_model, "predict_proba"):
            raw_probabilities = _model.predict_proba(scaled_values)[0]
            model_classes = getattr(_model, "classes_", range(len(raw_probabilities)))
            for class_value, probability in zip(model_classes, raw_probabilities):
                label = _display_class(class_value)
                probabilities[label] = round(float(probability) * 100, 2)
            if probabilities:
                confidence = max(probabilities.values())

        useful_feature_names = (
            "handles.nfile",
            "handles.nhandles",
            "pslist.avg_threads",
            "pslist.nprocs",
            "malfind.ninjections",
            "svcscan.nservices",
        )
        indicators = {}
        for name in useful_feature_names:
            if name in sample.index:
                value = sample[name]
                if pd.notna(value):
                    indicators[name] = float(value)

        return {
            "mode": "controlled_dataset_simulation",
            "requested_threat": threat_type,
            "predicted_class": predicted_label,
            "confidence_percent": confidence,
            "class_probabilities": probabilities,
            "sample_source": DATASET_PATH.name,
            "matched_using": source_column,
            "available_samples": int(len(matching_rows)),
            "feature_count": len(_feature_columns),
            "feature_indicators": indicators,
            "disclaimer": (
                "This result was generated from a sample in the research dataset. "
                "It is not a live scan, does not execute malware, and does not "
                "classify the currently running Windows processes."
            ),
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Simulation failed: {type(exc).__name__}: {exc}",
        ) from exc
