
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any

import joblib
import numpy as np
import pandas as pd
import psutil

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

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

PROCESS_CACHE_SECONDS = 2.0

# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="Sentinel AI - Suspicious Process Detection API",
    description=(
        "Provides live Windows process telemetry and controlled ML "
        "simulations using memory-forensics dataset samples."
    ),
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------
# GLOBAL MODEL AND DATASET STORAGE
# --------------------------------------------------

_model = None
_scaler = None
_dataset = None

_feature_columns: list[str] = []
_benign_baseline = None

# Each threat maps to precomputed dataset row positions.
_simulation_rows: dict[str, tuple[np.ndarray, str]] = {}

_load_error: str | None = None

_model_lock = Lock()

# --------------------------------------------------
# PROCESS CACHE
# --------------------------------------------------

_process_cache: dict[str, Any] | None = None
_process_cache_time = 0.0

_process_lock = Lock()


class SimulationRequest(BaseModel):
    threat_type: str = Field(
        ...,
        description="Ransomware, Spyware, or Trojan",
    )

class ProcessScanRequest(BaseModel):
    process_name: str = Field(
        ...,
        min_length=1,
        max_length=260,
        description="Windows executable name, e.g. chrome.exe",
    )

# --------------------------------------------------
# MODEL AND DATASET LOADING
# --------------------------------------------------


def _prepare_simulation_indexes(dataset):
    indexes = {}

    if "Category" not in dataset.columns:
        raise ValueError("Dataset is missing the Category column.")

    categories = dataset["Category"].fillna("").astype(str)

    for threat in SUPPORTED_THREATS:
        threat_name = str(threat).strip().lower()

        mask = categories.str.contains(
            threat_name,
            case=False,
            na=False,
            regex=False
        )

        positions = np.flatnonzero(mask.to_numpy())

        if len(positions) > 0:
            indexes[threat_name] = (positions, "Category")

    return indexes



def _load_artifacts() -> None:
    """Load and validate all ML artifacts once."""

    global _model
    global _scaler
    global _dataset
    global _feature_columns
    global _benign_baseline
    global _simulation_rows
    global _load_error

    if (
        _model is not None
        and _scaler is not None
        and _dataset is not None
    ):
        return

    with _model_lock:

        # Another request may have loaded the artifacts while
        # this request was waiting for the lock.
        if (
            _model is not None
            and _scaler is not None
            and _dataset is not None
        ):
            return

        try:

            missing = [
                path.name
                for path in (
                    MODEL_PATH,
                    SCALER_PATH,
                    DATASET_PATH,
                )
                if not path.exists()
            ]

            if missing:
                raise FileNotFoundError(
                    "Missing project artifacts: "
                    + ", ".join(missing)
                )

            model = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)

            dataset = pd.read_csv(DATASET_PATH)

            feature_frame = (
                dataset.drop(
                    columns=["Class", "Category", "Family"],
                    errors="ignore",
                )
                .select_dtypes(include=[np.number])
            )

            feature_columns = feature_frame.columns.tolist()

            if not feature_columns:
                raise ValueError(
                    "No numeric model features found."
                )

            expected_features = getattr(
                scaler,
                "n_features_in_",
                None,
            )

            if (
                expected_features is not None
                and expected_features != len(feature_columns)
            ):
                raise ValueError(
                    f"Scaler expects {expected_features} features, "
                    f"but dataset provides {len(feature_columns)}."
                )

            model_features = getattr(
                model,
                "n_features_in_",
                None,
            )

            if (
                model_features is not None
                and model_features != len(feature_columns)
            ):
                raise ValueError(
                    f"Model expects {model_features} features, "
                    f"but dataset provides {len(feature_columns)}."
                )

            # Prepare all threat indexes once.
            simulation_rows = _prepare_simulation_indexes(dataset)

            # Prepare benign baseline for experimental live process scanning.
            if "Class" not in dataset.columns:
                raise ValueError("Dataset is missing the Class column.")

            benign_rows = dataset.loc[
                dataset["Class"].astype(str).str.lower().eq("benign"),
                feature_columns,
            ]

            if benign_rows.empty:
                raise ValueError("No benign samples found in the dataset.")

            benign_baseline = benign_rows.median()

            _model = model
            _scaler = scaler
            _dataset = dataset
            _feature_columns = feature_columns
            _simulation_rows = simulation_rows
            _benign_baseline = benign_baseline

            _load_error = None

        except Exception as exc:

            _load_error = (
                f"{type(exc).__name__}: {exc}"
            )

            raise


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def _display_class(value: Any) -> str:

    try:
        numeric = int(value)

        if numeric in CLASS_LABELS:
            return CLASS_LABELS[numeric]

    except (TypeError, ValueError):
        pass

    text_value = str(value).strip()

    for label in (
        "Benign",
        "Ransomware",
        "Spyware",
        "Trojan",
    ):

        if label.lower() in text_value.lower():
            return label

    return text_value


def _get_simulation_rows(
    threat_type: str,
) -> tuple[np.ndarray, str]:

    result = _simulation_rows.get(threat_type.lower())

    if result is None:

        raise HTTPException(
            status_code=404,
            detail=f"No dataset samples found for {threat_type}.",
        )

    return result


# --------------------------------------------------
# ROOT AND HEALTH
# --------------------------------------------------

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

    return {
        "status": "ok",
    }


# --------------------------------------------------
# MODEL STATUS
# --------------------------------------------------

@app.get("/api/model-status")
def model_status():

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
            "scaler_feature_count": getattr(
                _scaler,
                "n_features_in_",
                None,
            ),
            "classes": [
                _display_class(value)
                for value in classes
            ],
            "estimators": estimators,
            "dataset_rows": int(len(_dataset)),
            "dataset_file": DATASET_PATH.name,
            "reported_accuracy_percent": 84.85,
            "accuracy_note": (
                "Reported in the project README; "
                "not recomputed by this API."
            ),
        }

    except Exception as exc:

        return {
            "status": "not_ready",
            "error": _load_error or str(exc),
            "expected_files": [
                MODEL_PATH.name,
                SCALER_PATH.name,
                DATASET_PATH.name,
            ],
        }


# --------------------------------------------------
# LIVE PROCESS MONITORING
# --------------------------------------------------

@app.get("/api/processes")
def get_processes():

    global _process_cache
    global _process_cache_time

    now = monotonic()

    # Return cached results when still fresh.
    if (
        _process_cache is not None
        and now - _process_cache_time < PROCESS_CACHE_SECONDS
    ):
        return _process_cache

    # Prevent multiple simultaneous scans.
    with _process_lock:

        now = monotonic()

        if (
            _process_cache is not None
            and now - _process_cache_time < PROCESS_CACHE_SECONDS
        ):
            return _process_cache

        processes = []

        for proc in psutil.process_iter(
            attrs=[
                "pid",
                "name",
                "username",
                "memory_info",
                "status",
            ]
        ):

            try:

                info = proc.info

                memory_info = info.get("memory_info")

                memory_mb = (
                    round(
                        memory_info.rss / (1024 * 1024),
                        2,
                    )
                    if memory_info
                    else 0.0
                )

                try:

                    cpu_percent = proc.cpu_percent(
                        interval=None
                    )

                except (
                    psutil.AccessDenied,
                    psutil.NoSuchProcess,
                ):
                    cpu_percent = 0.0

                processes.append(
                    {
                        "pid": info.get("pid"),
                        "name": (
                            info.get("name")
                            or "Unknown process"
                        ),
                        "username": (
                            info.get("username")
                            or "Unknown"
                        ),
                        "cpu_percent": round(
                            float(cpu_percent),
                            1,
                        ),
                        "memory_mb": memory_mb,
                        "os_status": (
                            info.get("status")
                            or "Unknown"
                        ),
                        "status": "Unclassified",
                    }
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue

        processes.sort(
            key=lambda item: item["cpu_percent"],
            reverse=True,
        )

        result = {
            "count": len(processes),
            "updated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "classification_note": (
                "Live OS telemetry only. These processes are "
                "not ML-classified because the dataset's "
                "55 memory-forensics features are not "
                "available from ordinary process telemetry."
            ),
            "processes": processes,
        }

        _process_cache = result
        _process_cache_time = monotonic()

        return result


# --------------------------------------------------
# EXPERIMENTAL LIVE PROCESS ML SCANNER
# --------------------------------------------------

@app.post("/api/scan-process")
def scan_process(request: ProcessScanRequest):

    process_name = request.process_name.strip()

    if not process_name or Path(process_name).name != process_name:
        raise HTTPException(
            status_code=400,
            detail="Enter a valid executable name, e.g. chrome.exe",
        )

    try:
        _load_artifacts()

        target_proc = None

        # Find the requested running process.
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info.get("name")

                if name and name.lower() == process_name.lower():
                    target_proc = proc
                    break

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue

        if target_proc is None:
            raise HTTPException(
                status_code=404,
                detail=f"Process '{process_name}' is not currently running.",
            )

        # Start with the dataset's benign median feature vector.
        feature_vector = _benign_baseline.copy()

        observed_fields = []
        assumed_fields = []

        # Collect available process telemetry.
        try:
            num_threads = target_proc.num_threads()

            feature_vector["pslist.avg_threads"] = num_threads
            observed_fields.append("pslist.avg_threads")

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            pass

        try:
            num_handles = target_proc.num_handles()

            feature_vector["handles.nfile"] = num_handles
            feature_vector["handles.nhandles"] = num_handles

            observed_fields.extend([
                "handles.nfile",
                "handles.nhandles",
            ])

        except (
            AttributeError,
            NotImplementedError,
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            pass

        # Total number of currently running system processes.
        try:
            feature_vector["pslist.nproc"] = len(psutil.pids())
            observed_fields.append("pslist.nproc")
        except Exception:
            pass

        # This is an assumption, NOT a live memory-forensics measurement.
        if "malfind.ninjections" in feature_vector.index:
            feature_vector["malfind.ninjections"] = 0
            assumed_fields.append("malfind.ninjections")

        feature_df = pd.DataFrame(
            [feature_vector],
            columns=_feature_columns,
        )

        # Run model inference.
        with _model_lock:
            scaled_features = _scaler.transform(feature_df)

            prediction = _model.predict(scaled_features)[0]
            predicted_label = _display_class(prediction)

            probabilities = _model.predict_proba(scaled_features)[0]

            model_classes = getattr(
                _model,
                "classes_",
                range(len(probabilities)),
            )

            class_probabilities = {
                _display_class(class_value): round(
                    float(probability) * 100,
                    2,
                )
                for class_value, probability in zip(
                    model_classes,
                    probabilities,
                )
            }

        confidence = class_probabilities.get(predicted_label)

        return {
            "mode": "experimental_live_process_scan",
            "process_name": process_name,
            "pid": target_proc.pid,
            "predicted_class": predicted_label,
            "confidence_percent": confidence,
            "class_probabilities": class_probabilities,
            "feature_count": len(_feature_columns),
            "observed_fields": observed_fields,
            "assumed_fields": assumed_fields,
            "status": (
                "SAFE"
                if predicted_label == "Benign"
                else "THREAT DETECTED"
            ),
            "disclaimer": (
                "Experimental prediction only. The input uses a benign "
                "dataset baseline with a small number of live telemetry "
                "fields. It does not extract all 55 memory-forensics "
                "features and must not be treated as a verified security "
                "verdict."
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Live scan failed: {type(exc).__name__}: {exc}",
        ) from exc


# --------------------------------------------------
# CONTROLLED THREAT SIMULATION
# --------------------------------------------------

@app.post("/api/simulate")
def simulate_threat(request: SimulationRequest):

    threat_type = request.threat_type.strip().title()

    if threat_type not in SUPPORTED_THREATS:

        raise HTTPException(
            status_code=400,
            detail=(
                "threat_type must be "
                "Ransomware, Spyware, or Trojan."
            ),
        )

    try:

        _load_artifacts()

        row_positions, source_column = (
            _get_simulation_rows(threat_type)
        )

        # Select one row directly using precomputed positions.
        selected_position = np.random.choice(row_positions)

        sample = _dataset.iloc[selected_position]

        feature_values = (
            sample[_feature_columns]
            .to_numpy(dtype=float)
            .reshape(1, -1)
        )

        scaled_values = _scaler.transform(feature_values)

        prediction = _model.predict(scaled_values)[0]

        predicted_label = _display_class(prediction)

        confidence = None
        probabilities: dict[str, float] = {}

        if hasattr(_model, "predict_proba"):

            raw_probabilities = _model.predict_proba(
                scaled_values
            )[0]

            model_classes = getattr(
                _model,
                "classes_",
                range(len(raw_probabilities)),
            )

            for class_value, probability in zip(
                model_classes,
                raw_probabilities,
            ):

                label = _display_class(class_value)

                probabilities[label] = round(
                    float(probability) * 100,
                    2,
                )

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
            "available_samples": int(len(row_positions)),
            "feature_count": len(_feature_columns),
            "feature_indicators": indicators,
            "disclaimer": (
                "This result was generated from a sample "
                "in the research dataset. It is not a live "
                "scan, does not execute malware, and does "
                "not classify currently running Windows processes."
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Simulation failed: "
                f"{type(exc).__name__}: {exc}"
            ),
        ) from exc
