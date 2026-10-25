
from pathlib import Path
import random

import joblib
import numpy as np
import pandas as pd
import psutil


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "xgboost_process_detector.pkl"
SCALER_PATH = BASE_DIR / "process_scaler.pkl"
DATASET_PATH = BASE_DIR / "Obfuscated-MalMem2022.csv"

CLASS_NAMES = {
    0: "Benign",
    1: "Ransomware",
    2: "Spyware",
    3: "Trojan",
}

LABEL_COLUMNS = {"Class", "Category", "Family"}


class DetectionEngine:
    """Model-backed dataset simulation and basic OS process inventory."""

    def __init__(self):
        for path in (MODEL_PATH, SCALER_PATH, DATASET_PATH):
            if not path.exists():
                raise FileNotFoundError(f"Required project file not found: {path.name}")

        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.data = pd.read_csv(DATASET_PATH)

        self.feature_columns = [
            column for column in self.data.columns
            if column not in LABEL_COLUMNS
            and pd.api.types.is_numeric_dtype(self.data[column])
        ]

        if len(self.feature_columns) != 55:
            raise ValueError(
                f"Expected 55 numeric features, found {len(self.feature_columns)}."
            )

        if getattr(self.model, "n_features_in_", None) != len(self.feature_columns):
            raise ValueError("Model feature count does not match dataset features.")

        if getattr(self.scaler, "n_features_in_", None) != len(self.feature_columns):
            raise ValueError("Scaler feature count does not match dataset features.")

    def _predict(self, sample, source, details=None):
        """Return a structured prediction for a feature row."""
        sample = sample.loc[:, self.feature_columns].astype(float)

        if sample.isna().any().any():
            raise ValueError("Sample contains missing feature values.")

        scaled = self.scaler.transform(sample)
        prediction = int(self.model.predict(scaled)[0])
        probabilities = self.model.predict_proba(scaled)[0]

        # Use the model's own class labels to associate each probability.
        probability_map = {
            CLASS_NAMES[int(class_id)]: round(float(prob) * 100, 2)
            for class_id, prob in zip(self.model.classes_, probabilities)
        }

        return {
            "source": source,
            "prediction": CLASS_NAMES.get(prediction, f"Unknown ({prediction})"),
            "predicted_class_id": prediction,
            "confidence_percent": round(float(np.max(probabilities)) * 100, 2),
            "probabilities": probability_map,
            "details": details or {},
            "note": (
                "Dataset-based classification; this is not a verified live-memory scan."
                if source == "dataset_simulation"
                else "Prediction based on supplied process features; not a verified malware diagnosis."
            ),
        }

    def simulate(self, threat_type="Ransomware"):
        """Classify a randomly selected dataset row for a chosen family."""
        requested = threat_type.strip().lower()

        if requested not in {"benign", "ransomware", "spyware", "trojan"}:
            raise ValueError("Choose Benign, Ransomware, Spyware, or Trojan.")

        if requested == "benign":
            matches = self.data[
                self.data["Category"].astype(str).str.lower().eq("benign")
            ]
        else:
            matches = self.data[
                self.data["Category"].astype(str).str.lower().str.startswith(
                    requested + "-"
                )
            ]

        if matches.empty:
            raise ValueError(f"No dataset samples found for {threat_type}.")

        sample_row = matches.sample(n=1).iloc[0]
        sample = sample_row[self.feature_columns].to_frame().T

        metrics = {}
        for feature in (
            "svcscan.nservices",
            "handles.nfile",
            "malfind.ninjections",
        ):
            if feature in sample.columns:
                metrics[feature] = float(sample.iloc[0][feature])

        return self._predict(
            sample,
            source="dataset_simulation",
            details={
                "requested_type": threat_type,
                "dataset_category": str(sample_row["Category"]),
                "behavioral_metrics": metrics,
            },
        )

    def list_processes(self):
        """List OS processes and basic accessible telemetry."""
        processes = []

        for proc in psutil.process_iter(["pid", "name", "num_threads"]):
            try:
                processes.append({
                    "pid": proc.info["pid"],
                    "name": proc.info["name"] or "Unknown",
                    "threads": proc.info["num_threads"],
                    "status": "Available",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return sorted(processes, key=lambda item: item["pid"])

    def get_process(self, pid):
        """Retrieve basic OS telemetry for one process; no malware verdict."""
        try:
            proc = psutil.Process(int(pid))
            with proc.oneshot():
                return {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "threads": proc.num_threads(),
                    "memory_rss_bytes": proc.memory_info().rss,
                    "status": proc.status(),
                    "source": "live_os_telemetry",
                    "note": (
                        "Basic OS telemetry only. Memory-forensic features are "
                        "not collected, so no malware prediction is made here."
                    ),
                }
        except (ValueError, psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            raise ValueError(f"Could not inspect PID {pid}: {exc}") from exc


if __name__ == "__main__":
    engine = DetectionEngine()

    print("Detection engine loaded.")
    print(f"Dataset records: {len(engine.data):,}")
    print(f"Numeric model features: {len(engine.feature_columns)}")

    result = engine.simulate("Ransomware")
    print("\nExample dataset simulation:")
    print(result)

    print("\nFirst five running processes:")
    for process in engine.list_processes()[:5]:
        print(process)
