from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np

from .payment_features import extract_payment_features, payment_vector


class PaymentQRModelService:
    def __init__(self, model_path: Path, metadata_path: Path):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.model = None
        self.metadata: dict = {}
        self.load()

    @property
    def loaded(self) -> bool:
        return self.model is not None

    def load(self) -> None:
        self.model = None
        self.metadata = {}
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None
        if self.metadata_path.exists():
            try:
                self.metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            except Exception:
                self.metadata = {}

    def predict_payload(self, payload: str) -> dict:
        features = extract_payment_features(payload)
        if self.model is None:
            return {"available": False, "probability": None, "label": None, "features": features, "model_name": None}
        matrix = np.asarray([payment_vector(features)], dtype=float)
        try:
            if hasattr(self.model, "predict_proba"):
                classes = list(getattr(self.model, "classes_", [0, 1]))
                index = classes.index(1) if 1 in classes else -1
                probability = float(self.model.predict_proba(matrix)[0, index])
            else:
                probability = float(self.model.predict(matrix)[0])
        except Exception:
            return {"available": False, "probability": None, "label": None, "features": features, "model_name": None}
        return {
            "available": True,
            "probability": round(probability, 4),
            "label": "suspicious" if probability >= 0.5 else "benign_like",
            "features": features,
            "model_name": self.metadata.get("model", self.model.__class__.__name__),
            "training_dataset": self.metadata.get("dataset"),
            "research_only": bool(self.metadata.get("research_only", True)),
        }
