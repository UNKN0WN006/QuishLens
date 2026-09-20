from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np

from .url_features import model_vector


class URLModelService:
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

    def predict(self, features: dict) -> dict:
        if self.model is None:
            return self._heuristic_fallback(features)
        try:
            probability = self._probabilities(np.asarray([model_vector(features)], dtype=float))[0]
            return self._result(float(probability), "trained_model")
        except Exception:
            return self._heuristic_fallback(features)

    def predict_many(self, feature_rows: list[dict]) -> list[dict]:
        """Batch inference for dataset evaluation; the web scanner still uses predict()."""
        if not feature_rows:
            return []
        if self.model is None:
            return [self._heuristic_fallback(row) for row in feature_rows]

        try:
            matrix = np.asarray([model_vector(row) for row in feature_rows], dtype=float)
            return [self._result(float(p), "trained_model") for p in self._probabilities(matrix)]
        except Exception:
            return [self._heuristic_fallback(row) for row in feature_rows]

    def _probabilities(self, matrix: np.ndarray) -> np.ndarray:
        if hasattr(self.model, "predict_proba"):
            classes = list(getattr(self.model, "classes_", [0, 1]))
            probabilities = self.model.predict_proba(matrix)
            positive_index = classes.index(1) if 1 in classes else -1
            return probabilities[:, positive_index]
        return np.asarray(self.model.predict(matrix), dtype=float)

    def _result(self, probability: float, source: str) -> dict:
        return {
            "label": "phishing" if probability >= 0.5 else "benign",
            "phishing_probability": round(probability, 4),
            "source": source,
            "model_name": self.metadata.get("model", self.model.__class__.__name__ if self.model else "fallback"),
        }

    @staticmethod
    def _heuristic_fallback(features: dict) -> dict:
        score = 0.08
        score += 0.18 if features.get("uses_ip_address") else 0
        score += 0.15 if features.get("contains_at_symbol") else 0
        score += 0.12 if features.get("contains_punycode") else 0
        score += 0.12 if features.get("uses_shortener") else 0
        score += min(0.2, 0.04 * int(features.get("suspicious_token_count", 0)))
        score += 0.08 if int(features.get("subdomain_count", 0)) >= 3 else 0
        score += 0.06 if int(features.get("url_length", 0)) >= 100 else 0
        score += 0.06 if float(features.get("hostname_entropy", 0)) >= 3.8 else 0
        score -= 0.05 if features.get("uses_https") else 0
        probability = max(0.01, min(0.99, score))
        return {
            "label": "phishing" if probability >= 0.5 else "benign",
            "phishing_probability": round(probability, 4),
            "source": "heuristic_fallback",
            "model_name": "transparent heuristic fallback",
        }
