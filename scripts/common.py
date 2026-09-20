from __future__ import annotations

import json
import sys
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def coerce_binary_label(value, positive_label: str | None = None) -> int:
    if positive_label is not None:
        return int(str(value).strip().lower() == positive_label.strip().lower())
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "phishing", "phish", "malicious", "bad", "unsafe"}:
        return 1
    if text in {"0", "false", "no", "benign", "legitimate", "safe", "good"}:
        return 0
    try:
        return int(float(value) > 0)
    except Exception as exc:
        raise ValueError(f"Cannot map label {value!r} to 0/1. Pass --positive-label if needed.") from exc


def metrics_dict(y_true, y_pred, y_score=None, latencies_ms=None) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if y_score is not None and len(set(y_true.tolist())) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
    else:
        metrics["roc_auc"] = None
    if latencies_ms:
        metrics["avg_latency_ms"] = float(np.mean(latencies_ms))
        metrics["p95_latency_ms"] = float(np.percentile(latencies_ms, 95))
    return metrics


def write_summary(dataset: str, samples: int, metrics: dict, notes: list[str] | None = None) -> Path:
    from app.config import BENCHMARK_SUMMARY_PATH

    payload = {
        "available": True,
        "dataset": dataset,
        "samples": int(samples),
        "metrics": metrics,
        "notes": notes or [],
    }
    BENCHMARK_SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    BENCHMARK_SUMMARY_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return BENCHMARK_SUMMARY_PATH
