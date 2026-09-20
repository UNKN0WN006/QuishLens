from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

import pandas as pd

from scripts.common import coerce_binary_label, metrics_dict, write_summary
from app.analysis.model_service import URLModelService
from app.analysis.url_features import extract_url_features
from app.config import MODEL_META_PATH, MODEL_PATH


def parse_args():
    p = argparse.ArgumentParser(description="Evaluate QuishLens on an external URL dataset without retraining.")
    p.add_argument("--csv", required=True, type=Path)
    p.add_argument("--url-column", required=True)
    p.add_argument("--label-column", required=True)
    p.add_argument("--positive-label", default=None)
    p.add_argument("--max-rows", type=int, default=50_000)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--name", default=None)
    p.add_argument("--output", type=Path, default=None)
    return p.parse_args()


def main():
    args = parse_args()
    model = URLModelService(MODEL_PATH, MODEL_META_PATH)
    frame = pd.read_csv(args.csv)
    for col in (args.url_column, args.label_column):
        if col not in frame.columns:
            raise SystemExit(f"Column {col!r} not found. Available: {', '.join(map(str, frame.columns))}")

    frame = frame[[args.url_column, args.label_column]].dropna()
    if args.max_rows and len(frame) > args.max_rows:
        frame = frame.sample(args.max_rows, random_state=42)

    urls = frame[args.url_column].astype(str).tolist()
    labels = frame[args.label_column].tolist()

    started = perf_counter()
    feature_rows = [extract_url_features(url) for url in urls]
    feature_ms = (perf_counter() - started) * 1000

    started = perf_counter()
    predictions = model.predict_many(feature_rows)
    inference_ms = (perf_counter() - started) * 1000
    per_row_ms = inference_ms / max(1, len(urls))

    y_true = [coerce_binary_label(label, args.positive_label) for label in labels]
    y_score = [float(item["phishing_probability"]) for item in predictions]
    y_pred = [int(score >= args.threshold) for score in y_score]
    metrics = metrics_dict(y_true, y_pred, y_score, [per_row_ms] * len(urls))

    rows = [
        {"url": url, "truth": truth, "prediction": pred, "score": score}
        for url, truth, pred, score in zip(urls, y_true, y_pred, y_score)
    ]
    name = args.name or args.csv.stem
    notes = [
        f"Threshold={args.threshold}",
        f"Model source={'trained model' if model.loaded else 'heuristic fallback'}",
        f"Feature extraction={feature_ms:.1f} ms total",
        f"Batch inference={inference_ms:.1f} ms total",
    ]
    summary_path = write_summary(name, len(rows), metrics, notes)
    output = args.output or (summary_path.parent / f"{args.csv.stem}_predictions.csv")
    pd.DataFrame(rows).to_csv(output, index=False)
    print(json.dumps({"dataset": name, "samples": len(rows), "metrics": metrics, "predictions": str(output)}, indent=2))


if __name__ == "__main__":
    main()
