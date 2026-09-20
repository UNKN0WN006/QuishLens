from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from common import ROOT, coerce_binary_label, metrics_dict, write_summary
from app.analysis.url_features import MODEL_FEATURES, extract_url_features, model_vector
from app.config import MODEL_META_PATH, MODEL_PATH


def parse_args():
    p = argparse.ArgumentParser(description="Train QuishLens' URL classifier from an arbitrary CSV schema.")
    p.add_argument("--csv", required=True, type=Path)
    p.add_argument("--url-column", required=True)
    p.add_argument("--label-column", required=True)
    p.add_argument("--positive-label", default=None, help="Exact label value that should be treated as phishing/malicious.")
    p.add_argument("--max-rows", type=int, default=100_000)
    p.add_argument("--trees", type=int, default=260)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--random-state", type=int, default=42)
    return p.parse_args()


def main():
    args = parse_args()
    frame = pd.read_csv(args.csv)
    missing = [c for c in (args.url_column, args.label_column) if c not in frame.columns]
    if missing:
        raise SystemExit(f"Missing column(s): {', '.join(missing)}. Available: {', '.join(map(str, frame.columns))}")

    frame = frame[[args.url_column, args.label_column]].dropna().drop_duplicates(subset=[args.url_column])
    if args.max_rows and len(frame) > args.max_rows:
        frame = frame.sample(args.max_rows, random_state=args.random_state)

    vectors, labels = [], []
    started = perf_counter()
    for url, label in frame.itertuples(index=False, name=None):
        features = extract_url_features(str(url))
        vectors.append(model_vector(features))
        labels.append(coerce_binary_label(label, args.positive_label))

    X = np.asarray(vectors, dtype=float)
    y = np.asarray(labels, dtype=int)
    if len(set(y.tolist())) < 2:
        raise SystemExit("Training data must contain both benign (0) and phishing/malicious (1) examples.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=args.random_state
    )
    model = RandomForestClassifier(
        n_estimators=args.trees,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=args.random_state,
    )
    model.fit(X_train, y_train)
    scores = model.predict_proba(X_test)[:, list(model.classes_).index(1)]
    preds = (scores >= 0.5).astype(int)
    metrics = metrics_dict(y_test, preds, scores)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    metadata = {
        "model": "RandomForestClassifier",
        "feature_names": MODEL_FEATURES,
        "training_source": str(args.csv),
        "rows": int(len(frame)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "random_state": args.random_state,
        "metrics": metrics,
        "feature_extraction_seconds": round(perf_counter() - started, 3),
    }
    MODEL_META_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    write_summary(f"Internal test: {args.csv.name}", len(X_test), metrics, ["Internal held-out test from training corpus."])

    print(json.dumps(metadata, indent=2))
    print(f"\nSaved model: {MODEL_PATH}")
    print(f"Saved metadata: {MODEL_META_PATH}")


if __name__ == "__main__":
    main()
