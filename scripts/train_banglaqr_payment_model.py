"""Train the optional payment-QR anomaly model from BanglaQR-Quish.

This model is deliberately scoped to research on BanglaQR-style synthetic payment
payloads. It is supporting evidence, not a claim that it can prove a real payee is
fraudulent.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.analysis.payment_features import PAYMENT_FEATURES, extract_payment_features, payment_vector  # noqa: E402
from app.scanner.qr_detector import decode_qr_from_bytes  # noqa: E402

PREFIX = "BanglaQR-Quish A Balanced Synthetic QR Image Datas/"


def _sample(frame: pd.DataFrame, per_group: int, seed: int) -> pd.DataFrame:
    parts = []
    for attack, group in frame.groupby("attack_type", sort=False):
        n = min(per_group, len(group))
        parts.append(group.sample(n=n, random_state=seed))
    return pd.concat(parts, ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset_zip", type=Path)
    parser.add_argument("--per-attack", type=int, default=1500, help="Rows sampled from each of benign_valid, URL injection, and redirection")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-out", type=Path, default=ROOT / "app" / "models" / "payment_qr_classifier.joblib")
    parser.add_argument("--meta-out", type=Path, default=ROOT / "app" / "models" / "payment_qr_classifier.meta.json")
    args = parser.parse_args()

    with zipfile.ZipFile(args.dataset_zip) as outer:
        metadata = pd.read_csv(io.BytesIO(outer.read(PREFIX + "metadata.csv")))
        rows = _sample(metadata, args.per_attack, args.seed)
        benign_zip = zipfile.ZipFile(io.BytesIO(outer.read(PREFIX + "benign.zip")))
        malicious_zip = zipfile.ZipFile(io.BytesIO(outer.read(PREFIX + "malicious.zip")))

        vectors = []
        labels = []
        attacks = []
        decoded = 0
        for row in rows.to_dict("records"):
            is_malicious = str(row["label"]).lower() == "malicious"
            archive = malicious_zip if is_malicious else benign_zip
            folder = "malicious" if is_malicious else "benign"
            member = f"{folder}/{row['image_name']}.png"
            hits = decode_qr_from_bytes(archive.read(member))
            if not hits:
                continue
            decoded += 1
            features = extract_payment_features(hits[0].payload)
            vectors.append(payment_vector(features))
            labels.append(int(is_malicious))
            attacks.append(row["attack_type"])

        benign_zip.close()
        malicious_zip.close()

    X = np.asarray(vectors, dtype=float)
    y = np.asarray(labels, dtype=int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=args.seed, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=220,
        max_depth=12,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
    }
    importance = sorted(zip(PAYMENT_FEATURES, model.feature_importances_), key=lambda pair: pair[1], reverse=True)

    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_out)
    metadata_out = {
        "model": "RandomForestClassifier (payment QR anomaly)",
        "dataset": "BanglaQR-Quish",
        "research_only": True,
        "sampled_rows": int(len(rows)),
        "decoded_rows": int(decoded),
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "features": PAYMENT_FEATURES,
        "metrics_internal_holdout": metrics,
        "top_feature_importance": [{"feature": name, "importance": float(score)} for name, score in importance[:10]],
        "training_sample_image_names": rows["image_name"].astype(str).tolist(),
        "note": "Internal hold-out numbers describe this synthetic dataset only; use independent datasets before making general claims.",
    }
    args.meta_out.write_text(json.dumps(metadata_out, indent=2), encoding="utf-8")
    print(json.dumps(metadata_out, indent=2))


if __name__ == "__main__":
    main()
