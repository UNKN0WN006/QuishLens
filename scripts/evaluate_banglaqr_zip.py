"""Evaluate QuishLens directly against the BanglaQR-Quish release ZIP.

The script never extracts 50,000 images to disk. It streams the nested benign.zip
and malicious.zip archives, decodes QR symbols only, runs QuishLens payload analysis,
and reports decode rate plus runtime risk classification by attack type.

Payment-redirection samples are intentionally reported separately: without a trusted
baseline or payee registry, a syntactically valid payment QR can redirect money while
remaining structurally valid. That is a real limitation, not something the evaluator
hides with a dataset-specific rule.
"""
from __future__ import annotations

import argparse
import io
import json
import random
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.analysis.qr_payload import analyze_qr_payload, payload_risk  # noqa: E402
from app.analysis.payment_model import PaymentQRModelService  # noqa: E402
from app.config import PAYMENT_MODEL_META_PATH, PAYMENT_MODEL_PATH  # noqa: E402
from app.scanner.qr_detector import decode_qr_from_bytes  # noqa: E402

PREFIX = "BanglaQR-Quish A Balanced Synthetic QR Image Datas/"


def _sample_rows(frame: pd.DataFrame, limit_per_class: int | None, seed: int) -> pd.DataFrame:
    if not limit_per_class:
        return frame.copy()
    parts = []
    for label, group in frame.groupby("label", sort=False):
        n = min(limit_per_class, len(group))
        parts.append(group.sample(n=n, random_state=seed))
    return pd.concat(parts, ignore_index=True)


def _read_nested_zip(outer: zipfile.ZipFile, member: str) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(outer.read(PREFIX + member)))


def evaluate(dataset_zip: Path, limit_per_class: int | None = None, seed: int = 42) -> dict:
    rng = random.Random(seed)
    payment_model = PaymentQRModelService(PAYMENT_MODEL_PATH, PAYMENT_MODEL_META_PATH)
    with zipfile.ZipFile(dataset_zip) as outer:
        metadata = pd.read_csv(io.BytesIO(outer.read(PREFIX + "metadata.csv")))
        excluded_training = set(payment_model.metadata.get("training_sample_image_names", [])) if payment_model.loaded else set()
        if excluded_training:
            metadata = metadata[~metadata["image_name"].astype(str).isin(excluded_training)].copy()
        rows = _sample_rows(metadata, limit_per_class, seed)
        benign_zip = _read_nested_zip(outer, "benign.zip")
        malicious_zip = _read_nested_zip(outer, "malicious.zip")

        y_true: list[int] = []
        y_pred: list[int] = []
        decoded = 0
        recognized_payment = 0
        attack_totals = Counter()
        attack_detected = Counter()
        decode_failures: list[str] = []
        examples: dict[str, list[dict]] = defaultdict(list)

        order = list(rows.to_dict("records"))
        rng.shuffle(order)
        for row in order:
            label = str(row["label"]).lower()
            attack_type = str(row["attack_type"])
            image_name = str(row["image_name"])
            archive = benign_zip if label == "benign" else malicious_zip
            folder = "benign" if label == "benign" else "malicious"
            member = f"{folder}/{image_name}.png"
            try:
                content = archive.read(member)
                hits = decode_qr_from_bytes(content)
            except Exception:
                hits = []

            expected = 1 if label == "malicious" else 0
            y_true.append(expected)
            attack_totals[attack_type] += 1

            if not hits:
                y_pred.append(0)
                decode_failures.append(image_name)
                continue

            decoded += 1
            analysis = analyze_qr_payload(hits[0].payload)
            if analysis.get("kind") == "payment":
                recognized_payment += 1
            risk = payload_risk(analysis)
            model_result = payment_model.predict_payload(hits[0].payload) if payment_model.loaded else {"available": False}
            model_score = min(70, round(max(0.0, float(model_result.get("probability") or 0) - 0.5) * 140)) if model_result.get("available") else 0
            combined_score = max(risk["score"], model_score)
            predicted = int(combined_score >= 30)
            y_pred.append(predicted)
            attack_detected[attack_type] += predicted

            if len(examples[attack_type]) < 3:
                examples[attack_type].append({
                    "image": image_name,
                    "score": combined_score,
                    "verdict": "high" if combined_score >= 60 else "suspicious" if combined_score >= 30 else "low",
                    "payment_model_probability": model_result.get("probability"),
                    "provider": ((analysis.get("payment") or {}).get("accounts") or [{}])[0].get("provider_name"),
                    "merchant": (analysis.get("payment") or {}).get("merchant_name"),
                    "flags": [flag.get("label") for flag in analysis.get("flags", [])],
                })

        benign_zip.close()
        malicious_zip.close()

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    result = {
        "dataset": "BanglaQR-Quish",
        "samples": len(y_true),
        "decode_rate": decoded / len(y_true) if y_true else 0,
        "payment_payload_recognition_rate": recognized_payment / decoded if decoded else 0,
        "metrics": {
            "accuracy": accuracy_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1": f1_score(y_true, y_pred, zero_division=0),
            "confusion_matrix": cm,
        },
        "attack_type_recall": {
            attack: (attack_detected[attack] / total if total else 0)
            for attack, total in attack_totals.items()
            if attack != "benign_valid"
        },
        "attack_type_counts": dict(attack_totals),
        "decode_failures": decode_failures[:25],
        "examples": dict(examples),
        "payment_model_loaded": payment_model.loaded,
        "excluded_payment_model_training_images": len(excluded_training),
        "important_note": (
            "Provider URL injection is detectable from payload semantics. If the optional BanglaQR-trained payment anomaly model is loaded, "
            "it can also flag synthetic payment-redirection patterns. Its score is supporting evidence only and should not be generalized "
            "to real payment ecosystems without independent validation."
        ),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset_zip", type=Path, help="Path to the outer BanglaQR-Quish ZIP")
    parser.add_argument("--limit-per-class", type=int, default=None, help="Sample this many benign and malicious rows")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "banglaqr_evaluation.json")
    args = parser.parse_args()

    result = evaluate(args.dataset_zip, args.limit_per_class, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
