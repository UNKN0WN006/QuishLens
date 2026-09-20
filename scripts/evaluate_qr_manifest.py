from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

import pandas as pd

from common import coerce_binary_label, metrics_dict, write_summary
from app.analysis.url_features import extract_url_features
from app.analysis.model_service import URLModelService
from app.config import MODEL_META_PATH, MODEL_PATH
from app.scanner.qr_detector import decode_qr_from_bytes


def parse_args():
    p = argparse.ArgumentParser(description="Evaluate QR decode success and URL classification from a manifest CSV.")
    p.add_argument("--manifest", required=True, type=Path, help="CSV containing image path + label columns.")
    p.add_argument("--path-column", default="path")
    p.add_argument("--label-column", default="label")
    p.add_argument("--positive-label", default=None)
    p.add_argument("--root", type=Path, default=None, help="Root directory for relative image paths.")
    p.add_argument("--max-rows", type=int, default=10_000)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--name", default=None)
    return p.parse_args()


def main():
    args = parse_args()
    frame = pd.read_csv(args.manifest)
    for col in (args.path_column, args.label_column):
        if col not in frame.columns:
            raise SystemExit(f"Missing column {col!r}. Available: {', '.join(map(str, frame.columns))}")
    if args.max_rows and len(frame) > args.max_rows:
        frame = frame.sample(args.max_rows, random_state=42)

    root = args.root or args.manifest.parent
    model = URLModelService(MODEL_PATH, MODEL_META_PATH)
    total = 0; decoded_count = 0
    y_true = []; y_pred = []; y_score = []; latencies = []
    failures = []
    for rel_path, raw_label in frame[[args.path_column, args.label_column]].itertuples(index=False, name=None):
        total += 1
        path = Path(rel_path)
        if not path.is_absolute():
            path = root / path
        start = perf_counter()
        try:
            decoded = decode_qr_from_bytes(path.read_bytes())
            url_payload = next((x.payload for x in decoded if "." in x.payload and " " not in x.payload), None)
            if not url_payload:
                failures.append({"path": str(path), "reason": "no_url_qr_decoded"})
                continue
            decoded_count += 1
            score = float(model.predict(extract_url_features(url_payload))["phishing_probability"])
            truth = coerce_binary_label(raw_label, args.positive_label)
            y_true.append(truth); y_score.append(score); y_pred.append(int(score >= args.threshold))
            latencies.append((perf_counter() - start) * 1000)
        except Exception as exc:
            failures.append({"path": str(path), "reason": type(exc).__name__})

    metrics = metrics_dict(y_true, y_pred, y_score, latencies) if y_true else {}
    metrics["qr_decode_rate"] = decoded_count / total if total else 0.0
    metrics["decoded_and_classified"] = decoded_count
    metrics["total_files"] = total
    name = args.name or args.manifest.stem
    write_summary(name, total, metrics, ["QR classification metrics include only successfully decoded URL payloads."])
    out = Path("results") / f"{args.manifest.stem}_qr_failures.csv"
    out.parent.mkdir(exist_ok=True)
    pd.DataFrame(failures).to_csv(out, index=False)
    print(json.dumps({"dataset": name, "metrics": metrics, "failures_csv": str(out)}, indent=2))


if __name__ == "__main__":
    main()
