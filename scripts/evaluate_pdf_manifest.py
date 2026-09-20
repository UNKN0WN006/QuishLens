from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

import pandas as pd

from common import coerce_binary_label, metrics_dict, write_summary
from app.scanner.file_scanner import scan_file
from app.service import QuishLensService


def parse_args():
    p = argparse.ArgumentParser(description="Evaluate QuishLens on labeled PDFs or image documents using a manifest CSV.")
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--path-column", default="path")
    p.add_argument("--label-column", default="label")
    p.add_argument("--positive-label", default=None)
    p.add_argument("--root", type=Path, default=None)
    p.add_argument("--max-rows", type=int, default=2_000)
    p.add_argument("--risk-threshold", type=int, default=60, help="Risk score at or above this value is predicted malicious.")
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
    service = QuishLensService()
    y_true=[]; y_pred=[]; y_score=[]; latencies=[]
    rows=[]; failures=0; qr_files=0
    for rel_path, raw_label in frame[[args.path_column, args.label_column]].itertuples(index=False, name=None):
        path = Path(rel_path)
        if not path.is_absolute(): path = root / path
        start = perf_counter()
        try:
            artifacts, text, limitations = scan_file(path.name, path.read_bytes())
            qr_files += int(bool(artifacts))
            selected = next((a["payload"] for a in artifacts if "." in a["payload"] and " " not in a["payload"]), None)
            score = service.analyze_url(selected, text)["risk"]["score"] if selected else 0
            truth = coerce_binary_label(raw_label, args.positive_label)
            pred = int(score >= args.risk_threshold)
            latency = (perf_counter()-start)*1000
            y_true.append(truth); y_pred.append(pred); y_score.append(score/100); latencies.append(latency)
            rows.append({"path":str(path),"truth":truth,"prediction":pred,"risk_score":score,"qr_count":len(artifacts),"latency_ms":latency})
        except Exception as exc:
            failures += 1
            rows.append({"path":str(path),"error":type(exc).__name__})

    metrics = metrics_dict(y_true,y_pred,y_score,latencies) if y_true else {}
    metrics["files_with_decoded_qr_rate"] = qr_files / len(frame) if len(frame) else 0
    metrics["processing_failure_rate"] = failures / len(frame) if len(frame) else 0
    name=args.name or args.manifest.stem
    write_summary(name,len(frame),metrics,[f"Risk threshold={args.risk_threshold}","Document-level prediction is based on the first decoded URL QR in each file."])
    out=Path("results")/f"{args.manifest.stem}_document_predictions.csv"; out.parent.mkdir(exist_ok=True)
    pd.DataFrame(rows).to_csv(out,index=False)
    print(json.dumps({"dataset":name,"samples":len(frame),"metrics":metrics,"predictions":str(out)},indent=2))


if __name__ == "__main__":
    main()
