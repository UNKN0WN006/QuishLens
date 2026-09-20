from __future__ import annotations

import argparse
import json
from pathlib import Path

import cv2
import numpy as np
import pandas as pd

from common import write_summary
from app.scanner.qr_detector import decode_qr_from_image


def transformations(image: np.ndarray):
    yield "original", image
    yield "rotate_15", rotate(image, 15)
    yield "rotate_45", rotate(image, 45)
    yield "blur_3", cv2.GaussianBlur(image, (3, 3), 0)
    yield "blur_7", cv2.GaussianBlur(image, (7, 7), 0)
    yield "downscale_50", cv2.resize(cv2.resize(image, None, fx=.5, fy=.5, interpolation=cv2.INTER_AREA), (image.shape[1], image.shape[0]), interpolation=cv2.INTER_NEAREST)
    yield "jpeg_quality_35", jpeg_roundtrip(image, 35)
    yield "low_contrast", cv2.convertScaleAbs(image, alpha=.45, beta=70)
    yield "noise", add_noise(image, 12)


def rotate(image: np.ndarray, angle: float):
    h, w = image.shape[:2]
    center = (w / 2, h / 2)
    matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
    cos = abs(matrix[0, 0]); sin = abs(matrix[0, 1])
    new_w = int(h * sin + w * cos); new_h = int(h * cos + w * sin)
    matrix[0, 2] += new_w / 2 - center[0]
    matrix[1, 2] += new_h / 2 - center[1]
    return cv2.warpAffine(image, matrix, (new_w, new_h), borderValue=(255,255,255))


def jpeg_roundtrip(image: np.ndarray, quality: int):
    ok, encoded = cv2.imencode(".jpg", image, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return cv2.imdecode(encoded, cv2.IMREAD_COLOR) if ok else image


def add_noise(image: np.ndarray, sigma: float):
    noise = np.random.default_rng(42).normal(0, sigma, image.shape).astype(np.float32)
    return np.clip(image.astype(np.float32) + noise, 0, 255).astype(np.uint8)


def main():
    p = argparse.ArgumentParser(description="Measure QR decoder robustness under image transformations.")
    p.add_argument("--image", required=True, type=Path)
    p.add_argument("--expected", default=None, help="Expected decoded payload; defaults to payload decoded from original image.")
    p.add_argument("--output", type=Path, default=Path("results/adversarial_qr.csv"))
    args = p.parse_args()

    image = cv2.imread(str(args.image))
    if image is None:
        raise SystemExit("Could not read image.")
    baseline = decode_qr_from_image(image)
    expected = args.expected or (baseline[0].payload if baseline else None)
    if not expected:
        raise SystemExit("Original image did not decode and --expected was not provided.")

    rows = []
    for name, transformed in transformations(image):
        decoded = decode_qr_from_image(transformed)
        payloads = [x.payload for x in decoded]
        rows.append({"transformation": name, "decoded": expected in payloads, "decoded_payloads": " | ".join(payloads)})

    args.output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(args.output, index=False)
    rate = sum(row["decoded"] for row in rows) / len(rows)
    metrics = {"qr_decode_rate": rate, "transformations": len(rows)}
    write_summary(f"Adversarial QR: {args.image.name}", len(rows), metrics, ["Measures decode robustness, not phishing classification."])
    print(json.dumps({"expected": expected, "decode_rate": rate, "rows": rows}, indent=2))


if __name__ == "__main__":
    main()
