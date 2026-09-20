from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import cv2
import numpy as np

# Creating QRCodeDetector is cheap, but doing it for every transformed image adds
# measurable overhead in dataset runs. One detector per worker process is enough.
_DETECTOR = cv2.QRCodeDetector()
_MAX_SCAN_DIMENSION = 2600


@dataclass
class DecodedQR:
    payload: str
    bbox: list[list[float]] | None
    method: str


def _normalize_points(points) -> list[list[float]] | None:
    if points is None:
        return None
    arr = np.asarray(points, dtype=float).reshape(-1, 2)
    return [[round(float(x), 2), round(float(y), 2)] for x, y in arr]


def _decode_once(image: np.ndarray, method: str) -> list[DecodedQR]:
    found: list[DecodedQR] = []

    try:
        ok, decoded_info, points, _ = _DETECTOR.detectAndDecodeMulti(image)
        if ok and decoded_info:
            for index, payload in enumerate(decoded_info):
                payload = (payload or "").strip()
                if not payload:
                    continue
                box = _normalize_points(points[index]) if points is not None and len(points) > index else None
                found.append(DecodedQR(payload, box, f"{method}:multi"))
    except cv2.error:
        pass

    if found:
        return found

    try:
        payload, points, _ = _DETECTOR.detectAndDecode(image)
        payload = (payload or "").strip()
        if payload:
            found.append(DecodedQR(payload, _normalize_points(points), f"{method}:single"))
    except cv2.error:
        pass

    return found


def _bounded(image: np.ndarray) -> np.ndarray:
    """Keep very large screenshots from turning every fallback into a huge image."""
    height, width = image.shape[:2]
    largest = max(height, width)
    if largest <= _MAX_SCAN_DIMENSION:
        return image
    scale = _MAX_SCAN_DIMENSION / largest
    return cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)


def _variants(image: np.ndarray) -> Iterable[tuple[str, np.ndarray]]:
    image = _bounded(image)
    yield "original", image

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image
    yield "grayscale", gray

    height, width = gray.shape[:2]
    smallest = min(height, width)
    if smallest < 900:
        scale = min(3.0, max(1.5, 900 / max(1, smallest)))
        yield "upscaled", cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield "otsu", otsu

    # 90-degree rotations are cheap and cover phone screenshots with lost EXIF
    # orientation. Arbitrary-angle recovery belongs in the benchmark/future work.
    yield "rotate-90", cv2.rotate(gray, cv2.ROTATE_90_CLOCKWISE)
    yield "rotate-180", cv2.rotate(gray, cv2.ROTATE_180)
    yield "rotate-270", cv2.rotate(gray, cv2.ROTATE_90_COUNTERCLOCKWISE)


def decode_qr_from_image(image: np.ndarray) -> list[DecodedQR]:
    seen: set[str] = set()
    results: list[DecodedQR] = []

    for method, variant in _variants(image):
        for item in _decode_once(variant, method):
            if item.payload in seen:
                continue
            seen.add(item.payload)
            results.append(item)
        if results:
            break

    return results


def decode_qr_from_bytes(content: bytes) -> list[DecodedQR]:
    image = cv2.imdecode(np.frombuffer(content, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("The uploaded image could not be decoded.")
    return decode_qr_from_image(image)
