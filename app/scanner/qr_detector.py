from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import cv2
import numpy as np

try:
    from pyzbar.pyzbar import ZBarSymbol, decode as zbar_decode
except Exception:  # Optional fallback; OpenCV remains the baseline decoder.
    ZBarSymbol = None
    zbar_decode = None

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




def _decode_with_zbar(image: np.ndarray, method: str) -> list[DecodedQR]:
    """Fallback decoder restricted to QR symbols only (never 1D barcodes)."""
    if zbar_decode is None or ZBarSymbol is None:
        return []
    found: list[DecodedQR] = []
    try:
        for item in zbar_decode(image, symbols=[ZBarSymbol.QRCODE]):
            payload = item.data.decode("utf-8", errors="replace").strip()
            if not payload:
                continue
            rect = item.rect
            bbox = [
                [float(rect.left), float(rect.top)],
                [float(rect.left + rect.width), float(rect.top)],
                [float(rect.left + rect.width), float(rect.top + rect.height)],
                [float(rect.left), float(rect.top + rect.height)],
            ]
            found.append(DecodedQR(payload, bbox, f"{method}:zbar-qr"))
    except Exception:
        return []
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

    bounded = _bounded(image)

    # ZBar is very fast on clean, ordinary QR images and is restricted above to
    # QRCODE symbols only. Trying it first makes large dataset runs much faster.
    for item in _decode_with_zbar(bounded, "original"):
        if item.payload not in seen:
            seen.add(item.payload)
            results.append(item)
    if results:
        return results

    # OpenCV then gets the harder cases plus preprocessing/rotation fallbacks.
    for method, variant in _variants(bounded):
        decoded = _decode_once(variant, method)
        if not decoded and method != "original":
            decoded = _decode_with_zbar(variant, method)
        for item in decoded:
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
