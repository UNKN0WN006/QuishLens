from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import cv2
import numpy as np

try:
    import zxingcpp
except Exception as exc:  # Optional at runtime; the app still has other decoders.
    zxingcpp = None
    _ZXING_ERROR = str(exc)
else:
    _ZXING_ERROR = None

try:
    from pyzbar.pyzbar import ZBarSymbol, decode as zbar_decode
except Exception as exc:  # pyzbar can be unavailable when the native ZBar DLL is missing.
    ZBarSymbol = None
    zbar_decode = None
    _ZBAR_ERROR = str(exc)
else:
    _ZBAR_ERROR = None

# One detector per worker process avoids repeatedly creating OpenCV detector state
# during benchmark runs.
_DETECTOR = cv2.QRCodeDetector()
_MAX_SCAN_DIMENSION = 2800


@dataclass
class DecodedQR:
    payload: str
    bbox: list[list[float]] | None
    method: str


def decoder_capabilities() -> dict:
    """Expose decoder availability so a broken native dependency is visible in the UI."""
    return {
        "zxingcpp": {
            "available": zxingcpp is not None,
            "error": _ZXING_ERROR,
        },
        "zbar_qr": {
            "available": zbar_decode is not None and ZBarSymbol is not None,
            "error": _ZBAR_ERROR,
        },
        "opencv_qr": {
            "available": True,
            "version": cv2.__version__,
        },
    }


def _normalize_points(points) -> list[list[float]] | None:
    if points is None:
        return None
    arr = np.asarray(points, dtype=float).reshape(-1, 2)
    return [[round(float(x), 2), round(float(y), 2)] for x, y in arr]


def _zxing_position(item) -> list[list[float]] | None:
    """Read ZXing-C++ corner coordinates without depending on one package minor version."""
    position = getattr(item, "position", None)
    if position is None:
        return None

    names = ("top_left", "top_right", "bottom_right", "bottom_left")
    points: list[list[float]] = []
    try:
        for name in names:
            p = getattr(position, name)
            points.append([round(float(p.x), 2), round(float(p.y), 2)])
    except Exception:
        return None
    return points


def _decode_with_zxing(image: np.ndarray, method: str) -> list[DecodedQR]:
    """Decode QR symbols with ZXing-C++ when available.

    ZXing-C++ is especially useful for stylised QR codes where OpenCV detects the
    square but fails to recover the payload. Only QR-family formats are accepted;
    1D barcodes are never returned by this function.
    """
    if zxingcpp is None:
        return []

    try:
        qr_format = getattr(getattr(zxingcpp, "BarcodeFormat", None), "QRCode", None)
        if qr_format is not None:
            try:
                items = zxingcpp.read_barcodes(
                    image,
                    formats=qr_format,
                    try_rotate=True,
                    try_downscale=True,
                    try_invert=True,
                )
            except TypeError:
                # Older Python bindings expose fewer keyword arguments.
                items = zxingcpp.read_barcodes(image, formats=qr_format)
        else:
            items = zxingcpp.read_barcodes(image)
    except Exception:
        return []

    found: list[DecodedQR] = []
    for item in items:
        fmt = str(getattr(item, "format", "")).lower()
        if "qr" not in fmt:
            continue
        payload = str(getattr(item, "text", "") or "").strip()
        if not payload:
            raw = getattr(item, "bytes", b"") or b""
            if isinstance(raw, (bytes, bytearray)):
                payload = bytes(raw).decode("utf-8", errors="replace").strip()
        if payload:
            found.append(DecodedQR(payload, _zxing_position(item), f"{method}:zxing-qr"))
    return found


def _decode_with_zbar(image: np.ndarray, method: str) -> list[DecodedQR]:
    """Decode with ZBar, explicitly restricted to QR symbols only."""
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


def _decode_with_opencv(image: np.ndarray, method: str) -> list[DecodedQR]:
    found: list[DecodedQR] = []

    try:
        ok, decoded_info, points, _ = _DETECTOR.detectAndDecodeMulti(image)
        if ok and decoded_info:
            for index, payload in enumerate(decoded_info):
                payload = (payload or "").strip()
                if not payload:
                    continue
                box = _normalize_points(points[index]) if points is not None and len(points) > index else None
                found.append(DecodedQR(payload, box, f"{method}:opencv-multi"))
    except cv2.error:
        pass

    if found:
        return found

    try:
        payload, points, _ = _DETECTOR.detectAndDecode(image)
        payload = (payload or "").strip()
        if payload:
            found.append(DecodedQR(payload, _normalize_points(points), f"{method}:opencv-single"))
    except cv2.error:
        pass

    return found


def _bounded(image: np.ndarray) -> np.ndarray:
    """Bound giant screenshots before expensive fallback transforms."""
    height, width = image.shape[:2]
    largest = max(height, width)
    if largest <= _MAX_SCAN_DIMENSION:
        return image
    scale = _MAX_SCAN_DIMENSION / largest
    return cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)


def _with_quiet_zone(image: np.ndarray) -> np.ndarray:
    """Add a white margin; screenshots frequently crop a QR's required quiet zone."""
    h, w = image.shape[:2]
    border = max(12, round(min(h, w) * 0.06))
    value = 255 if image.ndim == 2 else (255, 255, 255)
    return cv2.copyMakeBorder(image, border, border, border, border, cv2.BORDER_CONSTANT, value=value)


def _variants(image: np.ndarray) -> Iterable[tuple[str, np.ndarray]]:
    image = _bounded(image)
    yield "original", image
    yield "quiet-zone", _with_quiet_zone(image)

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image
    yield "grayscale", gray

    # Stylised/dotted QRs often benefit from preserving hard cell edges.
    height, width = gray.shape[:2]
    smallest = min(height, width)
    if smallest < 1200:
        scale = min(4.0, max(1.75, 1200 / max(1, smallest)))
        yield "upscaled-nearest", cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
        yield "upscaled-cubic", cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield "otsu", _with_quiet_zone(otsu)

    adaptive = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5
    )
    yield "adaptive", _with_quiet_zone(adaptive)

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    yield "contrast", _with_quiet_zone(clahe)

    # Inverted QR codes are uncommon but valid in some renderers.
    yield "inverted", _with_quiet_zone(cv2.bitwise_not(gray))

    # Orientation metadata is often lost in screenshots and chat apps.
    yield "rotate-90", cv2.rotate(gray, cv2.ROTATE_90_CLOCKWISE)
    yield "rotate-180", cv2.rotate(gray, cv2.ROTATE_180)
    yield "rotate-270", cv2.rotate(gray, cv2.ROTATE_90_COUNTERCLOCKWISE)


def _decode_variant(image: np.ndarray, method: str) -> list[DecodedQR]:
    # Independent decoders are intentional. A stylised QR can be visible to one
    # implementation and completely undecodable to another.
    for decoder in (_decode_with_zxing, _decode_with_zbar, _decode_with_opencv):
        found = decoder(image, method)
        if found:
            return found
    return []


def qr_candidate_detected(image: np.ndarray) -> bool:
    """Return True when OpenCV sees QR geometry even though no payload decoded."""
    bounded = _bounded(image)
    for variant in (bounded, _with_quiet_zone(bounded)):
        try:
            ok, points = _DETECTOR.detect(variant)
            if ok and points is not None:
                return True
        except cv2.error:
            pass
    return False


def decode_qr_from_image(image: np.ndarray) -> list[DecodedQR]:
    seen: set[str] = set()
    results: list[DecodedQR] = []

    for method, variant in _variants(image):
        for item in _decode_variant(variant, method):
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


def inspect_qr_bytes(content: bytes) -> tuple[list[DecodedQR], bool]:
    """Decode a QR and separately report whether QR geometry was merely detected."""
    image = cv2.imdecode(np.frombuffer(content, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("The uploaded image could not be decoded.")
    decoded = decode_qr_from_image(image)
    return decoded, bool(decoded) or qr_candidate_detected(image)
