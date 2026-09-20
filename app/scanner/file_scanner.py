from __future__ import annotations

from pathlib import Path

from app.config import ALLOWED_IMAGE_EXTENSIONS
from .pdf_scanner import scan_pdf_bytes
from .qr_detector import inspect_qr_bytes


def scan_file(filename: str, content: bytes) -> tuple[list[dict], str, list[str]]:
    extension = Path(filename).suffix.lower()

    if extension in ALLOWED_IMAGE_EXTENSIONS:
        decoded, candidate_detected = inspect_qr_bytes(content)
        artifacts = [
            {
                "payload": item.payload,
                "page": None,
                "bbox": item.bbox,
                "decode_method": item.method,
            }
            for item in decoded
        ]
        limitations: list[str] = []
        if not artifacts and candidate_detected:
            limitations.append(
                "A QR-shaped symbol was detected, but no decoder could recover its payload. "
                "This often happens with heavily stylised, damaged, low-resolution, or partially cropped codes. "
                "Try the original image or a sharper screenshot with the full quiet margin visible."
            )
        elif not artifacts:
            limitations.append(
                "No standard QR payload could be decoded. The image may contain another 2D code type rather than a QR code."
            )
        return artifacts, "", limitations

    if extension == ".pdf":
        return scan_pdf_bytes(content)

    raise ValueError("Unsupported file type. Use PNG, JPG, WEBP, BMP, or PDF.")
