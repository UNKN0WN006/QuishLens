from __future__ import annotations

from pathlib import Path

from app.config import ALLOWED_IMAGE_EXTENSIONS
from .pdf_scanner import scan_pdf_bytes
from .qr_detector import decode_qr_from_bytes


def scan_file(filename: str, content: bytes) -> tuple[list[dict], str, list[str]]:
    extension = Path(filename).suffix.lower()
    if extension in ALLOWED_IMAGE_EXTENSIONS:
        decoded = decode_qr_from_bytes(content)
        artifacts = [
            {
                "payload": item.payload,
                "page": None,
                "bbox": item.bbox,
                "decode_method": item.method,
            }
            for item in decoded
        ]
        return artifacts, "", []
    if extension == ".pdf":
        return scan_pdf_bytes(content)
    raise ValueError("Unsupported file type. Use PNG, JPG, WEBP, BMP, or PDF.")
