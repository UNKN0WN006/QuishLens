from __future__ import annotations

import cv2
import numpy as np
import pymupdf

from app.config import MAX_PDF_PAGES, MAX_TEXT_CHARS, PDF_RENDER_DPI
from .qr_detector import decode_qr_from_bytes, decode_qr_from_image


def _pixmap_to_bgr(pix: pymupdf.Pixmap) -> np.ndarray:
    data = np.frombuffer(pix.samples, dtype=np.uint8)
    image = data.reshape(pix.height, pix.width, pix.n)
    if pix.n == 4:
        return cv2.cvtColor(image, cv2.COLOR_RGBA2BGR)
    if pix.n == 3:
        return cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
    return cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)


def _scan_embedded_images(document: pymupdf.Document, page: pymupdf.Page, page_number: int) -> list[dict]:
    """Fast path for the common case: a QR is embedded as a normal image."""
    artifacts: list[dict] = []
    seen_xrefs: set[int] = set()

    for image_info in page.get_images(full=True):
        xref = int(image_info[0])
        if xref in seen_xrefs:
            continue
        seen_xrefs.add(xref)
        try:
            payload = document.extract_image(xref).get("image")
            if not payload:
                continue
            for item in decode_qr_from_bytes(payload):
                artifacts.append({
                    "payload": item.payload,
                    "page": page_number,
                    "bbox": None,
                    "decode_method": f"pdf-embedded:{item.method}",
                })
        except (ValueError, RuntimeError, cv2.error):
            continue

    return artifacts


def scan_pdf_bytes(content: bytes) -> tuple[list[dict], str, list[str]]:
    artifacts: list[dict] = []
    text_parts: list[str] = []
    limitations: list[str] = []
    text_chars = 0

    try:
        document = pymupdf.open(stream=content, filetype="pdf")
    except Exception as exc:
        raise ValueError(f"The PDF could not be opened safely: {exc}") from exc

    with document:
        page_count = document.page_count
        if page_count > MAX_PDF_PAGES:
            limitations.append(f"Only the first {MAX_PDF_PAGES} of {page_count} PDF pages were scanned.")

        for index in range(min(page_count, MAX_PDF_PAGES)):
            page = document[index]

            if text_chars < MAX_TEXT_CHARS:
                try:
                    page_text = page.get_text("text")
                    text_parts.append(page_text)
                    text_chars += len(page_text)
                except Exception:
                    pass

            page_number = index + 1
            quick_hits = _scan_embedded_images(document, page, page_number)
            if quick_hits:
                artifacts.extend(quick_hits)
                continue

            # Rendering catches vector QR codes and flattened/scanned pages.
            pix = page.get_pixmap(dpi=PDF_RENDER_DPI, alpha=False)
            for item in decode_qr_from_image(_pixmap_to_bgr(pix)):
                artifacts.append({
                    "payload": item.payload,
                    "page": page_number,
                    "bbox": item.bbox,
                    "decode_method": f"pdf-render:{item.method}",
                })

    # Keep only the first occurrence of each page/payload pair.
    unique: list[dict] = []
    seen: set[tuple[int | None, str]] = set()
    for item in artifacts:
        key = (item.get("page"), item["payload"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique, "\n".join(text_parts)[:MAX_TEXT_CHARS], limitations
