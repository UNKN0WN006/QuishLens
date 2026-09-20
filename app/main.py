from __future__ import annotations

import json
import mimetypes
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app.config import (
    ALLOWED_EXTENSIONS,
    BENCHMARK_SUMMARY_PATH,
    MAX_UPLOAD_BYTES,
    SCAN_HISTORY_LIMIT,
    STATIC_DIR,
)
from app.scanner.file_scanner import scan_file
from app.schemas import HealthResponse, ScanResponse, URLRequest
from app.service import QuishLensService

app = FastAPI(
    title="QuishLens",
    version="1.1.0",
    description="Pre-click QR phishing analysis for images, PDFs, and URLs.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

service = QuishLensService()
history: deque[dict] = deque(maxlen=SCAN_HISTORY_LIMIT)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        model_loaded=service.model.loaded,
        model_name=service.model.metadata.get("model") if service.model.loaded else None,
        bootstrap_model=bool(service.model.metadata.get("bootstrap_only", False)),
        threat_intel_urls=len(service.threat_intel.urls),
        threat_intel_domains=len(service.threat_intel.domains),
    )


@app.post("/api/analyze-url")
def analyze_url(payload: URLRequest):
    try:
        return service.analyze_url(payload.url, payload.context or "")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/scan", response_model=ScanResponse)
async def scan(file: UploadFile = File(...)):
    started = time.perf_counter()
    filename = Path(file.filename or "upload.bin").name
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Use PNG, JPG, JPEG, WEBP, BMP, or PDF files.")

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File is too large. Maximum size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    try:
        artifacts, text, limitations = await run_in_threadpool(scan_file, filename, content)
        response = service.make_scan_response(
            filename=filename,
            file_type=mimetypes.guess_type(filename)[0] or extension.lstrip("."),
            artifacts=artifacts,
            extracted_text=text,
            limitations=limitations,
            started_at=started,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="The scanner could not process this file safely.") from exc

    history.appendleft({
        "scan_id": response.scan_id,
        "filename": response.filename,
        "risk_score": response.risk_score,
        "verdict": response.verdict,
        "qr_count": response.qr_count,
        "elapsed_ms": response.elapsed_ms,
    })
    return response


@app.get("/api/history")
def get_history():
    return {"items": list(history)}


@app.get("/api/benchmark/summary")
def benchmark_summary():
    if BENCHMARK_SUMMARY_PATH.exists():
        try:
            return json.loads(BENCHMARK_SUMMARY_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "available": False,
        "message": "No benchmark summary has been generated yet. Run scripts/evaluate_url_dataset.py or scripts/evaluate_qr_manifest.py.",
    }


@app.post("/api/reload")
def reload_assets():
    service.refresh()
    return {
        "ok": True,
        "model_loaded": service.model.loaded,
        "threat_intel_urls": len(service.threat_intel.urls),
        "threat_intel_domains": len(service.threat_intel.domains),
    }
