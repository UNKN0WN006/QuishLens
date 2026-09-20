from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"
STATIC_DIR = BASE_DIR / "app" / "static"
MODEL_DIR = BASE_DIR / "app" / "models"

MAX_UPLOAD_BYTES = 12 * 1024 * 1024
MAX_PDF_PAGES = 20
PDF_RENDER_DPI = 190
MAX_TEXT_CHARS = 40_000
SCAN_HISTORY_LIMIT = 50

ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf"}
ALLOWED_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_DOCUMENT_EXTENSIONS

MODEL_PATH = MODEL_DIR / "url_classifier.joblib"
MODEL_META_PATH = MODEL_DIR / "url_classifier.meta.json"
THREAT_URLS_PATH = DATA_DIR / "threat_intel" / "known_urls.txt"
THREAT_DOMAINS_PATH = DATA_DIR / "threat_intel" / "known_domains.txt"
BENCHMARK_SUMMARY_PATH = RESULTS_DIR / "benchmark_summary.json"
