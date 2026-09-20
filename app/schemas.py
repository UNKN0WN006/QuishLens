from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


Verdict = Literal["low", "suspicious", "high", "critical"]


class Signal(BaseModel):
    key: str
    label: str
    level: Literal["info", "safe", "warning", "danger"]
    value: str | int | float | bool | None = None
    detail: str | None = None


class QRArtifact(BaseModel):
    payload: str
    page: int | None = None
    bbox: list[list[float]] | None = None
    decode_method: str = "opencv"


class ScanResponse(BaseModel):
    scan_id: str
    filename: str
    file_type: str
    qr_found: bool
    qr_count: int = 0
    artifacts: list[QRArtifact] = Field(default_factory=list)
    selected_payload: str | None = None
    payload_analysis: dict[str, Any] | None = None
    artifact_analyses: list[dict[str, Any]] = Field(default_factory=list)
    extracted_text_preview: str | None = None
    url_analysis: dict[str, Any] | None = None
    context_analysis: dict[str, Any] | None = None
    signals: list[Signal] = Field(default_factory=list)
    risk_score: int = 0
    verdict: Verdict = "low"
    explanation: str
    plain_language: str
    limitations: list[str] = Field(default_factory=list)
    elapsed_ms: float = 0


class URLRequest(BaseModel):
    url: str = Field(min_length=3, max_length=4096)
    context: str | None = Field(default=None, max_length=40_000)


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: str | None = None
    bootstrap_model: bool = False
    threat_intel_urls: int
    threat_intel_domains: int
    payment_model_loaded: bool = False
    payment_model_name: str | None = None
