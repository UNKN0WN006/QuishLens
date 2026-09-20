from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from app.analysis.brand_detector import analyze_brand_impersonation
from app.analysis.context_nlp import analyze_context
from app.analysis.explain import build_explanations
from app.analysis.model_service import URLModelService
from app.analysis.risk_engine import calculate_risk
from app.analysis.threat_intel import ThreatIntelStore
from app.analysis.url_features import extract_url_features, normalize_url
from app.config import MODEL_META_PATH, MODEL_PATH, THREAT_DOMAINS_PATH, THREAT_URLS_PATH
from app.schemas import ScanResponse, Signal


def _looks_like_url(value: str) -> bool:
    value = (value or "").strip().lower()
    return value.startswith(("http://", "https://")) or ("." in value and " " not in value)


class QuishLensService:
    def __init__(self):
        self.model = URLModelService(MODEL_PATH, MODEL_META_PATH)
        self.threat_intel = ThreatIntelStore(THREAT_URLS_PATH, THREAT_DOMAINS_PATH)

    def refresh(self) -> None:
        self.model.load()
        self.threat_intel.reload()

    def analyze_url(self, raw_url: str, context_text: str = "") -> dict[str, Any]:
        normalized = normalize_url(raw_url)
        url_features = extract_url_features(normalized)
        context = analyze_context(context_text)
        brand = analyze_brand_impersonation(normalized, context_text)
        threat = self.threat_intel.lookup(normalized)
        model_result = self.model.predict(url_features)
        risk = calculate_risk(url_features, model_result, brand, threat, context)
        technical, plain = build_explanations(
            risk["verdict"], risk["score"], risk, brand, threat, context
        )

        signals: list[dict] = []
        signals.append({
            "key": "model",
            "label": "URL classifier",
            "level": "danger" if model_result["phishing_probability"] >= 0.7 else "warning" if model_result["phishing_probability"] >= 0.4 else "safe",
            "value": f"{model_result['phishing_probability']:.0%}",
            "detail": f"Source: {model_result['model_name']} ({model_result['source']}).",
        })
        signals.append({
            "key": "threat_intel",
            "label": "Threat-intelligence match",
            "level": "danger" if threat["matched"] else "safe",
            "value": threat["matched"],
            "detail": "Matched local URL/domain intelligence." if threat["matched"] else "No match in the loaded local threat-intelligence snapshot.",
        })
        signals.append({
            "key": "brand",
            "label": "Brand impersonation",
            "level": "danger" if brand["impersonation_detected"] else "safe",
            "value": brand["impersonation_detected"],
            "detail": _brand_detail(brand),
        })

        warning_features = [
            ("ip", "Raw IP destination", url_features["uses_ip_address"], "The URL uses an IP address rather than a normal domain."),
            ("punycode", "Punycode", url_features["contains_punycode"], "Punycode can be legitimate but is also used in lookalike domains."),
            ("shortener", "URL shortener", url_features["uses_shortener"], "A shortener hides the final destination."),
            ("at", "@ character", url_features["contains_at_symbol"], "An @ symbol can make the effective destination less obvious."),
        ]
        for key, label, present, detail in warning_features:
            signals.append({"key": key, "label": label, "level": "warning" if present else "safe", "value": present, "detail": detail})

        if url_features["suspicious_tokens"]:
            signals.append({
                "key": "tokens",
                "label": "Security-sensitive URL terms",
                "level": "warning",
                "value": ", ".join(url_features["suspicious_tokens"]),
                "detail": "These words are not malicious by themselves; they are used only as supporting evidence.",
            })

        if context.get("available"):
            signals.append({
                "key": "context",
                "label": "Document/social-engineering context",
                "level": "warning" if context.get("manipulation_score", 0) >= 25 else "info",
                "value": context.get("manipulation_score", 0),
                "detail": _context_detail(context),
            })

        return {
            "normalized_url": normalized,
            "features": url_features,
            "model": model_result,
            "brand": brand,
            "threat_intel": threat,
            "context": context,
            "risk": risk,
            "signals": signals,
            "explanation": technical,
            "plain_language": plain,
        }

    def make_scan_response(
        self,
        filename: str,
        file_type: str,
        artifacts: list[dict],
        extracted_text: str,
        limitations: list[str],
        started_at: float,
    ) -> ScanResponse:
        selected = next((item["payload"] for item in artifacts if _looks_like_url(item["payload"])), None)
        if selected:
            analysis = self.analyze_url(selected, extracted_text)
            score = analysis["risk"]["score"]
            verdict = analysis["risk"]["verdict"]
            explanation = analysis["explanation"]
            plain = analysis["plain_language"]
            signals = [Signal(**item) for item in analysis["signals"]]
            url_analysis = analysis
            context_analysis = analysis["context"]
        else:
            context_analysis = analyze_context(extracted_text)
            url_analysis = None
            score = 15 if artifacts else 0
            verdict = "low"
            if artifacts:
                explanation = "A QR code was decoded, but its payload was not recognized as a web URL. QuishLens did not attempt to execute or open the payload."
                plain = "A QR code was found, but it does not look like a normal website link. Do not open unfamiliar QR content unless you know who created it."
            else:
                explanation = "No decodable QR code was found in the submitted file. This does not prove that the document is safe; QuishLens only reports what its current static checks can observe."
                plain = "No readable QR code was found. The file could still contain other kinds of scams or harmful content, so only trust it if you know where it came from."
            signals = []

        elapsed_ms = round((time.perf_counter() - started_at) * 1000, 1)
        return ScanResponse(
            scan_id=str(uuid.uuid4()),
            filename=Path(filename).name,
            file_type=file_type,
            qr_found=bool(artifacts),
            qr_count=len(artifacts),
            artifacts=artifacts,
            selected_payload=selected,
            extracted_text_preview=(extracted_text[:1200] if extracted_text else None),
            url_analysis=url_analysis,
            context_analysis=context_analysis,
            signals=signals,
            risk_score=score,
            verdict=verdict,
            explanation=explanation,
            plain_language=plain,
            limitations=limitations,
            elapsed_ms=elapsed_ms,
        )


def _brand_detail(brand: dict) -> str:
    best = brand.get("best_match") or {}
    if brand.get("impersonation_detected"):
        expected = ", ".join(best.get("expected_domains", [])[:3])
        return f"Possible {best.get('brand', 'brand')} impersonation. Expected domains include {expected}."
    if best and best.get("legitimate"):
        return f"The detected {best.get('brand')} brand appears to use a recognized domain."
    return "No strong brand/domain mismatch was detected."


def _context_detail(context: dict) -> str:
    categories = context.get("categories", {})
    active = [name.replace("_", " ") for name, terms in categories.items() if terms]
    if not active:
        return "No strong urgency, credential, payment, or pressure language was detected in the extracted text."
    return "Detected language related to: " + ", ".join(active) + "."
