from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from app.analysis.brand_detector import analyze_brand_impersonation
from app.analysis.context_nlp import analyze_context
from app.analysis.explain import build_explanations
from app.analysis.model_service import URLModelService
from app.analysis.payment_model import PaymentQRModelService
from app.analysis.qr_payload import analyze_qr_payload, payload_risk
from app.analysis.risk_engine import calculate_risk
from app.analysis.threat_intel import ThreatIntelStore
from app.analysis.url_features import extract_url_features, normalize_url
from app.config import (
    MODEL_META_PATH, MODEL_PATH, PAYMENT_MODEL_META_PATH, PAYMENT_MODEL_PATH,
    THREAT_DOMAINS_PATH, THREAT_URLS_PATH,
)
from app.schemas import ScanResponse, Signal


def _looks_like_url(value: str) -> bool:
    value = (value or "").strip().lower()
    return value.startswith(("http://", "https://")) or ("." in value and " " not in value)


class QuishLensService:
    def __init__(self):
        self.model = URLModelService(MODEL_PATH, MODEL_META_PATH)
        self.payment_model = PaymentQRModelService(PAYMENT_MODEL_PATH, PAYMENT_MODEL_META_PATH)
        self.threat_intel = ThreatIntelStore(THREAT_URLS_PATH, THREAT_DOMAINS_PATH)

    def refresh(self) -> None:
        self.model.load()
        self.payment_model.load()
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
        context_analysis = analyze_context(extracted_text)
        artifact_analyses: list[dict[str, Any]] = []

        for artifact in artifacts:
            payload = artifact.get("payload", "")
            parsed = analyze_qr_payload(payload)
            qr_risk = payload_risk(parsed)
            payment_model = self.payment_model.predict_payload(payload) if parsed.get("kind") == "payment" and parsed.get("format") == "emv_tlv" else {"available": False}
            payment_model_score = 0
            if payment_model.get("available") and payment_model.get("probability") is not None:
                payment_model_score = min(70, round(max(0.0, float(payment_model["probability"]) - 0.5) * 140))
                parsed["payment_model"] = payment_model
            urls = parsed.get("embedded_urls", [])
            web_analysis = self.analyze_url(urls[0], extracted_text) if urls else None
            if web_analysis and parsed.get("kind") == "url":
                fields = parsed.setdefault("fields", [])
                registered = web_analysis.get("features", {}).get("registered_domain")
                if registered:
                    fields.append({"label": "Registered domain", "value": registered})
                if web_analysis.get("features", {}).get("uses_shortener"):
                    fields.append({
                        "label": "Final destination",
                        "value": "Hidden behind a URL shortener; QuishLens does not follow suspicious redirects automatically.",
                    })
            web_score = web_analysis["risk"]["score"] if web_analysis else 0
            combined_score = max(qr_risk["score"], web_score, payment_model_score)
            artifact_analyses.append({
                "payload": payload,
                "page": artifact.get("page"),
                "decode_method": artifact.get("decode_method"),
                "payload_analysis": parsed,
                "url_analysis": web_analysis,
                "payment_model": payment_model,
                "risk_score": combined_score,
                "verdict": _verdict_for_score(combined_score),
            })

        selected_analysis = max(artifact_analyses, key=lambda item: item["risk_score"], default=None)
        if selected_analysis:
            parsed = selected_analysis["payload_analysis"]
            url_analysis = selected_analysis["url_analysis"]
            score = selected_analysis["risk_score"]
            verdict = selected_analysis["verdict"]
            signals: list[Signal] = []

            for index, flag in enumerate(parsed.get("flags", [])):
                signals.append(Signal(
                    key=f"payload_{index}",
                    label=flag.get("label", "QR payload signal"),
                    level=flag.get("level", "info"),
                    value=True,
                    detail=flag.get("detail"),
                ))
            payment_model = selected_analysis.get("payment_model") or {}
            if payment_model.get("available"):
                probability = float(payment_model.get("probability", 0))
                signals.append(Signal(
                    key="payment_research_model",
                    label="Payment QR anomaly model",
                    level="danger" if probability >= 0.75 else "warning" if probability >= 0.5 else "info",
                    value=f"{probability:.0%}",
                    detail=(
                        "Research model trained on BanglaQR-Quish-style synthetic payment QR patterns. "
                        "Useful as supporting evidence, not proof that a real receiver is fraudulent."
                    ),
                ))
            if url_analysis:
                signals.extend(Signal(**item) for item in url_analysis["signals"])

            if parsed.get("kind") == "payment":
                title = parsed.get("title", "Payment QR")
                explanation = (
                    f"QuishLens decoded this as {title.lower()} and inspected its payment fields, "
                    f"checksum, provider identifier, embedded links, and any available document context. "
                    f"The combined static risk score is {score}/100 ({verdict.upper()})."
                )
                if any(flag.get("level") == "danger" for flag in parsed.get("flags", [])):
                    explanation += " One or more payment-structure checks found a strong warning sign."
                plain = _plain_payload_message(parsed, verdict)
            elif url_analysis:
                explanation = url_analysis["explanation"]
                plain = url_analysis["plain_language"]
            else:
                explanation = (
                    f"QuishLens decoded the QR as {parsed.get('title', 'data')}. "
                    "The content was classified and explained without executing it or opening any destination."
                )
                plain = _plain_payload_message(parsed, verdict)

            selected_payload = selected_analysis["payload"]
            payload_analysis = parsed
        else:
            url_analysis = None
            payload_analysis = None
            score = 0
            verdict = "low"
            signals = []
            selected_payload = None
            explanation = (
                "No decodable QR code was found in the submitted file. This does not prove that the file is safe; "
                "QuishLens only reports what its current static QR checks can observe."
            )
            plain = "No readable QR code was found. If the code is tiny, blurred, cropped, or damaged, try a clearer image or screenshot."

        elapsed_ms = round((time.perf_counter() - started_at) * 1000, 1)
        return ScanResponse(
            scan_id=str(uuid.uuid4()),
            filename=Path(filename).name,
            file_type=file_type,
            qr_found=bool(artifacts),
            qr_count=len(artifacts),
            artifacts=artifacts,
            selected_payload=selected_payload,
            payload_analysis=payload_analysis,
            artifact_analyses=artifact_analyses,
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


def _verdict_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "suspicious"
    return "low"


def _plain_payload_message(parsed: dict, verdict: str) -> str:
    kind = parsed.get("kind")
    if kind == "payment":
        payment = parsed.get("payment", {})
        merchant = payment.get("merchant_name") or payment.get("name") or payment.get("payee")
        amount = payment.get("amount")
        who = f" for {merchant}" if merchant else ""
        amount_text = f" for {amount}" if amount else ""
        if verdict in {"high", "critical"}:
            return f"This is a payment QR{who}{amount_text}, and QuishLens found a strong warning sign. Do not pay until the receiver shown by your payment app matches who you expected."
        return f"This is a payment QR{who}{amount_text}. Its structure does not show a strong warning sign, but a valid QR can still send money to the wrong person. Check the receiver name in your payment app before approving."
    if kind == "wifi":
        return "This QR contains Wi-Fi settings, not a website. Only join the network if you recognize who provided it."
    if kind == "credential":
        return "This QR contains an authentication secret. Treat it like a password and do not share a screenshot of it."
    if kind in {"contact", "email", "message", "phone", "location"}:
        return parsed.get("summary", "The QR contains an action rather than a website. Review it before continuing.")
    if kind == "text":
        return "This QR contains text or app-specific data. QuishLens shows the decoded content so you can inspect it before another app acts on it."
    return parsed.get("summary", "The QR was decoded. Review its content before acting on it.")


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
