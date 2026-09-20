from __future__ import annotations

import re
from collections import defaultdict

from .brand_detector import BRANDS

CATEGORY_TERMS = {
    "urgency": ["urgent", "immediately", "within 24 hours", "expires", "expiry", "today", "now", "final warning", "last chance"],
    "credentials": ["password", "passcode", "otp", "one time password", "credential", "sign in", "login", "verify account", "authentication"],
    "payment": ["payment", "invoice", "refund", "bank", "upi", "card", "wallet", "transaction", "billing"],
    "threat_or_pressure": ["suspended", "blocked", "disabled", "locked", "penalty", "unauthorized", "security alert", "unusual activity"],
    "qr_call_to_action": ["scan qr", "scan the qr", "scan code", "scan this code", "use your camera"],
}


def _sentences(text: str) -> list[str]:
    cleaned = re.sub(r"\s+", " ", text.strip())
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", cleaned) if s.strip()]


def analyze_context(text: str) -> dict:
    text = (text or "")[:40_000]
    lowered = text.lower()
    categories: dict[str, list[str]] = defaultdict(list)

    for category, terms in CATEGORY_TERMS.items():
        for term in terms:
            if term in lowered:
                categories[category].append(term)

    brands = [brand for brand in BRANDS if re.search(rf"\b{re.escape(brand)}\b", lowered)]
    scored_sentences: list[tuple[int, str]] = []
    for sentence in _sentences(text):
        low = sentence.lower()
        score = sum(term in low for terms in CATEGORY_TERMS.values() for term in terms)
        score += 2 * sum(re.search(rf"\b{re.escape(brand)}\b", low) is not None for brand in BRANDS)
        if score:
            scored_sentences.append((score, sentence))

    scored_sentences.sort(key=lambda pair: pair[0], reverse=True)
    evidence = [sentence for _, sentence in scored_sentences[:4]]
    manipulation_score = min(100, sum(len(v) for v in categories.values()) * 9 + len(brands) * 8)

    return {
        "available": bool(text.strip()),
        "categories": dict(categories),
        "brands_mentioned": brands,
        "evidence_sentences": evidence,
        "manipulation_score": manipulation_score,
        "text_length": len(text),
    }
