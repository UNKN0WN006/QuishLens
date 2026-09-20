from __future__ import annotations

from difflib import SequenceMatcher
from urllib.parse import urlsplit

from .url_features import registered_domain

BRANDS = {
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"},
    "google": {"google.com", "gmail.com", "googleusercontent.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "paypal": {"paypal.com"},
    "meta": {"meta.com", "facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "netflix": {"netflix.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "bank.sbi"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "phonepe": {"phonepe.com"},
    "paytm": {"paytm.com"},
    "flipkart": {"flipkart.com"},
}

LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})


def _squash(value: str) -> str:
    return "".join(ch for ch in value.lower().translate(LEET_MAP) if ch.isalnum())


def analyze_brand_impersonation(url: str, context_text: str = "") -> dict:
    parsed = urlsplit(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    reg_domain = registered_domain(host)
    host_core = _squash(reg_domain.split(".")[0])
    context = context_text.lower()

    candidates = []
    for brand, legitimate_domains in BRANDS.items():
        brand_norm = _squash(brand)
        mentioned = brand in context
        similarity = SequenceMatcher(None, host_core, brand_norm).ratio() if host_core else 0.0
        host_mentions_brand = brand_norm in _squash(host)
        legitimate = any(reg_domain == d or reg_domain.endswith("." + d) for d in legitimate_domains)

        if mentioned or host_mentions_brand or similarity >= 0.72:
            candidates.append({
                "brand": brand,
                "legitimate": legitimate,
                "similarity": round(similarity, 3),
                "mentioned_in_context": mentioned,
                "brand_like_domain": host_mentions_brand or similarity >= 0.72,
                "expected_domains": sorted(legitimate_domains),
            })

    candidates.sort(key=lambda item: (item["mentioned_in_context"], item["similarity"]), reverse=True)
    best = candidates[0] if candidates else None
    impersonation = bool(best and not best["legitimate"] and (best["mentioned_in_context"] or best["brand_like_domain"]))

    return {
        "registered_domain": reg_domain,
        "impersonation_detected": impersonation,
        "best_match": best,
        "candidates": candidates[:4],
    }
