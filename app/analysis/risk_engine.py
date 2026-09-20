from __future__ import annotations


def calculate_risk(url_features: dict, model: dict, brand: dict, threat: dict, context: dict) -> dict:
    contributions: list[dict] = []

    def add(name: str, points: int, detail: str) -> None:
        if points:
            contributions.append({"name": name, "points": points, "detail": detail})

    probability = float(model.get("phishing_probability", 0))
    ml_points = round(probability * 35)
    add("URL classifier", ml_points, f"Model/fallback phishing score: {probability:.0%}")

    if threat.get("matched"):
        add("Threat intelligence", 30, "The URL or domain appears in the local threat-intelligence snapshot.")
    if brand.get("impersonation_detected"):
        best = brand.get("best_match") or {}
        add("Brand mismatch", 15, f"Looks related to {best.get('brand', 'a known brand')} but uses a different registered domain.")
    if url_features.get("uses_ip_address"):
        add("Direct IP destination", 10, "The URL uses a raw IP address instead of a normal domain name.")
    if url_features.get("contains_punycode"):
        add("Punycode domain", 6, "The domain uses internationalized/punycode notation that can hide lookalike names.")
    if url_features.get("contains_at_symbol"):
        add("@ in URL", 5, "An @ character can obscure the effective destination for non-technical users.")
    if url_features.get("uses_shortener"):
        add("Shortened URL", 4, "URL shorteners hide the final destination.")
    token_count = int(url_features.get("suspicious_token_count", 0))
    if token_count:
        add("Security-sensitive wording", min(7, token_count * 2), f"Found {token_count} suspicious URL token(s).")
        if not url_features.get("uses_https"):
            add("Sensitive action over HTTP", 7, "Security-sensitive wording appears on an unencrypted HTTP URL.")
        if url_features.get("uses_ip_address"):
            add("Credential-style path on raw IP", 5, "A raw IP address is combined with login, account, payment, or verification wording.")
    if int(url_features.get("subdomain_count", 0)) >= 3:
        add("Excessive subdomains", 4, "The hostname contains several nested subdomains.")
    context_score = int(context.get("manipulation_score", 0))
    if context_score >= 25:
        add("Social-engineering context", min(8, round(context_score / 12)), "Nearby document text contains urgency, credential, payment, or pressure language.")

    score = min(100, sum(item["points"] for item in contributions))
    if score >= 80:
        verdict = "critical"
    elif score >= 60:
        verdict = "high"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "low"

    return {"score": score, "verdict": verdict, "contributions": contributions}
