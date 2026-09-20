from app.analysis.risk_engine import calculate_risk


def test_threat_intel_and_brand_drive_high_risk():
    features = {"uses_ip_address": False, "contains_punycode": False, "contains_at_symbol": False, "uses_shortener": False, "suspicious_token_count": 2, "subdomain_count": 0}
    model = {"phishing_probability": 0.9}
    brand = {"impersonation_detected": True, "best_match": {"brand": "microsoft"}}
    threat = {"matched": True}
    context = {"manipulation_score": 40}
    result = calculate_risk(features, model, brand, threat, context)
    assert result["score"] >= 80
    assert result["verdict"] == "critical"
