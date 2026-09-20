from app.analysis.brand_detector import analyze_brand_impersonation
from app.analysis.context_nlp import analyze_context
from app.analysis.url_features import extract_url_features


def test_url_feature_flags_ip_and_tokens():
    f = extract_url_features("http://192.0.2.10/login/verify?account=1")
    assert f["uses_ip_address"] is True
    assert "login" in f["suspicious_tokens"]
    assert f["suspicious_token_count"] >= 2


def test_brand_mismatch_detected():
    result = analyze_brand_impersonation(
        "https://micros0ft-account-verify.example.invalid/login",
        "Microsoft account verification",
    )
    assert result["impersonation_detected"] is True
    assert result["best_match"]["brand"] == "microsoft"


def test_context_detects_pressure_language():
    result = analyze_context("Urgent: verify your password immediately or your account will be suspended. Scan the QR code now.")
    assert result["manipulation_score"] >= 25
    assert result["categories"]["urgency"]
    assert result["categories"]["credentials"]
