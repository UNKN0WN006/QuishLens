from app.analysis.model_service import URLModelService
from app.analysis.url_features import extract_url_features


def test_batch_fallback_matches_single_predictions(tmp_path):
    service = URLModelService(tmp_path / "missing.joblib", tmp_path / "missing.json")
    rows = [
        extract_url_features("https://example.com"),
        extract_url_features("http://192.0.2.10/login/verify"),
    ]
    singles = [service.predict(row) for row in rows]
    batched = service.predict_many(rows)
    assert [x["phishing_probability"] for x in batched] == [x["phishing_probability"] for x in singles]
