from app.analysis.qr_payload import analyze_qr_payload, payload_risk, validate_emv_crc


BENIGN_BANGLAQR = "00020101021126460008TallyPay01020302041005031691005219262213205204569753030505802BD5914JANATA TAILORS6007RANGPUR62390312ST41042948310708000000010807PAYMENT63044030"
MALICIOUS_PROVIDER_URL = "00020101021126650024https://pay.example.test01020202042002031992002210597845929465204545153030505802BD5911NABAB DAIRY6011COX'S BAZAR62260211010245719010807PAYMENT63047A3D"


def test_bangla_payment_qr_is_parsed_as_payment():
    result = analyze_qr_payload(BENIGN_BANGLAQR)
    assert result["kind"] == "payment"
    assert result["payment"]["merchant_name"] == "JANATA TAILORS"
    assert result["payment"]["currency_code"] == "050"
    assert result["payment"]["crc_valid"] is True
    assert result["payment"]["accounts"][0]["provider_name"] == "TallyPay"
    assert payload_risk(result)["score"] < 30


def test_provider_url_injection_is_flagged():
    result = analyze_qr_payload(MALICIOUS_PROVIDER_URL)
    assert result["kind"] == "payment"
    assert result["payment"]["accounts"][0]["provider_identifier"] == "https://pay.example.test"
    assert result["embedded_urls"] == ["https://pay.example.test"]
    assert payload_risk(result)["score"] >= 60


def test_upi_is_explained_instead_of_treated_as_web_url():
    result = analyze_qr_payload("upi://pay?pa=merchant@upi&pn=Tiny%20Shop&am=125.50&cu=INR")
    assert result["kind"] == "payment"
    assert result["format"] == "upi"
    assert result["payment"]["payee"] == "merchant@upi"
    assert result["payment"]["amount"] == "125.50"


def test_wifi_password_is_not_echoed_in_structured_fields():
    result = analyze_qr_payload("WIFI:T:WPA;S:HomeNet;P:supersecret;;")
    assert result["kind"] == "wifi"
    values = [field["value"] for field in result["fields"]]
    assert "supersecret" not in values
    assert "Present (hidden by QuishLens)" in values


def test_redirect_parameter_is_exposed_without_following_it():
    result = analyze_qr_payload("https://example.com/out?redirect=https%3A%2F%2Fdestination.example%2Flogin")
    assert result["kind"] == "url"
    assert result["redirect_hints"] == ["https://destination.example/login"]
