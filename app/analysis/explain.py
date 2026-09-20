from __future__ import annotations


def build_explanations(verdict: str, score: int, risk: dict, brand: dict, threat: dict, context: dict) -> tuple[str, str]:
    contributions = sorted(risk.get("contributions", []), key=lambda x: x["points"], reverse=True)
    reasons = [item["detail"] for item in contributions[:3]]

    if reasons:
        technical = f"QuishLens assigned a {score}/100 {verdict.upper()} risk score. " + " ".join(reasons)
    else:
        technical = f"QuishLens assigned a {score}/100 LOW risk score. No strong phishing indicators were found in the static analysis."

    if threat.get("matched"):
        technical += " A threat-intelligence match is one of the strongest indicators in this result."
    elif brand.get("impersonation_detected"):
        technical += " The apparent brand and registered destination domain do not agree."

    if verdict in {"critical", "high"}:
        plain = "This QR code or link looks risky. Do not sign in, enter a password, send money, or share an OTP through it. Ask a trusted person or open the official app/site yourself instead."
    elif verdict == "suspicious":
        plain = "Some warning signs were found. It is safer not to continue from this QR code. Open the organisation's official app or type its known website address yourself."
    else:
        plain = "No strong warning signs were found in this static check, but that does not guarantee the destination is safe. Avoid sharing passwords, OTPs, or payment details unless you trust the source."

    if context.get("categories", {}).get("urgency"):
        plain += " The message also uses urgency, which is common in scams designed to make people act quickly."

    return technical, plain
