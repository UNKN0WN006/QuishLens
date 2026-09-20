from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
DOMAIN_ONLY_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:[/][^\s]*)?$",
    re.IGNORECASE,
)
REDIRECT_KEYS = {
    "url", "u", "uri", "redirect", "redirect_url", "redirect_uri", "target", "dest",
    "destination", "next", "continue", "return", "return_url", "rurl", "to",
}
CURRENCY_NAMES = {
    "050": "BDT — Bangladeshi taka",
    "356": "INR — Indian rupee",
    "840": "USD — US dollar",
    "978": "EUR — Euro",
    "826": "GBP — Pound sterling",
}


@dataclass
class TLVItem:
    tag: str
    value: str


def parse_tlv(value: str) -> tuple[list[TLVItem], list[str]]:
    """Parse EMV-style two-digit tag/two-digit length fields without guessing past corruption."""
    items: list[TLVItem] = []
    errors: list[str] = []
    pos = 0
    while pos + 4 <= len(value):
        tag = value[pos:pos + 2]
        length_text = value[pos + 2:pos + 4]
        if not (tag.isdigit() and length_text.isdigit()):
            errors.append(f"Stopped at offset {pos}: expected numeric tag and length.")
            break
        length = int(length_text)
        start = pos + 4
        end = start + length
        if end > len(value):
            errors.append(f"Tag {tag} declares {length} characters but the payload ends early.")
            break
        items.append(TLVItem(tag, value[start:end]))
        pos = end
    if pos != len(value) and not errors:
        errors.append(f"{len(value) - pos} trailing character(s) were not part of a complete TLV field.")
    return items, errors


def _crc16_ccitt_false(text: str) -> str:
    crc = 0xFFFF
    for byte in text.encode("utf-8", errors="replace"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def validate_emv_crc(payload: str) -> bool | None:
    marker = payload.rfind("6304")
    if marker < 0 or marker + 8 != len(payload):
        return None
    supplied = payload[-4:].upper()
    calculated = _crc16_ccitt_false(payload[:marker + 4])
    return supplied == calculated


def _unquote_repeated(value: str, rounds: int = 3) -> str:
    current = value
    for _ in range(rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_RE.findall(text or ""):
        cleaned = match.rstrip(".,);]}")
        if cleaned not in found:
            found.append(cleaned)
    return found


def redirect_hints(url: str) -> list[str]:
    """Return URLs explicitly embedded in redirect-style query parameters; never follows the network."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return []
    hints: list[str] = []
    for key, values in parse_qs(parsed.query, keep_blank_values=False).items():
        if key.lower() not in REDIRECT_KEYS:
            continue
        for raw in values:
            candidate = _unquote_repeated(raw).strip()
            if candidate.startswith(("http://", "https://")) and candidate not in hints:
                hints.append(candidate)
    return hints


def _masked(value: str, visible: int = 4) -> str:
    value = (value or "").strip()
    if len(value) <= visible * 2:
        return value
    return value[:visible] + "…" + value[-visible:]


def _provider_name(identifier: str) -> str:
    low = identifier.lower()
    mapping = {
        "bkash": "bKash",
        "nagad": "Nagad",
        "tallypay": "TallyPay",
        "mutual": "Mutual Trust Bank",
        "mtb": "Mutual Trust Bank",
        "dbbl": "DBBL / NexusPay",
        "nexus": "DBBL / NexusPay",
    }
    return next((name for token, name in mapping.items() if token in low), identifier or "Unknown provider")


def _analyze_emv_payment(payload: str) -> dict:
    items, errors = parse_tlv(payload)
    by_tag = {item.tag: item.value for item in items}
    fields: list[dict] = []
    flags: list[dict] = []
    embedded_urls: list[str] = []
    nested_accounts: list[dict] = []

    merchant_name = by_tag.get("59")
    merchant_city = by_tag.get("60")
    country = by_tag.get("58")
    amount = by_tag.get("54")
    currency_code = by_tag.get("53")
    category = by_tag.get("52")
    crc_valid = validate_emv_crc(payload)

    for tag in sorted(k for k in by_tag if k.isdigit() and 26 <= int(k) <= 51):
        nested, nested_errors = parse_tlv(by_tag[tag])
        nested_map = {item.tag: item.value for item in nested}
        provider_id = nested_map.get("00", "")
        provider_urls = extract_urls(provider_id)
        for candidate in provider_urls:
            if candidate not in embedded_urls:
                embedded_urls.append(candidate)
        for nested_item in nested:
            for candidate in extract_urls(nested_item.value):
                if candidate not in embedded_urls:
                    embedded_urls.append(candidate)
        account_values = [item.value for item in nested if item.tag != "00"]
        nested_accounts.append({
            "template_tag": tag,
            "provider_identifier": provider_id,
            "provider_name": _provider_name(provider_id),
            "account_fields": [{"tag": item.tag, "value": _masked(item.value)} for item in nested if item.tag != "00"],
            "parse_errors": nested_errors,
        })
        if provider_urls:
            flags.append({
                "level": "danger",
                "label": "Provider identifier replaced by a web address",
                "detail": "A payment-provider identity field contains a URL. That is unusual for a normal merchant payment QR and can indicate redirection or tampering.",
                "points": 62,
            })
        if not provider_id:
            flags.append({
                "level": "warning",
                "label": "Missing payment provider identifier",
                "detail": "The merchant account template does not expose a provider identifier that QuishLens can explain.",
                "points": 12,
            })
        # Keep account values visible enough to verify, without dumping every identifier in simple mode.
        if account_values:
            pass

    if merchant_name:
        fields.append({"label": "Merchant", "value": merchant_name})
    if merchant_city:
        fields.append({"label": "City", "value": merchant_city})
    if country:
        fields.append({"label": "Country", "value": country})
    if currency_code:
        fields.append({"label": "Currency", "value": CURRENCY_NAMES.get(currency_code, currency_code)})
    if amount:
        fields.append({"label": "Requested amount", "value": amount})
    else:
        fields.append({"label": "Requested amount", "value": "Not fixed in the QR"})
    if category:
        fields.append({"label": "Merchant category code", "value": category})
    if nested_accounts:
        fields.append({"label": "Payment provider", "value": nested_accounts[0]["provider_name"]})
        provider_id = nested_accounts[0]["provider_identifier"]
        if provider_id:
            fields.append({"label": "Provider identifier", "value": provider_id})

    if crc_valid is False:
        flags.append({
            "level": "danger",
            "label": "Payment QR checksum does not match",
            "detail": "The EMV-style CRC checksum is invalid. The QR may be corrupted or altered.",
            "points": 48,
        })
    elif crc_valid is True:
        flags.append({
            "level": "safe",
            "label": "Payment QR checksum is valid",
            "detail": "The EMV-style payload passes its CRC integrity check. This confirms structure, not who owns the receiving account.",
            "points": 0,
        })

    if errors:
        flags.append({
            "level": "warning",
            "label": "Payment payload is only partly structured",
            "detail": " ".join(errors[:2]),
            "points": 16,
        })

    if not any(flag["level"] == "danger" for flag in flags):
        flags.append({
            "level": "info",
            "label": "Payment destination needs human verification",
            "detail": "A structurally valid payment QR can still point to the wrong receiver. Verify the payee shown by the payment app before approving money.",
            "points": 8,
        })

    return {
        "kind": "payment",
        "format": "emv_tlv",
        "title": "Merchant payment QR",
        "summary": "This QR contains a structured merchant-payment payload rather than an ordinary website link.",
        "fields": fields,
        "flags": flags,
        "embedded_urls": embedded_urls,
        "redirect_hints": [],
        "payment": {
            "merchant_name": merchant_name,
            "merchant_city": merchant_city,
            "country": country,
            "currency_code": currency_code,
            "amount": amount,
            "merchant_category": category,
            "crc_valid": crc_valid,
            "accounts": nested_accounts,
        },
    }


def _analyze_upi(payload: str) -> dict:
    parsed = urlsplit(payload)
    query = {k: values[0] for k, values in parse_qs(parsed.query).items() if values}
    payee = query.get("pa", "")
    name = query.get("pn", "")
    amount = query.get("am", "")
    note = query.get("tn", "")
    fields = [
        {"label": "Payee", "value": payee or "Not supplied"},
        {"label": "Payee name", "value": name or "Not supplied"},
        {"label": "Amount", "value": amount or "Not fixed in the QR"},
    ]
    if note:
        fields.append({"label": "Payment note", "value": note})
    flags = [{
        "level": "info",
        "label": "Payment request",
        "detail": "Verify the payee name and UPI ID in your payment app before approving. QuishLens does not initiate the payment.",
        "points": 8,
    }]
    if not payee:
        flags.append({"level": "warning", "label": "Missing UPI payee", "detail": "No pa= payee identifier was found.", "points": 15})
    return {
        "kind": "payment",
        "format": "upi",
        "title": "UPI payment QR",
        "summary": f"This QR requests a UPI payment to {name or payee or 'an unspecified payee'}.",
        "fields": fields,
        "flags": flags,
        "embedded_urls": [],
        "redirect_hints": [],
        "payment": {"payee": payee, "name": name, "amount": amount, "note": note},
    }


def analyze_qr_payload(payload: str) -> dict:
    raw = (payload or "").strip().replace("\x00", "")
    lower = raw.lower()

    if not raw:
        return {
            "kind": "empty", "format": "unknown", "title": "Empty QR payload",
            "summary": "The QR detector found a symbol but recovered no readable content.",
            "fields": [], "flags": [], "embedded_urls": [], "redirect_hints": [],
        }

    if raw.startswith("000201") and "6304" in raw[-12:]:
        return _analyze_emv_payment(raw)

    if lower.startswith("upi://pay"):
        return _analyze_upi(raw)

    if lower.startswith(("http://", "https://")) or DOMAIN_ONLY_RE.fullmatch(raw):
        url = raw if lower.startswith(("http://", "https://")) else "http://" + raw
        redirects = redirect_hints(url)
        url_fields = [{"label": "Destination", "value": url}]
        url_fields.extend({"label": "Embedded redirect target", "value": target} for target in redirects[:3])
        return {
            "kind": "url", "format": "web_url", "title": "Website link",
            "summary": "This QR contains a web address. QuishLens shows redirect-style destinations encoded inside the link without following them.",
            "fields": url_fields,
            "flags": ([{
                "level": "warning", "label": "Embedded redirect target",
                "detail": "The URL contains another destination inside a redirect-style query parameter.", "points": 12,
            }] if redirects else []),
            "embedded_urls": [url] + [u for u in redirects if u != url],
            "redirect_hints": redirects,
        }

    if lower.startswith("wifi:"):
        fields = []
        body = raw[5:]
        values = {}
        for part in re.split(r"(?<!\\);", body):
            if ":" in part:
                key, value = part.split(":", 1)
                values[key.upper()] = value.replace("\\;", ";").replace("\\:", ":")
        if values.get("S"):
            fields.append({"label": "Wi-Fi name", "value": values["S"]})
        if values.get("T"):
            fields.append({"label": "Security", "value": values["T"]})
        if values.get("P"):
            fields.append({"label": "Password", "value": "Present (hidden by QuishLens)"})
        return {
            "kind": "wifi", "format": "wifi", "title": "Wi-Fi configuration",
            "summary": "This QR contains Wi-Fi connection settings, not a website.",
            "fields": fields,
            "flags": [{"level": "info", "label": "Network configuration", "detail": "Only join networks you recognize. The password is not displayed in the simple view.", "points": 4}],
            "embedded_urls": extract_urls(raw), "redirect_hints": [],
        }

    if lower.startswith(("begin:vcard", "mecard:")):
        fields = []
        for label, pattern in [("Name", r"(?:FN|N):([^\r\n;]+)"), ("Phone", r"TEL[^:]*:([^\r\n;]+)"), ("Email", r"EMAIL[^:]*:([^\r\n;]+)")]:
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                fields.append({"label": label, "value": match.group(1).strip()})
        urls = extract_urls(raw)
        return {
            "kind": "contact", "format": "vcard", "title": "Contact card",
            "summary": "This QR contains contact information.", "fields": fields,
            "flags": [{"level": "info", "label": "Contact import", "detail": "Review the contact details before saving them.", "points": 2}],
            "embedded_urls": urls, "redirect_hints": [],
        }

    if lower.startswith("mailto:"):
        address = raw[7:].split("?", 1)[0]
        return {
            "kind": "email", "format": "mailto", "title": "Email action",
            "summary": f"This QR prepares an email to {address or 'an address'}.",
            "fields": [{"label": "Recipient", "value": address or "Not supplied"}],
            "flags": [{"level": "info", "label": "Email action", "detail": "Review the recipient and message before sending.", "points": 3}],
            "embedded_urls": extract_urls(raw), "redirect_hints": [],
        }

    if lower.startswith(("sms:", "smsto:")):
        return {
            "kind": "message", "format": "sms", "title": "SMS action",
            "summary": "This QR prepares a text message.",
            "fields": [{"label": "Payload", "value": raw[:260]}],
            "flags": [{"level": "warning", "label": "Message action", "detail": "Do not send codes, passwords, or financial information to an unfamiliar number.", "points": 7}],
            "embedded_urls": extract_urls(raw), "redirect_hints": [],
        }

    if lower.startswith("tel:"):
        return {
            "kind": "phone", "format": "telephone", "title": "Phone number",
            "summary": "This QR contains a telephone number.",
            "fields": [{"label": "Number", "value": raw[4:]}],
            "flags": [{"level": "info", "label": "Call action", "detail": "Confirm the number before calling, especially if the QR came from an unexpected message.", "points": 3}],
            "embedded_urls": [], "redirect_hints": [],
        }

    if lower.startswith("geo:"):
        return {
            "kind": "location", "format": "geo", "title": "Map location",
            "summary": "This QR contains geographic coordinates.",
            "fields": [{"label": "Coordinates", "value": raw[4:].split("?", 1)[0]}],
            "flags": [], "embedded_urls": [], "redirect_hints": [],
        }

    if lower.startswith("otpauth://"):
        return {
            "kind": "credential", "format": "otpauth", "title": "Authenticator setup secret",
            "summary": "This QR can configure a one-time-password authenticator.",
            "fields": [{"label": "Secret", "value": "Present (hidden by QuishLens)"}],
            "flags": [{"level": "danger", "label": "Authentication secret", "detail": "Treat this QR like a password. Anyone who copies it may be able to generate your login codes.", "points": 55}],
            "embedded_urls": [], "redirect_hints": [],
        }

    urls = extract_urls(raw)
    flags = []
    if urls:
        flags.append({
            "level": "warning", "label": "Web address embedded inside text",
            "detail": "The QR is not a plain URL, but it contains one or more web addresses that should still be inspected.", "points": 12,
        })
    return {
        "kind": "text", "format": "plain_text", "title": "Text or custom data",
        "summary": "This QR contains text or an application-specific payload rather than a standard web link.",
        "fields": [{"label": "Decoded content", "value": raw[:1000]}],
        "flags": flags,
        "embedded_urls": urls,
        "redirect_hints": [],
    }


def payload_risk(payload_analysis: dict) -> dict:
    flags = payload_analysis.get("flags", [])
    contributions = [
        {"name": flag.get("label", "QR payload signal"), "points": int(flag.get("points", 0)), "detail": flag.get("detail", "")}
        for flag in flags if int(flag.get("points", 0)) > 0
    ]
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
