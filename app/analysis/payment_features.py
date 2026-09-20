from __future__ import annotations

import math
import re
from collections import Counter

from .qr_payload import parse_tlv, validate_emv_crc


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _max_run(text: str) -> int:
    if not text:
        return 0
    longest = current = 1
    previous = text[0]
    for char in text[1:]:
        if char == previous:
            current += 1
            longest = max(longest, current)
        else:
            previous = char
            current = 1
    return longest


def extract_payment_features(payload: str) -> dict[str, float]:
    """Numerical features for EMV-style payment payloads.

    The features are structural and content-shape based. They deliberately avoid image
    names, dataset labels, and exact synthetic attacker strings.
    """
    items, errors = parse_tlv(payload)
    top = {item.tag: item.value for item in items}
    account_templates = []
    sensitive_values: list[str] = []
    provider_ids: list[str] = []
    nested_error_count = 0

    for tag, value in top.items():
        if tag.isdigit() and 26 <= int(tag) <= 51:
            nested, nested_errors = parse_tlv(value)
            nested_error_count += len(nested_errors)
            account_templates.append(nested)
            for item in nested:
                if item.tag == "00":
                    provider_ids.append(item.value)
                else:
                    sensitive_values.append(item.value)

    additional = top.get("62", "")
    additional_items, additional_errors = parse_tlv(additional) if additional else ([], [])
    sensitive_values.extend(item.value for item in additional_items)
    nested_error_count += len(additional_errors)

    provider_blob = "|".join(provider_ids)
    sensitive_blob = "|".join(sensitive_values)
    digits = [ch for ch in sensitive_blob if ch.isdigit()]
    all_digits = [ch for ch in payload if ch.isdigit()]

    provider_low = provider_blob.lower()
    known_tokens = ["bkash", "nagad", "tallypay", "mutual", "mtb", "dbbl", "nexus"]
    known_provider = any(token in provider_low for token in known_tokens)
    provider_contains_url = "http://" in provider_low or "https://" in provider_low

    return {
        "payload_length": float(len(payload)),
        "top_level_field_count": float(len(items)),
        "top_parse_error_count": float(len(errors)),
        "account_template_count": float(len(account_templates)),
        "nested_parse_error_count": float(nested_error_count),
        "provider_id_length": float(max((len(x) for x in provider_ids), default=0)),
        "provider_contains_url": float(provider_contains_url),
        "known_provider": float(known_provider),
        "sensitive_value_count": float(len(sensitive_values)),
        "sensitive_total_length": float(len(sensitive_blob)),
        "sensitive_digit_ratio": float(len(digits) / max(1, len(sensitive_blob))),
        "sensitive_entropy": float(_entropy(sensitive_blob)),
        "sensitive_max_repeated_char_run": float(_max_run(sensitive_blob)),
        "sensitive_max_repeated_digit_run": float(max((_max_run(v) for v in sensitive_values if v.isdigit()), default=0)),
        "payload_digit_ratio": float(len(all_digits) / max(1, len(payload))),
        "merchant_name_length": float(len(top.get("59", ""))),
        "city_length": float(len(top.get("60", ""))),
        "amount_present": float(bool(top.get("54"))),
        "crc_valid": float(validate_emv_crc(payload) is True),
        "http_token_count": float(len(re.findall(r"https?://", payload, re.IGNORECASE))),
    }


PAYMENT_FEATURES = [
    "payload_length", "top_level_field_count", "top_parse_error_count", "account_template_count",
    "nested_parse_error_count", "provider_id_length", "provider_contains_url", "known_provider",
    "sensitive_value_count", "sensitive_total_length", "sensitive_digit_ratio", "sensitive_entropy",
    "sensitive_max_repeated_char_run", "sensitive_max_repeated_digit_run", "payload_digit_ratio",
    "merchant_name_length", "city_length", "amount_present", "crc_valid", "http_token_count",
]


def payment_vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in PAYMENT_FEATURES]
