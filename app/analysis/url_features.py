from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlsplit

SUSPICIOUS_TOKENS = {
    "account", "auth", "authenticate", "bank", "billing", "confirm", "credential",
    "invoice", "login", "password", "payment", "recover", "reset", "secure",
    "signin", "support", "unlock", "update", "verify", "verification", "wallet",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly",
    "shorturl.at", "ow.ly", "buff.ly", "rb.gy",
}


def normalize_url(raw: str) -> str:
    value = (raw or "").strip().replace("\x00", "")
    if not value:
        return ""
    if "://" not in value:
        value = "http://" + value
    return value


def registered_domain(hostname: str) -> str:
    # Lightweight approximation that avoids a runtime dependency on the PSL.
    # It covers common two-level country suffixes well enough for hackathon use.
    host = hostname.lower().strip(".")
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    two_level_suffixes = {
        "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "firm.in",
        "net.in", "org.in", "gen.in", "ind.in", "co.jp", "co.nz", "com.br",
    }
    tail = ".".join(labels[-2:])
    if tail in two_level_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _looks_like_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _count_encoded_sequences(value: str) -> int:
    return len(re.findall(r"%[0-9a-fA-F]{2}", value))


def extract_url_features(raw_url: str) -> dict[str, float | int | str | bool | list[str]]:
    url = normalize_url(raw_url)
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    decoded = unquote(url).lower()
    domain = registered_domain(host)
    tokens = sorted(token for token in SUSPICIOUS_TOKENS if token in decoded)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    host_labels = [x for x in host.split(".") if x]

    return {
        "url": url,
        "scheme": parsed.scheme.lower(),
        "hostname": host,
        "registered_domain": domain,
        "tld": domain.rsplit(".", 1)[-1] if "." in domain else "",
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "digit_count": sum(ch.isdigit() for ch in url),
        "special_count": len(re.findall(r"[^A-Za-z0-9]", url)),
        "subdomain_count": max(0, len(host_labels) - (3 if domain.count(".") == 2 else 2)),
        "query_param_count": len(query_pairs),
        "encoded_sequence_count": _count_encoded_sequences(url),
        "hostname_entropy": round(_entropy(host), 4),
        "url_entropy": round(_entropy(url), 4),
        "uses_https": parsed.scheme.lower() == "https",
        "uses_ip_address": _looks_like_ip(host),
        "contains_at_symbol": "@" in url,
        "contains_punycode": any(label.startswith("xn--") for label in host_labels),
        "uses_shortener": domain in SHORTENER_DOMAINS,
        "double_slash_in_path": "//" in parsed.path,
        "has_port": parsed.port is not None if host else False,
        "suspicious_token_count": len(tokens),
        "suspicious_tokens": tokens,
        "decoded_path_preview": path_and_query[:240],
    }


MODEL_FEATURES = [
    "url_length", "hostname_length", "path_length", "query_length", "dot_count",
    "hyphen_count", "underscore_count", "digit_count", "special_count",
    "subdomain_count", "query_param_count", "encoded_sequence_count",
    "hostname_entropy", "url_entropy", "uses_https", "uses_ip_address",
    "contains_at_symbol", "contains_punycode", "uses_shortener",
    "double_slash_in_path", "has_port", "suspicious_token_count",
]


def model_vector(features: dict) -> list[float]:
    return [float(bool(features[name])) if isinstance(features[name], bool) else float(features[name]) for name in MODEL_FEATURES]
