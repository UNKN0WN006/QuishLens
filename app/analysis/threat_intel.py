from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .url_features import normalize_url, registered_domain


class ThreatIntelStore:
    def __init__(self, urls_path: Path, domains_path: Path):
        self.urls_path = urls_path
        self.domains_path = domains_path
        self.urls: set[str] = set()
        self.domains: set[str] = set()
        self.reload()

    @staticmethod
    def _read(path: Path) -> set[str]:
        if not path.exists():
            return set()
        values = set()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                values.add(line.lower())
        return values

    def reload(self) -> None:
        self.urls = self._read(self.urls_path)
        self.domains = self._read(self.domains_path)

    def lookup(self, raw_url: str) -> dict:
        normalized = normalize_url(raw_url)
        parsed = urlsplit(normalized)
        host = (parsed.hostname or "").lower()
        domain = registered_domain(host)
        exact = normalized.lower() in self.urls or raw_url.strip().lower() in self.urls
        domain_match = host in self.domains or domain in self.domains
        return {
            "matched": exact or domain_match,
            "exact_url_match": exact,
            "domain_match": domain_match,
            "matched_domain": domain if domain_match else None,
            "source": "local threat-intelligence snapshot",
        }
