from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from common import ROOT
from app.analysis.url_features import normalize_url, registered_domain


def parse_args():
    p = argparse.ArgumentParser(description="Import a downloaded URL feed into QuishLens' local threat-intelligence snapshot.")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--url-column", default=None, help="CSV column containing URLs. Omit for one-URL-per-line text files.")
    p.add_argument("--append", action="store_true", help="Append to existing local snapshot rather than replacing it.")
    p.add_argument("--max-rows", type=int, default=200_000)
    return p.parse_args()


def main():
    args = parse_args()
    if args.url_column:
        frame = pd.read_csv(args.input)
        if args.url_column not in frame.columns:
            raise SystemExit(f"Column {args.url_column!r} not found. Available: {', '.join(map(str, frame.columns))}")
        values = frame[args.url_column].dropna().astype(str).tolist()
    else:
        values = [line.strip() for line in args.input.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.startswith("#")]

    values = values[: args.max_rows]
    urls: set[str] = set()
    domains: set[str] = set()
    for raw in values:
        try:
            normalized = normalize_url(raw)
            parsed = urlsplit(normalized)
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            urls.add(normalized.lower())
            domains.add(registered_domain(host))
        except Exception:
            continue

    intel_dir = ROOT / "data" / "threat_intel"
    intel_dir.mkdir(parents=True, exist_ok=True)
    url_path = intel_dir / "known_urls.txt"
    domain_path = intel_dir / "known_domains.txt"

    if args.append:
        for path, values_set in ((url_path, urls), (domain_path, domains)):
            existing = {line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.startswith("#")} if path.exists() else set()
            values_set.update(existing)

    url_path.write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")
    domain_path.write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")
    print(f"Imported {len(urls):,} URLs and {len(domains):,} registered domains.")
    print("Restart the server or POST /api/reload to load the new snapshot.")


if __name__ == "__main__":
    main()
