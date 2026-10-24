"""
PhishTank feed collector -- downloads the official CSV feed and
yields normalized records ready for ThreatIntelRepository.upsert().

No credentials are hardcoded: the feed URL and optional app_key both
come from Settings (env-driven). An app_key is optional -- PhishTank
serves the feed without one, just at a lower rate limit -- so this
collector works out of the box and can be upgraded later purely via
environment variables.
"""
import csv
import io
import logging
from datetime import datetime

import requests

from app.config import settings
from app.services.url_service import normalize_url, get_hostname

logger = logging.getLogger("phishscan.feeds.phishtank")


def fetch_phishtank_records() -> list[dict]:
    """Downloads and parses the PhishTank CSV feed. Raises on network/
    parse failure so the caller (threat_intel_service) can record the
    sync run as failed rather than silently upserting nothing."""
    url = settings.PHISHTANK_FEED_URL
    params = {}
    if settings.PHISHTANK_APP_KEY:
        params["app_key"] = settings.PHISHTANK_APP_KEY

    resp = requests.get(
        url, params=params, timeout=60,
        headers={"User-Agent": "PhishScan/1.0 (academic threat-intel sync)"},
    )
    resp.raise_for_status()

    reader = csv.DictReader(io.StringIO(resp.text))
    records = []
    for row in reader:
        raw_url = (row.get("url") or "").strip()
        if not raw_url:
            continue
        normalized = normalize_url(raw_url)
        if not normalized:
            continue

        records.append({
            "url": raw_url,
            "normalized_url": normalized,
            "domain": get_hostname(normalized),
            "source": "phishtank",
            "label": "phishing",
            "target": (row.get("target") or "").strip() or None,
            "verified": _parse_bool(row.get("verified")),
            "online": _parse_bool(row.get("online")),
            "first_seen": _parse_date(row.get("submission_time")) or datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "raw_metadata": {
                "phish_id": row.get("phish_id"),
                "phish_detail_url": row.get("phish_detail_url"),
                "verification_time": row.get("verification_time"),
            },
        })
    logger.info("Parsed %d PhishTank records", len(records))
    return records


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in ("yes", "true", "1")


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None
