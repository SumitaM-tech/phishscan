"""
OpenPhish feed collector -- configurable so it works against either
the free community feed (plain-text, one URL per line, refreshed
every ~12h) or a premium/academic feed URL, entirely via environment
variables. No credentials or feed URLs are hardcoded.

If OPENPHISH_API_KEY is set, it's sent as a Bearer token, which is
how OpenPhish's premium API expects it -- adjust in one place here if
your specific plan documents a different auth scheme.
"""
import logging
from datetime import datetime

import requests

from app.config import settings
from app.services.url_service import normalize_url, get_hostname

logger = logging.getLogger("phishscan.feeds.openphish")


def fetch_openphish_records() -> list[dict]:
    url = settings.OPENPHISH_FEED_URL
    headers = {"User-Agent": "PhishScan/1.0 (academic threat-intel sync)"}
    if settings.OPENPHISH_API_KEY:
        headers["Authorization"] = f"Bearer {settings.OPENPHISH_API_KEY}"

    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()

    records = []
    now = datetime.utcnow()
    for line in resp.text.splitlines():
        raw_url = line.strip()
        if not raw_url or raw_url.startswith("#"):
            continue
        normalized = normalize_url(raw_url)
        if not normalized:
            continue

        records.append({
            "url": raw_url,
            "normalized_url": normalized,
            "domain": get_hostname(normalized),
            "source": "openphish",
            "label": "phishing",
            "target": None,  # not provided by the free feed
            "verified": True,  # OpenPhish only lists confirmed phish
            "online": None,  # not provided
            "first_seen": now,
            "last_seen": now,
            "raw_metadata": {},
        })
    logger.info("Parsed %d OpenPhish records", len(records))
    return records
