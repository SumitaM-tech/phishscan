"""
Threat-intelligence service: owns syncing PhishTank/OpenPhish into
ThreatIntelRecord, and answering "has this URL already been observed
as malicious?" (Signal B in the architecture -- independent of and
complementary to the ML model's Signal A).

Sync is idempotent (upsert on normalized_url+source) so it can run on
a schedule (app/scheduler.py) without ever needing a manual dataset
upload.
"""
import logging
from sqlalchemy.orm import Session

from app.database.repository import ThreatIntelRepository, FeedSyncRepository
from app.services.url_service import normalize_url, get_hostname
from app.collectors.threat_feeds import phishtank, openphish

logger = logging.getLogger("phishscan.threat_intel")


def sync_phishtank(db: Session) -> dict:
    return _run_sync(db, "phishtank", phishtank.fetch_phishtank_records)


def sync_openphish(db: Session) -> dict:
    return _run_sync(db, "openphish", openphish.fetch_openphish_records)


def sync_all(db: Session) -> list[dict]:
    return [sync_phishtank(db), sync_openphish(db)]


def _run_sync(db: Session, source: str, fetch_fn) -> dict:
    sync_repo = FeedSyncRepository(db)
    intel_repo = ThreatIntelRepository(db)
    run = sync_repo.start(source)

    try:
        records = fetch_fn()
        new_count = 0
        for record in records:
            if intel_repo.upsert(record):
                new_count += 1
        sync_repo.finish(run, status="success", records_seen=len(records), records_new=new_count)
        logger.info("%s sync complete: %d seen, %d new", source, len(records), new_count)
        return {"source": source, "status": "success", "records_seen": len(records), "records_new": new_count}
    except Exception as exc:  # noqa: BLE001
        logger.exception("%s sync failed", source)
        sync_repo.finish(run, status="failed", records_seen=0, records_new=0, message=str(exc))
        return {"source": source, "status": "failed", "message": str(exc)}


def check_url(db: Session, raw_url: str) -> dict:
    """Signal B: has this URL (or its domain) already been observed on
    a known threat feed? Checked independently of the ML model."""
    normalized = normalize_url(raw_url)
    if not normalized:
        return {"matched": False, "url": raw_url, "records": []}

    domain = get_hostname(normalized)
    intel_repo = ThreatIntelRepository(db)
    matches = intel_repo.check(normalized, domain)

    return {
        "matched": len(matches) > 0,
        "url": raw_url,
        "normalizedUrl": normalized,
        "domain": domain,
        "records": [
            {
                "source": m.source,
                "matchedOn": "url" if m.normalized_url == normalized else "domain",
                "target": m.target,
                "verified": m.verified,
                "online": m.online,
                "firstSeen": m.first_seen,
                "lastSeen": m.last_seen,
            }
            for m in matches
        ],
    }
