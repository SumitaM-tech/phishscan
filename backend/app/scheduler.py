"""
Runs PhishTank/OpenPhish sync on a recurring schedule so the local
threat-intelligence table stays current without anyone manually
downloading or uploading a dataset. Controlled entirely by env vars
(ENABLE_FEED_SCHEDULER, *_SYNC_INTERVAL_MINUTES) -- disabled by
default in test/CI-style runs if you set ENABLE_FEED_SCHEDULER=false.

Uses APScheduler's BackgroundScheduler (thread-based, no extra event
loop to manage) with its own short-lived DB session per job run.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import settings
from app.database.database import SessionLocal
from app.services import threat_intel_service

logger = logging.getLogger("phishscan.scheduler")

_scheduler: BackgroundScheduler | None = None


def _run_phishtank_sync():
    db = SessionLocal()
    try:
        threat_intel_service.sync_phishtank(db)
    finally:
        db.close()


def _run_openphish_sync():
    db = SessionLocal()
    try:
        threat_intel_service.sync_openphish(db)
    finally:
        db.close()


def start_scheduler():
    global _scheduler
    if not settings.ENABLE_FEED_SCHEDULER:
        logger.info("Feed scheduler disabled (ENABLE_FEED_SCHEDULER=false)")
        return
    if _scheduler is not None:
        return  # already running (e.g. re-entrant startup in tests)

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        _run_phishtank_sync, "interval",
        minutes=settings.PHISHTANK_SYNC_INTERVAL_MINUTES,
        id="phishtank_sync", next_run_time=None,
    )
    _scheduler.add_job(
        _run_openphish_sync, "interval",
        minutes=settings.OPENPHISH_SYNC_INTERVAL_MINUTES,
        id="openphish_sync", next_run_time=None,
    )
    _scheduler.start()
    logger.info(
        "Feed scheduler started: phishtank every %sm, openphish every %sm",
        settings.PHISHTANK_SYNC_INTERVAL_MINUTES, settings.OPENPHISH_SYNC_INTERVAL_MINUTES,
    )

    if settings.SYNC_ON_STARTUP:
        # Kick off an immediate first sync in the background rather than
        # waiting a full interval, so a fresh install has threat-intel
        # data within seconds instead of up to an hour.
        _scheduler.add_job(_run_phishtank_sync, id="phishtank_sync_initial")
        _scheduler.add_job(_run_openphish_sync, id="openphish_sync_initial")


def stop_scheduler():
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
