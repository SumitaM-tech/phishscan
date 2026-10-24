from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.repository import FeedSyncRepository, ThreatIntelRepository
from app.services import threat_intel_service
from app.schemas.threat_intelligence import ThreatIntelCheckResponse, FeedSyncResult

router = APIRouter(prefix="/threat-intelligence", tags=["threat-intelligence"])


@router.get("/check", response_model=ThreatIntelCheckResponse)
def check_url(url: str = Query(..., description="URL to check against synced threat feeds"), db: Session = Depends(get_db)):
    return threat_intel_service.check_url(db, url)


@router.post("/sync", response_model=list[FeedSyncResult])
def trigger_sync(db: Session = Depends(get_db)):
    """Manual sync trigger -- useful for demos, or the first run before
    the scheduler's initial sync has landed. The scheduler otherwise
    keeps this fresh automatically (see app/scheduler.py)."""
    return threat_intel_service.sync_all(db)


@router.get("/status")
def sync_status(db: Session = Depends(get_db)):
    sync_repo = FeedSyncRepository(db)
    intel_repo = ThreatIntelRepository(db)
    return {
        "recordCounts": intel_repo.count_by_source(),
        "recentRuns": [
            {
                "source": r.source, "status": r.status, "startedAt": r.started_at,
                "finishedAt": r.finished_at, "recordsSeen": r.records_seen,
                "recordsNew": r.records_new, "message": r.message,
            }
            for r in sync_repo.latest()
        ],
    }
