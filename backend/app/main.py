from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.config import settings
from app.database.database import init_db, SessionLocal
from app.database.repository import InvestigationRepository
from app.api import investigations, reports, health, threat_intelligence
from app import scheduler

logger = logging.getLogger("phishscan.main")

app = FastAPI(title=settings.APP_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()

    # Clean up anything left "running" by a process that died or was
    # restarted mid-investigation, so History doesn't accumulate
    # permanently-stuck rows (see InvestigationRepository.sweep_orphaned).
    db = SessionLocal()
    try:
        cleaned = InvestigationRepository(db).sweep_orphaned()
        if cleaned:
            logger.warning("Marked %d orphaned investigation(s) as failed on startup", cleaned)
    finally:
        db.close()

    scheduler.start_scheduler()


@app.on_event("shutdown")
def on_shutdown():
    scheduler.stop_scheduler()


app.include_router(health.router, prefix=settings.API_PREFIX)
app.include_router(investigations.router, prefix=settings.API_PREFIX)
app.include_router(reports.router, prefix=settings.API_PREFIX)
app.include_router(threat_intelligence.router, prefix=settings.API_PREFIX)


@app.get("/")
def root():
    return {"service": settings.APP_NAME, "docs": "/docs"}
