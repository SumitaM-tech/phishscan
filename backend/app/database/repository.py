"""
Thin repository layer. Keeps raw SQLAlchemy queries out of the
service layer so services stay focused on orchestration logic.
"""
from __future__ import annotations
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from sqlalchemy.exc import IntegrityError

from app.database import models


class InvestigationRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, target: str, normalized_target: str) -> models.Investigation:
        inv = models.Investigation(
            target=target,
            normalized_target=normalized_target,
            status="queued",
            risk_verdict="unknown",
        )
        self.db.add(inv)
        self.db.commit()
        self.db.refresh(inv)
        return inv

    def get(self, investigation_id: str) -> models.Investigation | None:
        return (
            self.db.query(models.Investigation)
            .filter(models.Investigation.id == investigation_id)
            .first()
        )

    def list(self, limit: int = 200) -> list[models.Investigation]:
        return (
            self.db.query(models.Investigation)
            .order_by(desc(models.Investigation.created_at))
            .limit(limit)
            .all()
        )

    def sweep_orphaned(self) -> int:
        """Marks any investigation left in queued/running as failed.

        These are rows from a process that died or was restarted
        mid-investigation (killed terminal, server crash, or --reload
        restarting mid-request) -- run_investigation() only ever
        commits "running" then later "complete"/"partial"/"failed" in
        the SAME process, so anything still "queued"/"running" at the
        next startup is provably orphaned, not actually in progress.
        Left alone these sit in History forever showing 0% coverage
        and "Running", which is misleading and never resolves itself.
        Called once on app startup. Returns how many were cleaned up.
        """
        orphaned = (
            self.db.query(models.Investigation)
            .filter(models.Investigation.status.in_(["queued", "running"]))
            .all()
        )
        for inv in orphaned:
            inv.status = "failed"
            inv.completed_at = datetime.utcnow()
            inv.risk_verdict = "unknown"
            inv.risk_rationale = (
                "Investigation was interrupted before it finished (the server "
                "restarted or stopped mid-run) and has been marked failed. "
                "Start a new scan for this target."
            )
        if orphaned:
            self.db.commit()
        return len(orphaned)

    def set_status(self, inv: models.Investigation, status: str):
        inv.status = status
        if status in ("complete", "failed", "partial"):
            inv.completed_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(inv)

    def set_risk(self, inv: models.Investigation, score, verdict, confidence, rationale, coverage):
        inv.risk_score = score
        inv.risk_verdict = verdict
        inv.risk_confidence = confidence
        inv.risk_rationale = rationale
        inv.coverage = coverage
        self.db.commit()
        self.db.refresh(inv)

    def add_evidence(self, investigation_id: str, items: list[dict]):
        rows = [models.Evidence(investigation_id=investigation_id, **item) for item in items]
        self.db.add_all(rows)
        self.db.commit()

    def add_providers(self, investigation_id: str, items: list[dict]):
        rows = [models.ProviderDiagnostic(investigation_id=investigation_id, **item) for item in items]
        self.db.add_all(rows)
        self.db.commit()

    def add_findings(self, investigation_id: str, items: list[dict]):
        rows = [models.Finding(investigation_id=investigation_id, **item) for item in items]
        self.db.add_all(rows)
        self.db.commit()

    def add_graph(self, investigation_id: str, nodes: list[dict], edges: list[dict]):
        node_rows = [models.GraphNode(investigation_id=investigation_id, **n) for n in nodes]
        edge_rows = [models.GraphEdge(investigation_id=investigation_id, **e) for e in edges]
        self.db.add_all(node_rows + edge_rows)
        self.db.commit()

    def add_timeline(self, investigation_id: str, items: list[dict]):
        rows = [models.TimelineEvent(investigation_id=investigation_id, **item) for item in items]
        self.db.add_all(rows)
        self.db.commit()


class ReportRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, investigation_id: str, title: str, fmt: str) -> models.Report:
        rpt = models.Report(
            investigation_id=investigation_id, title=title, format=fmt, status="generating"
        )
        self.db.add(rpt)
        self.db.commit()
        self.db.refresh(rpt)
        return rpt

    def mark_ready(self, rpt: models.Report, file_path: str, size: str):
        rpt.status = "ready"
        rpt.file_path = file_path
        rpt.size = size
        self.db.commit()
        self.db.refresh(rpt)

    def list(self) -> list[models.Report]:
        return self.db.query(models.Report).order_by(desc(models.Report.created_at)).all()

    def get(self, report_id: str) -> models.Report | None:
        return self.db.query(models.Report).filter(models.Report.id == report_id).first()


class ThreatIntelRepository:
    """Upserts feed records keyed on (normalized_url, source) and serves
    the real-time /threat-intelligence/check lookup."""

    def __init__(self, db: Session):
        self.db = db

    def upsert(self, record: dict) -> bool:
        """Returns True if this was a brand-new record, False if it
        already existed (and had last_seen/metadata refreshed)."""
        existing = (
            self.db.query(models.ThreatIntelRecord)
            .filter(
                models.ThreatIntelRecord.normalized_url == record["normalized_url"],
                models.ThreatIntelRecord.source == record["source"],
            )
            .first()
        )
        if existing:
            existing.last_seen = record.get("last_seen", datetime.utcnow())
            existing.verified = record.get("verified", existing.verified)
            existing.online = record.get("online", existing.online)
            existing.target = record.get("target", existing.target)
            existing.raw_metadata = record.get("raw_metadata", existing.raw_metadata)
            self.db.commit()
            return False

        row = models.ThreatIntelRecord(**record)
        self.db.add(row)
        try:
            self.db.commit()
            return True
        except IntegrityError:
            # Race with a concurrent sync job inserting the same
            # (normalized_url, source) pair -- treat as an update, not
            # an error.
            self.db.rollback()
            return False

    def check(self, normalized_url: str, domain: str | None) -> list[models.ThreatIntelRecord]:
        q = self.db.query(models.ThreatIntelRecord).filter(
            models.ThreatIntelRecord.normalized_url == normalized_url
        )
        matches = q.all()
        if not matches and domain:
            matches = (
                self.db.query(models.ThreatIntelRecord)
                .filter(models.ThreatIntelRecord.domain == domain)
                .all()
            )
        return matches

    def count_by_source(self) -> dict:
        rows = (
            self.db.query(models.ThreatIntelRecord.source, func.count(models.ThreatIntelRecord.id))
            .group_by(models.ThreatIntelRecord.source)
            .all()
        )
        return {source: count for source, count in rows}


class FeedSyncRepository:
    def __init__(self, db: Session):
        self.db = db

    def start(self, source: str) -> models.FeedSyncRun:
        run = models.FeedSyncRun(source=source, status="running")
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        return run

    def finish(self, run: models.FeedSyncRun, status: str, records_seen: int, records_new: int, message: str = ""):
        run.status = status
        run.records_seen = records_seen
        run.records_new = records_new
        run.message = message
        run.finished_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(run)

    def latest(self) -> list[models.FeedSyncRun]:
        rows = (
            self.db.query(models.FeedSyncRun)
            .order_by(desc(models.FeedSyncRun.started_at))
            .limit(20)
            .all()
        )
        return rows


class PredictionRepository:
    def __init__(self, db: Session):
        self.db = db

    def add(self, investigation_id: str, items: list[dict]):
        rows = [models.Prediction(investigation_id=investigation_id, **item) for item in items]
        self.db.add_all(rows)
        self.db.commit()
