"""
Storage layer schema.

Tables map directly onto the frontend's Investigation object so that
assembling an API response is mostly a straight read + group-by,
with no impedance mismatch between what's stored and what's served.
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Float, Integer, DateTime, ForeignKey, JSON, Boolean, Text, UniqueConstraint
)
from sqlalchemy.orm import relationship

from app.database.database import Base


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String, primary_key=True, default=lambda: new_id("INV"))
    target = Column(String, nullable=False)
    normalized_target = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="queued")  # queued|running|complete|partial|failed

    # Risk assessment (flattened onto the investigation row, 1:1)
    risk_score = Column(Float, default=0.0)
    risk_verdict = Column(String, default="unknown")  # malicious|suspicious|clean|unknown
    risk_confidence = Column(Float, default=0.0)
    risk_rationale = Column(Text, default="")

    coverage = Column(Float, default=0.0)

    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="investigation", cascade="all, delete-orphan")
    providers = relationship("ProviderDiagnostic", back_populates="investigation", cascade="all, delete-orphan")
    graph_nodes = relationship("GraphNode", back_populates="investigation", cascade="all, delete-orphan")
    graph_edges = relationship("GraphEdge", back_populates="investigation", cascade="all, delete-orphan")
    timeline = relationship("TimelineEvent", back_populates="investigation", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="investigation", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: new_id("FND"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    title = Column(String)
    severity = Column(String)  # critical|high|medium|low|info
    summary = Column(Text)
    evidence_ids = Column(JSON, default=list)
    status = Column(String, default="active")  # active|resolved

    investigation = relationship("Investigation", back_populates="findings")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, default=lambda: new_id("EVD"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    provider = Column(String)
    category = Column(String)  # DNS|RDAP|ASN|TLS|CT|HTTP
    label = Column(String)
    value = Column(Text)
    observed_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="pending")  # complete|partial|unavailable|pending

    investigation = relationship("Investigation", back_populates="evidence")


class ProviderDiagnostic(Base):
    __tablename__ = "provider_diagnostics"

    id = Column(String, primary_key=True, default=lambda: new_id("PRV"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    provider = Column(String)
    category = Column(String)
    state = Column(String, default="pending")
    latency_ms = Column(Integer, nullable=True)
    message = Column(Text, default="")

    investigation = relationship("Investigation", back_populates="providers")


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id = Column(String, primary_key=True, default=lambda: new_id("NODE"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    type = Column(String)  # DOMAIN|SUBDOMAIN|IP|ASN|REGISTRAR|NAMESERVER|TLS CERTIFICATE
    label = Column(String)
    value = Column(String)
    is_target = Column(Boolean, default=False)
    risk = Column(String, nullable=True)  # critical|high|medium|low|info
    pos_x = Column(Float, default=0.0)
    pos_y = Column(Float, default=0.0)
    node_metadata = Column(JSON, default=dict)

    investigation = relationship("Investigation", back_populates="graph_nodes")


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id = Column(String, primary_key=True, default=lambda: new_id("EDGE"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    source = Column(String)
    target = Column(String)
    relationship_label = Column(String)

    investigation = relationship("Investigation", back_populates="graph_edges")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True, default=lambda: new_id("TML"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    title = Column(String)
    detail = Column(Text)
    type = Column(String)  # observed|registered|issued|changed

    investigation = relationship("Investigation", back_populates="timeline")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: new_id("RPT"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    title = Column(String)
    format = Column(String)  # PDF|JSON|HTML
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="generating")  # ready|generating
    size = Column(String, default="0 KB")
    file_path = Column(String, nullable=True)

    investigation = relationship("Investigation", back_populates="reports")


class ThreatIntelRecord(Base):
    """
    Local mirror of real-time threat-intelligence feeds (PhishTank,
    OpenPhish). Populated by app/services/threat_intel_service.py,
    either on a schedule (app/scheduler.py) or via a manual sync
    trigger -- never by hand-editing this table or committing dataset
    files into the app.
    """
    __tablename__ = "threat_intel_records"

    id = Column(String, primary_key=True, default=lambda: new_id("TI"))
    url = Column(String, nullable=False)
    normalized_url = Column(String, nullable=False, index=True)
    domain = Column(String, index=True)
    ip = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    source = Column(String, nullable=False)  # phishtank|openphish
    label = Column(String, default="phishing")
    target = Column(String, nullable=True)  # brand/org impersonated, if the feed says
    verified = Column(Boolean, nullable=True)  # PhishTank-specific
    online = Column(Boolean, nullable=True)  # PhishTank-specific
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    raw_metadata = Column(JSON, default=dict)

    __table_args__ = (
        UniqueConstraint("normalized_url", "source", name="uq_threat_intel_url_source"),
    )


class FeedSyncRun(Base):
    """Audit trail for scheduled/manual feed syncs -- lets the API and
    the operator see when each source last ran and how it went, instead
    of that only living in log files."""
    __tablename__ = "feed_sync_runs"

    id = Column(String, primary_key=True, default=lambda: new_id("SYNC"))
    source = Column(String, nullable=False)  # phishtank|openphish
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String, default="running")  # running|success|failed
    records_seen = Column(Integer, default=0)
    records_new = Column(Integer, default=0)
    message = Column(Text, default="")


class Prediction(Base):
    """Per-model prediction audit trail for an investigation -- the
    individual RF/XGBoost/SVM/hybrid outputs that get blended into the
    single risk score on the investigation row. Kept separate so the
    ablation story (which model said what) is queryable later without
    re-running inference; not exposed on the public API contract."""
    __tablename__ = "predictions"

    id = Column(String, primary_key=True, default=lambda: new_id("PRED"))
    investigation_id = Column(String, ForeignKey("investigations.id"))
    model_name = Column(String, nullable=False)  # random_forest|xgboost|svm|hybrid|threat_intel
    score = Column(Float, nullable=False)  # 0-1 probability
    label = Column(String, nullable=False)  # phishing|legitimate
    detail = Column(JSON, default=dict)  # e.g. {"alpha":0.8,"beta":0.2} for hybrid
    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation")
