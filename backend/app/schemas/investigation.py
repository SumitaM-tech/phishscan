"""
Pydantic response models.

These are a 1:1 mirror of frontend/lib/types.ts. Field names use
camelCase aliases so the JSON returned by FastAPI is exactly what
the Next.js frontend already expects -- no adapter layer needed on
either side.
"""
from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field

CamelModel = lambda: ConfigDict(populate_by_name=True, from_attributes=True)  # noqa: E731

Verdict = Literal["malicious", "suspicious", "clean", "unknown"]
Severity = Literal["critical", "high", "medium", "low", "info"]
ProviderState = Literal["complete", "partial", "unavailable", "pending"]
GraphNodeType = Literal["DOMAIN", "SUBDOMAIN", "IP", "ASN", "REGISTRAR", "NAMESERVER", "TLS CERTIFICATE"]
EvidenceCategory = Literal["DNS", "RDAP", "ASN", "TLS", "CT", "HTTP"]


class RiskAssessment(BaseModel):
    model_config = CamelModel()
    score: float
    verdict: Verdict
    confidence: float
    rationale: str


class Finding(BaseModel):
    model_config = CamelModel()
    id: str
    title: str
    severity: Severity
    summary: str
    evidence_ids: list[str] = Field(alias="evidenceIds", default_factory=list)
    status: Literal["active", "resolved"]


class Evidence(BaseModel):
    model_config = CamelModel()
    id: str
    provider: str
    category: EvidenceCategory
    label: str
    value: str
    observed_at: datetime = Field(alias="observedAt")
    status: ProviderState


class ProviderDiagnostic(BaseModel):
    model_config = CamelModel()
    id: str
    provider: str
    category: EvidenceCategory
    state: ProviderState
    latency_ms: Optional[int] = Field(default=None, alias="latencyMs")
    message: str


class Position(BaseModel):
    x: float
    y: float


class GraphNode(BaseModel):
    model_config = CamelModel()
    id: str
    type: GraphNodeType
    label: str
    value: str
    is_target: Optional[bool] = Field(default=None, alias="isTarget")
    risk: Optional[Severity] = None
    position: Position
    metadata: dict = Field(default_factory=dict)


class GraphEdge(BaseModel):
    model_config = CamelModel()
    id: str
    source: str
    target: str
    relationship: str


class InfrastructureGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    model_config = CamelModel()
    id: str
    timestamp: datetime
    title: str
    detail: str
    type: Literal["observed", "registered", "issued", "changed"]


class Investigation(BaseModel):
    model_config = CamelModel()
    id: str
    target: str
    normalized_target: str = Field(alias="normalizedTarget")
    created_at: datetime = Field(alias="createdAt")
    completed_at: Optional[datetime] = Field(default=None, alias="completedAt")
    status: Literal["queued", "running", "complete", "partial", "failed"]
    risk: RiskAssessment
    coverage: float
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    providers: list[ProviderDiagnostic] = Field(default_factory=list)
    graph: InfrastructureGraph
    timeline: list[TimelineEvent] = Field(default_factory=list)


class Report(BaseModel):
    model_config = CamelModel()
    id: str
    investigation_id: str = Field(alias="investigationId")
    title: str
    format: Literal["PDF", "JSON", "HTML"]
    created_at: datetime = Field(alias="createdAt")
    status: Literal["ready", "generating"]
    size: str


class CreateInvestigationRequest(BaseModel):
    target: str


class CreateReportRequest(BaseModel):
    model_config = CamelModel()
    investigation_id: str = Field(alias="investigationId")
    format: Literal["PDF", "JSON", "HTML"] = "PDF"
