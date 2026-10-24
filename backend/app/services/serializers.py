"""Converts ORM rows into the exact shape lib/types.ts's Investigation
expects. Kept separate from the Pydantic schema module so the schema
stays a pure contract definition and this stays "how we fill it in"."""
from app.database import models


def serialize_investigation(inv: models.Investigation) -> dict:
    return {
        "id": inv.id,
        "target": inv.target,
        "normalizedTarget": inv.normalized_target,
        "createdAt": inv.created_at,
        "completedAt": inv.completed_at,
        "status": inv.status,
        "risk": {
            "score": inv.risk_score,
            "verdict": inv.risk_verdict,
            "confidence": inv.risk_confidence,
            "rationale": inv.risk_rationale,
        },
        "coverage": inv.coverage,
        "findings": [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "summary": f.summary, "evidenceIds": f.evidence_ids or [],
                "status": f.status,
            }
            for f in inv.findings
        ],
        "evidence": [
            {
                "id": e.id, "provider": e.provider, "category": e.category,
                "label": e.label, "value": e.value, "observedAt": e.observed_at,
                "status": e.status,
            }
            for e in inv.evidence
        ],
        "providers": [
            {
                "id": p.id, "provider": p.provider, "category": p.category,
                "state": p.state, "latencyMs": p.latency_ms, "message": p.message,
            }
            for p in inv.providers
        ],
        "graph": {
            "nodes": [
                {
                    "id": n.id, "type": n.type, "label": n.label, "value": n.value,
                    "isTarget": n.is_target, "risk": n.risk,
                    "position": {"x": n.pos_x, "y": n.pos_y},
                    "metadata": n.node_metadata or {},
                }
                for n in inv.graph_nodes
            ],
            "edges": [
                {"id": e.id, "source": e.source, "target": e.target, "relationship": e.relationship_label}
                for e in inv.graph_edges
            ],
        },
        "timeline": [
            {"id": t.id, "timestamp": t.timestamp, "title": t.title, "detail": t.detail, "type": t.type}
            for t in inv.timeline
        ],
    }


def serialize_report(r: models.Report) -> dict:
    return {
        "id": r.id, "investigationId": r.investigation_id, "title": r.title,
        "format": r.format, "createdAt": r.created_at, "status": r.status,
        "size": r.size,
    }
