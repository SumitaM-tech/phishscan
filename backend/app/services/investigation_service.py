"""
Investigation orchestrator -- the "Investigation Layer" in the
architecture. Ties together evidence collection, graph construction,
feature extraction, ML scoring, findings generation, and persistence.

Flow (mirrors the architecture doc):
  normalize -> create record -> collect evidence -> build graph ->
  extract features -> score (hybrid model) -> findings -> risk ->
  store -> status=complete
"""
import logging
from datetime import datetime
from sqlalchemy.orm import Session

from app.database.repository import InvestigationRepository, PredictionRepository
from app.database import models
from app.services.url_service import normalize_url, get_hostname
from app.services.evidence_service import gather_evidence
from app.services.graph_service import build_graph
from app.services import threat_intel_service
from app.models.classifier import get_model

logger = logging.getLogger("phishscan.investigation")


def run_investigation(db: Session, target: str, follow_redirects: bool = True) -> models.Investigation:
    repo = InvestigationRepository(db)
    pred_repo = PredictionRepository(db)
    normalized = normalize_url(target)
    if not normalized:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    inv = repo.create(target=target, normalized_target=normalized)
    repo.set_status(inv, "running")

    try:
        hostname = get_hostname(normalized)

        # Signal B: has this URL/domain already been observed on a
        # known threat feed? Checked independently of the ML model so
        # a stale/undertrained model can't hide a confirmed phish.
        threat_intel = threat_intel_service.check_url(db, normalized)

        evidence_bundle = gather_evidence(normalized, follow_redirects=follow_redirects)
        graph = build_graph(inv.id, hostname, evidence_bundle)

        # Signal A: does this URL structurally/semantically look like
        # phishing, independent of whether it's been seen before?
        model = get_model()
        score_result = model.score_url(
            normalized,
            [_node_view(n) for n in graph["nodes"]],
            [_edge_view(e) for e in graph["edges"]],
        )

        final = _combine_signals(score_result, threat_intel)

        findings = generate_findings(evidence_bundle, score_result, graph, threat_intel)
        timeline = build_timeline(evidence_bundle, threat_intel)

        # Evidence rows -> DB dicts
        evidence_dicts = [
            {
                "provider": e["provider"], "category": e["category"], "label": e["label"],
                "value": e["value"], "status": e.get("status", "complete"),
                "observed_at": datetime.utcnow(),
            }
            for e in evidence_bundle["evidence"]
        ]
        repo.add_evidence(inv.id, evidence_dicts)

        provider_dicts = [
            {
                "provider": d["provider"], "category": d["category"], "state": d["state"],
                "latency_ms": d.get("latency_ms"), "message": d.get("message", ""),
            }
            for d in evidence_bundle["diagnostics"]
        ]
        repo.add_providers(inv.id, provider_dicts)

        repo.add_graph(inv.id, graph["nodes"], graph["edges"])
        repo.add_timeline(inv.id, timeline)

        finding_dicts = [
            {
                "title": f["title"], "severity": f["severity"], "summary": f["summary"],
                "evidence_ids": [], "status": "active",
            }
            for f in findings
        ]
        repo.add_findings(inv.id, finding_dicts)

        pred_repo.add(inv.id, _prediction_rows(score_result, threat_intel))

        rationale = _rationale(final, score_result, threat_intel, findings)
        repo.set_risk(
            inv,
            score=final["score"],
            verdict=final["verdict"],
            confidence=final["confidence"],
            rationale=rationale,
            coverage=evidence_bundle["coverage"],
        )

        final_status = "complete" if evidence_bundle["coverage"] >= 0.5 else "partial"
        repo.set_status(inv, final_status)

    except Exception as exc:  # noqa: BLE001
        logger.exception("Investigation %s failed", inv.id)
        # A failure partway through (e.g. a DB constraint error while
        # writing evidence/graph rows) leaves the session's transaction
        # in a rolled-back state; committing anything else without an
        # explicit rollback first raises a second, unrelated error and
        # aborts this cleanup too -- which is how an investigation ends
        # up stuck at "running" forever instead of being marked failed.
        db.rollback()
        repo.set_risk(inv, score=0, verdict="unknown", confidence=0, rationale=f"Investigation failed: {exc}", coverage=0)
        repo.set_status(inv, "failed")

    return repo.get(inv.id)


def _node_view(n: dict) -> dict:
    return {"id": n["id"], "type": n["type"], "is_target": n.get("is_target", False), "risk": n.get("risk")}


def _edge_view(e: dict) -> dict:
    return {"source": e["source"], "target": e["target"]}


def _combine_signals(score_result: dict, threat_intel: dict) -> dict:
    """Blends Signal A (ML) with Signal B (threat-feed match). A
    verified hit on a known feed is treated as ground truth and wins
    outright -- no ML score should be able to talk a confirmed,
    analyst-verified phish back down to "clean". An unverified hit
    still pushes the score up but doesn't override completely."""
    ml_score = score_result["score"] / 100.0

    if not threat_intel["matched"]:
        return {"score": score_result["score"], "verdict": score_result["verdict"], "confidence": score_result["confidence"]}

    verified = any(r.get("verified") for r in threat_intel["records"])
    if verified:
        blended = max(ml_score, 0.98)
    else:
        blended = max(ml_score, 0.85)

    verdict = "malicious" if blended >= 0.75 else ("suspicious" if blended >= 0.45 else "clean")
    return {
        "score": round(blended * 100, 1),
        "verdict": verdict,
        "confidence": round(0.5 + abs(blended - 0.5), 3),
    }


def _prediction_rows(score_result: dict, threat_intel: dict) -> list[dict]:
    rows = []
    for name, score in (score_result.get("baseline_scores") or {}).items():
        if score is not None:
            rows.append({"model_name": name, "score": score, "label": "phishing" if score >= 0.5 else "legitimate", "detail": {}})
    if score_result.get("hybrid_score") is not None:
        rows.append({
            "model_name": "hybrid",
            "score": score_result["hybrid_score"],
            "label": "phishing" if score_result["hybrid_score"] >= 0.5 else "legitimate",
            "detail": {"alpha": score_result.get("semantic_weight"), "beta": score_result.get("graph_weight")},
        })
    if threat_intel["matched"]:
        rows.append({
            "model_name": "threat_intel",
            "score": 1.0,
            "label": "phishing",
            "detail": {"sources": [r["source"] for r in threat_intel["records"]]},
        })
    return rows


def generate_findings(evidence_bundle: dict, score_result: dict, graph: dict, threat_intel: dict | None = None) -> list[dict]:
    findings = []
    feats = score_result.get("features", {})
    http_signals = evidence_bundle.get("http", {}).get("page_signals", {})
    cert_info = evidence_bundle.get("tls", {}).get("cert_info", {})

    if threat_intel and threat_intel.get("matched"):
        sources = sorted({r["source"] for r in threat_intel["records"]})
        verified = any(r.get("verified") for r in threat_intel["records"])
        label = "Verified" if verified else "Reported"
        findings.append({
            "title": f"{label} match on known threat-intelligence feed",
            "severity": "critical",
            "summary": f"This URL or its domain is present in {', '.join(s.title() for s in sources)}, a feed of previously observed phishing infrastructure.",
        })

    if feats.get("has_ip_host"):
        findings.append({
            "title": "Raw IP address used as host",
            "severity": "high",
            "summary": "The target URL uses a numeric IP address instead of a domain name, a pattern rarely used by legitimate services and common in phishing infrastructure.",
        })

    if feats.get("suspicious_word_count", 0) >= 2:
        findings.append({
            "title": "Suspicious lexical patterns in URL",
            "severity": "medium",
            "summary": "The URL contains multiple terms commonly used in phishing lures (e.g. 'secure', 'verify', 'login', 'account').",
        })

    if feats.get("brand_token_count", 0) >= 1 and not feats.get("has_https"):
        findings.append({
            "title": "Brand impersonation without HTTPS",
            "severity": "high",
            "summary": "The URL references a well-known brand name but is not served over HTTPS, inconsistent with the real brand's site.",
        })
    elif feats.get("brand_token_count", 0) >= 1:
        findings.append({
            "title": "Possible brand impersonation",
            "severity": "medium",
            "summary": "The domain contains a recognizable brand token that does not match the domain's registrar or certificate issuer.",
        })

    # Extra signals available when the synthetic-trained model is the active
    # scorer (keys are absent in backup mode, so these simply don't fire).
    if feats.get("leet_brand_match") or feats.get("near_brand_typosquat"):
        findings.append({
            "title": "Possible typosquatted brand domain",
            "severity": "high",
            "summary": "The domain name is a near-miss of a well-known brand (character swaps, look-alike digits or a single-letter change) and is not that brand's official domain.",
        })
    if feats.get("brand_exact_unofficial_domain") or feats.get("subdomain_brand_unofficial") or feats.get("path_brand_unofficial"):
        findings.append({
            "title": "Brand name used on an unofficial domain",
            "severity": "high",
            "summary": "A well-known brand name appears in the subdomain, domain or path, but the registrable domain is not one the brand owns.",
        })
    if feats.get("path_lure_word_count", 0) >= 2 or (feats.get("path_lure_word_count", 0) >= 1 and feats.get("path_script_ext")):
        findings.append({
            "title": "Credential-lure terms in URL path",
            "severity": "medium",
            "summary": "The path combines lure vocabulary (e.g. login, verify, secure, invoice) with script-style endpoints commonly seen in phishing kits.",
        })
    if feats.get("redirect_cross_domain"):
        findings.append({
            "title": "Redirect parameter points to a different domain",
            "severity": "medium",
            "summary": "A query parameter embeds a URL on another registrable domain, a pattern used for open-redirect abuse and link cloaking.",
        })
    if feats.get("path_dangerous_ext"):
        findings.append({
            "title": "Link points to an executable or archive",
            "severity": "high",
            "summary": "The URL path ends in an executable or archive file type (e.g. .exe, .scr, .apk, .zip), a common malware delivery pattern.",
        })
    if feats.get("tld_cheap") and feats.get("is_free_hosting") == 0 and feats.get("sld_vowel_ratio", 1) < 0.2 and feats.get("sld_length", 0) >= 8:
        findings.append({
            "title": "Random-looking domain on a low-cost TLD",
            "severity": "medium",
            "summary": "The domain name looks algorithmically generated and uses a TLD that is heavily used by throwaway phishing infrastructure.",
        })

    if feats.get("is_shortened"):
        findings.append({
            "title": "URL shortener detected",
            "severity": "medium",
            "summary": "The link uses a URL-shortening service, which is often used to obscure the true destination.",
        })

    if cert_info.get("self_signed"):
        findings.append({
            "title": "Self-signed TLS certificate",
            "severity": "high",
            "summary": "The site presents a self-signed certificate rather than one from a trusted certificate authority.",
        })
    if isinstance(cert_info.get("days_to_expiry"), int) and cert_info["days_to_expiry"] < 0:
        findings.append({
            "title": "Expired TLS certificate",
            "severity": "medium",
            "summary": "The TLS certificate presented by the site has already expired.",
        })

    if http_signals.get("has_password_field") and http_signals.get("has_external_form_action"):
        findings.append({
            "title": "Login form posts to external domain",
            "severity": "critical",
            "summary": "The page contains a password field whose form submits to a different domain than the one visited, a strong credential-harvesting indicator.",
        })
    elif http_signals.get("has_password_field"):
        findings.append({
            "title": "Login form present",
            "severity": "low",
            "summary": "The page includes a password field. Not inherently malicious, but worth reviewing alongside the other findings.",
        })

    redirect_chain = evidence_bundle.get("http", {}).get("redirect_chain", [])
    if len(redirect_chain) >= 3:
        findings.append({
            "title": "Long redirect chain",
            "severity": "low",
            "summary": f"The URL passed through {len(redirect_chain)} redirects before reaching its final destination.",
        })

    ct_entries = evidence_bundle.get("ct", {}).get("entries", [])
    if isinstance(ct_entries, list) and len(ct_entries) > 25:
        findings.append({
            "title": "High certificate issuance volume",
            "severity": "low",
            "summary": f"Certificate Transparency logs show {len(ct_entries)} certificates issued referencing this domain, consistent with rapid subdomain generation seen in some phishing kits.",
        })

    if feats.get("subdomain_count", 0) >= 3:
        findings.append({
            "title": "Deep subdomain nesting",
            "severity": "medium",
            "summary": "The domain uses an unusually high number of subdomain levels, a pattern sometimes used to disguise the true destination in the address bar.",
        })

    if score_result.get("model_mode") == "hybrid":
        alpha = score_result.get("semantic_weight")
        beta = score_result.get("graph_weight")
        if alpha is not None and beta is not None:
            findings.append({
                "title": "Model fusion weighting",
                "severity": "info",
                "summary": f"The adaptive fusion layer weighted the semantic URL signal at {alpha:.2f} and the infrastructure graph signal at {beta:.2f} for this verdict.",
            })

    if not findings:
        findings.append({
            "title": "No strong indicators detected",
            "severity": "info",
            "summary": "Automated analysis did not surface significant phishing indicators for this target.",
        })

    return findings


def build_timeline(evidence_bundle: dict, threat_intel: dict | None = None) -> list[dict]:
    events = []
    now = datetime.utcnow()
    events.append({"timestamp": now, "title": "Investigation started", "detail": "Evidence collection initiated across DNS, RDAP, TLS, HTTP and CT providers.", "type": "observed"})

    if threat_intel and threat_intel.get("matched"):
        for record in threat_intel["records"]:
            events.append({
                "timestamp": _safe_dt_value(record.get("firstSeen"), now),
                "title": f"First observed on {record['source'].title()}",
                "detail": f"Matched on {record['matchedOn']}" + (f", target: {record['target']}" if record.get("target") else "."),
                "type": "observed",
            })

    created = evidence_bundle.get("rdap", {}).get("created")
    if created:
        events.append({"timestamp": _safe_dt(created, now), "title": "Domain registered", "detail": f"Registration event recorded at {created}.", "type": "registered"})

    cert_info = evidence_bundle.get("tls", {}).get("cert_info", {})
    if cert_info.get("not_before"):
        events.append({"timestamp": _safe_dt(cert_info["not_before"], now), "title": "TLS certificate issued", "detail": f"Issuer: {cert_info.get('issuer', 'unknown')}", "type": "issued"})

    events.append({"timestamp": now, "title": "Evidence collection complete", "detail": "All collectors returned or timed out; graph and risk assessment generated.", "type": "changed"})

    events.sort(key=lambda e: e["timestamp"])
    return events


def _safe_dt(value: str, fallback: datetime) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:  # noqa: BLE001
        return fallback


def _safe_dt_value(value, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return _safe_dt(value, fallback)
    return fallback


def _rationale(final: dict, score_result: dict, threat_intel: dict, findings: list[dict]) -> str:
    top = sorted(findings, key=lambda f: _severity_rank(f["severity"]), reverse=True)[:2]
    mode = score_result.get("model_mode", "heuristic")
    parts = [f"ML model mode: {mode} (score {score_result['score']}/100)."]
    if threat_intel.get("matched"):
        sources = sorted({r["source"] for r in threat_intel["records"]})
        parts.append(f"Threat-intel match: {', '.join(sources)}.")
    else:
        parts.append("No threat-intel feed match.")
    parts.append(f"Combined score {final['score']}/100.")
    if top:
        parts.append("Key signals: " + "; ".join(f["title"] for f in top) + ".")
    return " ".join(parts)


def _severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)
