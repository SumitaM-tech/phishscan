"""
Builds the InfrastructureGraph (nodes + edges) the frontend renders,
directly from the evidence bundle gathered by evidence_service. Node
types match lib/types.ts's GraphNodeType exactly: DOMAIN, SUBDOMAIN,
IP, ASN, REGISTRAR, NAMESERVER, TLS CERTIFICATE. SUBDOMAIN nodes are
derived from real Certificate Transparency log entries (see
_extract_subdomains below) -- passive enumeration of subdomains that
actually had a certificate issued for them, not a guess or wordlist.

Layout: a simple layered/radial placement (domain at the center,
each category in its own ring) -- good enough for the frontend's
graph view without needing a real force-directed layout on the
backend (the frontend can also just re-layout client-side; positions
here are a reasonable default).
"""
import math

# Only used to spot obviously suspicious tokens on a *discovered*
# subdomain (login/verify/secure-style lookalikes), reusing the same
# word list the classical URL features already use -- kept local
# (not importing app.features.url_features) so this module has no
# feature-engineering dependency, just a small, explicit list.
_SUSPICIOUS_SUBDOMAIN_WORDS = (
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "password", "billing", "support",
)
MAX_SUBDOMAIN_NODES = 20


def _registrable_domain(host: str) -> str:
    """Same lightweight eTLD+1 heuristic as datasets/audit_corpus.py's
    registrable_domain(), duplicated locally (not imported) so the
    live API package has no dependency on the offline datasets/
    package. Good enough to decide "is this CT name actually a
    subdomain of the investigated domain", not a full PSL."""
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return host
    two_label_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "co.jp", "com.br",
        "com.au", "co.za", "com.cn", "com.mx", "com.tr", "co.id", "co.kr",
    }
    last_two = ".".join(labels[-2:])
    if last_two in two_label_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _extract_subdomains(hostname: str, ct_entries: list[dict]) -> list[str]:
    """Real Certificate Transparency-derived subdomain enumeration:
    every `name_value` in a crt.sh entry can hold one or more SAN
    names (newline-separated) and may include wildcards. This is the
    standard *passive* way to discover subdomains actually used by a
    domain (no active brute-forcing, which is slower, noisier, and
    often blocked). We keep only names that are real subdomains of
    the investigated registrable domain (not the apex itself, not an
    unrelated SAN some CA bundled in), de-duplicate, drop bare
    wildcards, and cap the count so a domain with thousands of certs
    doesn't blow up the graph."""
    target_reg_domain = _registrable_domain(hostname)
    found: set[str] = set()
    for entry in ct_entries:
        raw = entry.get("name_value", "") or ""
        for name in raw.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name or name == hostname.lower() or name == target_reg_domain:
                continue
            if not name.endswith("." + target_reg_domain) and name != target_reg_domain:
                continue  # SAN for an unrelated domain on a shared cert -- not this target's subdomain
            found.add(name)
    return sorted(found)[:MAX_SUBDOMAIN_NODES]


def _subdomain_risk(name: str) -> str | None:
    return "medium" if any(w in name for w in _SUSPICIOUS_SUBDOMAIN_WORDS) else None



def _pos(ring: int, index: int, count: int) -> dict:
    if ring == 0:
        return {"x": 0.0, "y": 0.0}
    radius = ring * 160
    angle = (2 * math.pi * index) / max(count, 1)
    return {"x": round(radius * math.cos(angle), 1), "y": round(radius * math.sin(angle), 1)}


def build_graph(investigation_id: str, hostname: str, evidence_bundle: dict) -> dict:
    """investigation_id salts every node id so infrastructure shared
    across investigations (the same domain scanned twice, or two
    different domains sharing a nameserver/IP/ASN) never collides in
    the graph_nodes table, which uses these ids as its primary key."""
    def nid(local_id: str) -> str:
        return f"{investigation_id}::{local_id}"

    nodes: list[dict] = []
    edges: list[dict] = []

    domain_id = nid(f"domain::{hostname}")
    nodes.append({
        "id": domain_id, "type": "DOMAIN", "label": hostname, "value": hostname,
        "is_target": True, "risk": None, "pos_x": 0.0, "pos_y": 0.0,
        "node_metadata": {"source": "target"},
    })

    # Nameservers (ring 1)
    nameservers = evidence_bundle.get("dns", {}).get("nameservers", [])
    for i, ns in enumerate(nameservers):
        ns_id = nid(f"ns::{ns}")
        pos = _pos(1, i, len(nameservers))
        nodes.append({
            "id": ns_id, "type": "NAMESERVER", "label": ns, "value": ns,
            "is_target": False, "risk": None, "pos_x": pos["x"], "pos_y": pos["y"],
            "node_metadata": {},
        })
        edges.append({"source": domain_id, "target": ns_id, "relationship_label": "uses"})

    # Subdomains discovered via Certificate Transparency logs (ring 1)
    # -- real, passive subdomain enumeration from actual issued certs,
    # not a guess or a brute-force wordlist.
    ct_entries = evidence_bundle.get("ct", {}).get("entries", []) or []
    subdomains = _extract_subdomains(hostname, ct_entries)
    for i, sub in enumerate(subdomains):
        sub_id = nid(f"subdomain::{sub}")
        pos = _pos(1, len(nameservers) + i, len(nameservers) + len(subdomains))
        nodes.append({
            "id": sub_id, "type": "SUBDOMAIN", "label": sub, "value": sub,
            "is_target": False, "risk": _subdomain_risk(sub),
            "pos_x": pos["x"], "pos_y": pos["y"],
            "node_metadata": {"source": "certificate_transparency"},
        })
        edges.append({"source": domain_id, "target": sub_id, "relationship_label": "subdomain"})

    # Registrar (ring 1)
    registrar = evidence_bundle.get("rdap", {}).get("registrar")
    if registrar:
        reg_id = nid(f"registrar::{registrar}")
        pos = _pos(1, len(nameservers) + len(subdomains), len(nameservers) + len(subdomains) + 1)
        nodes.append({
            "id": reg_id, "type": "REGISTRAR", "label": registrar, "value": registrar,
            "is_target": False, "risk": None, "pos_x": pos["x"], "pos_y": pos["y"],
            "node_metadata": {"registered": evidence_bundle.get("rdap", {}).get("created") or ""},
        })
        edges.append({"source": domain_id, "target": reg_id, "relationship_label": "registered_by"})

    # TLS certificate (ring 1)
    cert_info = evidence_bundle.get("tls", {}).get("cert_info") or {}
    if cert_info:
        cert_id = nid(f"cert::{hostname}")
        risk = "medium" if cert_info.get("self_signed") else None
        pos = _pos(1, len(nameservers) + len(subdomains) + 1, len(nameservers) + len(subdomains) + 2)
        nodes.append({
            "id": cert_id, "type": "TLS CERTIFICATE", "label": cert_info.get("issuer", "Unknown issuer"),
            "value": cert_info.get("subject", hostname), "is_target": False, "risk": risk,
            "pos_x": pos["x"], "pos_y": pos["y"],
            "node_metadata": {
                "notBefore": cert_info.get("not_before", ""),
                "notAfter": cert_info.get("not_after", ""),
                "daysToExpiry": str(cert_info.get("days_to_expiry", "")),
            },
        })
        edges.append({"source": domain_id, "target": cert_id, "relationship_label": "secured_by"})

    # IPs (ring 2) + ASN (ring 3)
    ips = evidence_bundle.get("dns", {}).get("ips", [])
    asn_blocks = evidence_bundle.get("asn", [])
    asn_by_ip = {b.get("asn_info", {}).get("ip"): b.get("asn_info", {}) for b in asn_blocks if b.get("asn_info")}

    for i, ip in enumerate(ips):
        ip_id = nid(f"ip::{ip}")
        pos = _pos(2, i, len(ips))
        nodes.append({
            "id": ip_id, "type": "IP", "label": ip, "value": ip,
            "is_target": False, "risk": None, "pos_x": pos["x"], "pos_y": pos["y"],
            "node_metadata": {},
        })
        edges.append({"source": domain_id, "target": ip_id, "relationship_label": "resolves_to"})

        asn_info = asn_by_ip.get(ip)
        if asn_info and asn_info.get("asn"):
            asn_id = nid(f"asn::{asn_info['asn']}")
            if not any(n["id"] == asn_id for n in nodes):
                pos_a = _pos(3, i, max(len(ips), 1))
                nodes.append({
                    "id": asn_id, "type": "ASN", "label": f"AS{asn_info['asn']}",
                    "value": asn_info.get("org", ""), "is_target": False, "risk": None,
                    "pos_x": pos_a["x"], "pos_y": pos_a["y"],
                    "node_metadata": {"country": asn_info.get("country", ""), "registry": asn_info.get("registry", "")},
                })
            edges.append({"source": ip_id, "target": asn_id, "relationship_label": "belongs_to"})

    return {"nodes": nodes, "edges": edges}
