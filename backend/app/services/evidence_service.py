"""
Runs all collectors for a target URL and returns a unified bundle:
raw evidence rows, provider diagnostics, and the structured facts
(ips, registrar, nameservers, cert info, asn info) that graph_service
and the classifier need. Collectors run concurrently since they're
all I/O bound network calls.

Every future is bounded with an explicit result() timeout on top of
each collector's own internal timeout -- belt and suspenders against
a collector that hangs past its configured timeout (e.g. a raw TCP
connect() that doesn't respect socket.settimeout() cleanly on some
networks/OSes). A slow or hung collector degrades to "unavailable"
rather than stalling the whole investigation.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError

from app.config import settings
from app.collectors import dns as dns_collector
from app.collectors import rdap as rdap_collector
from app.collectors import tls as tls_collector
from app.collectors import http as http_collector
from app.collectors import certificate as ct_collector
from app.collectors import asn as asn_collector
from app.services.url_service import get_hostname

# Hard ceiling per collector, independent of the collector's own
# internal timeout setting -- catches TCP connects that ignore
# socket timeouts on some networks.
_HARD_TIMEOUT = max(
    settings.HTTP_TIMEOUT_SECONDS, settings.DNS_TIMEOUT_SECONDS, settings.TLS_TIMEOUT_SECONDS
) + 4


def _collect_result(future, key: str, label: str, timeout: float = _HARD_TIMEOUT) -> dict:
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError:
        return {
            "evidence": [],
            "diagnostic": {
                "provider": label, "category": key.upper(), "state": "unavailable",
                "latency_ms": int(timeout * 1000), "message": f"{label} timed out after {timeout:.0f}s",
            },
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "evidence": [],
            "diagnostic": {
                "provider": label, "category": key.upper(), "state": "unavailable",
                "latency_ms": None, "message": f"Collector crashed: {exc}",
            },
        }


def gather_evidence(url: str, follow_redirects: bool = True) -> dict:
    hostname = get_hostname(url)

    results = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(dns_collector.collect_dns, hostname): ("dns", "DNS Resolver"),
            pool.submit(rdap_collector.collect_rdap, hostname): ("rdap", "RDAP"),
            pool.submit(tls_collector.collect_tls, hostname): ("tls", "TLS Inspector"),
            pool.submit(http_collector.collect_http, url, follow_redirects): ("http", "HTTP Client"),
            pool.submit(ct_collector.collect_ct, hostname): ("ct", "crt.sh"),
        }
        for future in as_completed(futures, timeout=_HARD_TIMEOUT + 2):
            key, label = futures[future]
            results[key] = _collect_result(future, key, label)

    # ASN depends on DNS results (needs an IP), run after the pool above
    ips = results.get("dns", {}).get("ips", [])
    asn_results = []
    if ips:
        with ThreadPoolExecutor(max_workers=min(4, len(ips))) as pool:
            futures = {pool.submit(asn_collector.collect_asn, ip): ip for ip in ips[:4]}
            for future in as_completed(futures, timeout=_HARD_TIMEOUT + 2):
                asn_results.append(_collect_result(future, "asn", "Team Cymru"))
    results["asn"] = asn_results

    evidence_rows: list[dict] = []
    diagnostics: list[dict] = []

    for key in ("dns", "rdap", "tls", "http", "ct"):
        block = results.get(key, {})
        evidence_rows.extend(block.get("evidence", []))
        diag = block.get("diagnostic")
        if diag:
            diagnostics.append(diag)

    for asn_block in asn_results:
        evidence_rows.extend(asn_block.get("evidence", []))
        if asn_block.get("diagnostic"):
            diagnostics.append(asn_block["diagnostic"])

    coverage = _coverage(diagnostics)

    return {
        "hostname": hostname,
        "evidence": evidence_rows,
        "diagnostics": diagnostics,
        "coverage": coverage,
        "dns": results.get("dns", {}),
        "rdap": results.get("rdap", {}),
        "tls": results.get("tls", {}),
        "http": results.get("http", {}),
        "ct": results.get("ct", {}),
        "asn": asn_results,
    }


def _coverage(diagnostics: list[dict]) -> float:
    if not diagnostics:
        return 0.0
    weight = {"complete": 1.0, "partial": 0.5, "unavailable": 0.0, "pending": 0.0}
    total = sum(weight.get(d["state"], 0.0) for d in diagnostics)
    return round(total / len(diagnostics), 3)
