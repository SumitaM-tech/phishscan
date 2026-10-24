"""
DNS collector: A/AAAA/MX/NS/TXT resolution for a hostname.

Returns a list of evidence dicts (category="DNS") plus the resolved
IP list, which downstream collectors (RDAP/ASN) and the graph
builder depend on.
"""
import time
import dns.resolver
from app.config import settings


def collect_dns(hostname: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = settings.DNS_TIMEOUT_SECONDS
    resolver.lifetime = settings.DNS_TIMEOUT_SECONDS

    evidence = []
    ips, nameservers = [], []
    start = time.perf_counter()
    state = "complete"
    message = "DNS records resolved"

    def _query(rtype):
        try:
            return [str(r) for r in resolver.resolve(hostname, rtype)]
        except Exception:
            return []

    try:
        a_records = _query("A")
        aaaa_records = _query("AAAA")
        ns_records = _query("NS")
        mx_records = _query("MX")
        txt_records = _query("TXT")

        ips = a_records + aaaa_records
        nameservers = [r.rstrip(".") for r in ns_records]

        for ip in a_records:
            evidence.append(_ev("A", ip))
        for ip in aaaa_records:
            evidence.append(_ev("AAAA", ip))
        for ns in nameservers:
            evidence.append(_ev("NS", ns))
        for mx in mx_records:
            evidence.append(_ev("MX", mx))
        for txt in txt_records[:5]:
            evidence.append(_ev("TXT", txt))

        if not ips:
            state = "partial"
            message = "No A/AAAA records found"
    except Exception as exc:  # noqa: BLE001
        state = "unavailable"
        message = f"DNS lookup failed: {exc}"

    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "evidence": evidence,
        "ips": ips,
        "nameservers": nameservers,
        "diagnostic": {
            "provider": "DNS Resolver",
            "category": "DNS",
            "state": state,
            "latency_ms": latency_ms,
            "message": message,
        },
    }


def _ev(label: str, value: str) -> dict:
    return {"provider": "DNS Resolver", "category": "DNS", "label": label, "value": value, "status": "complete"}
