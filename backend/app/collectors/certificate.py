"""
Certificate Transparency collector via crt.sh.

Surfaces how many certs have been issued for the domain and how
recently -- a burst of freshly issued certs for many lookalike
subdomains is a classic phishing-kit fingerprint.
"""
import time
import requests
from app.config import settings


def collect_ct(hostname: str) -> dict:
    evidence = []
    state = "complete"
    message = "Certificate Transparency logs queried"
    entries = []
    start = time.perf_counter()

    if not settings.CT_LOOKUP_ENABLED:
        return {
            "evidence": [],
            "entries": [],
            "diagnostic": {
                "provider": "crt.sh",
                "category": "CT",
                "state": "unavailable",
                "latency_ms": 0,
                "message": "CT lookups disabled by configuration",
            },
        }

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": hostname, "output": "json"},
            timeout=settings.HTTP_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200 and resp.text.strip():
            entries = resp.json()
            unique_names = {e.get("name_value", "") for e in entries}
            issuers = {e.get("issuer_name", "") for e in entries}

            evidence.append(_ev("Certificates Found", str(len(entries))))
            evidence.append(_ev("Unique SAN Names", str(len(unique_names))))
            for issuer in list(issuers)[:3]:
                evidence.append(_ev("CT Issuer", issuer))

            if len(entries) == 0:
                state = "partial"
                message = "No certificates found in CT logs"
        else:
            state = "partial"
            message = f"crt.sh returned HTTP {resp.status_code}"
    except Exception as exc:  # noqa: BLE001
        state = "unavailable"
        message = f"CT lookup failed: {exc}"

    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "evidence": evidence,
        "entries": entries,
        "diagnostic": {
            "provider": "crt.sh",
            "category": "CT",
            "state": state,
            "latency_ms": latency_ms,
            "message": message,
        },
    }


def _ev(label: str, value: str) -> dict:
    return {"provider": "crt.sh", "category": "CT", "label": label, "value": str(value), "status": "complete"}
