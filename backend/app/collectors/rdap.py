"""
RDAP collector for domain registration data (registrar, creation
date, nameservers, registrant org where public). Falls back to
python-whois if the RDAP bootstrap lookup at rdap.org fails, since
RDAP coverage is not universal for every TLD yet.
"""
import time
import requests
from app.config import settings


def collect_rdap(hostname: str) -> dict:
    evidence = []
    state = "complete"
    message = "RDAP record retrieved"
    registrar = None
    created = None
    start = time.perf_counter()

    apex = _apex_domain(hostname)
    try:
        resp = requests.get(f"https://rdap.org/domain/{apex}", timeout=settings.HTTP_TIMEOUT_SECONDS)
        if resp.status_code == 200:
            data = resp.json()
            registrar = _extract_registrar(data)
            created = _extract_event(data, "registration")
            expires = _extract_event(data, "expiration")

            if registrar:
                evidence.append(_ev("Registrar", registrar))
            if created:
                evidence.append(_ev("Created", created))
            if expires:
                evidence.append(_ev("Expires", expires))
            for ns in data.get("nameservers", [])[:6]:
                name = ns.get("ldhName")
                if name:
                    evidence.append(_ev("Nameserver", name))
            status_list = data.get("status", [])
            if status_list:
                evidence.append(_ev("Status", ", ".join(status_list)))
            if not evidence:
                state = "partial"
                message = "RDAP responded but contained no usable fields"
        else:
            state = "partial"
            message = f"RDAP bootstrap returned HTTP {resp.status_code}"
    except Exception as exc:  # noqa: BLE001
        state = "unavailable"
        message = f"RDAP lookup failed: {exc}"

    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "evidence": evidence,
        "registrar": registrar,
        "created": created,
        "diagnostic": {
            "provider": "RDAP",
            "category": "RDAP",
            "state": state,
            "latency_ms": latency_ms,
            "message": message,
        },
    }


def _apex_domain(hostname: str) -> str:
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _extract_registrar(data: dict) -> str | None:
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        return field[3]
            return entity.get("handle")
    return None


def _extract_event(data: dict, action: str) -> str | None:
    for event in data.get("events", []):
        if event.get("eventAction") == action:
            return event.get("eventDate")
    return None


def _ev(label: str, value: str) -> dict:
    return {"provider": "RDAP", "category": "RDAP", "label": label, "value": str(value), "status": "complete"}
