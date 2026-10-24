"""
ASN collector: resolves an IP to its announcing ASN, org name and
country via Team Cymru's whois service (no API key required, and
much lighter than a full RDAP-for-IP round trip).
"""
import socket
import time
from app.config import settings


def collect_asn(ip: str) -> dict:
    evidence = []
    state = "complete"
    message = "ASN record retrieved"
    asn_info = {}
    start = time.perf_counter()

    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=settings.DNS_TIMEOUT_SECONDS) as sock:
            sock.sendall(f" -v {ip}\n".encode())
            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        lines = raw.decode(errors="ignore").strip().split("\n")
        if len(lines) >= 2:
            fields = [f.strip() for f in lines[1].split("|")]
            if len(fields) >= 7:
                asn_info = {
                    "asn": fields[0],
                    "ip": fields[1],
                    "bgp_prefix": fields[2],
                    "country": fields[3],
                    "registry": fields[4],
                    "allocated": fields[5],
                    "org": fields[6],
                }
                evidence.append(_ev("ASN", asn_info["asn"]))
                evidence.append(_ev("Organization", asn_info["org"]))
                evidence.append(_ev("Country", asn_info["country"]))
                evidence.append(_ev("BGP Prefix", asn_info["bgp_prefix"]))
        if not asn_info:
            state = "partial"
            message = "No ASN record returned"
    except Exception as exc:  # noqa: BLE001
        state = "unavailable"
        message = f"ASN lookup failed: {exc}"

    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "evidence": evidence,
        "asn_info": asn_info,
        "diagnostic": {
            "provider": "Team Cymru",
            "category": "ASN",
            "state": state,
            "latency_ms": latency_ms,
            "message": message,
        },
    }


def _ev(label: str, value: str) -> dict:
    return {"provider": "Team Cymru", "category": "ASN", "label": label, "value": str(value), "status": "complete"}
