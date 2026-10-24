"""
TLS collector: connects on 443, pulls the leaf certificate and
reports issuer, subject, validity window and days-to-expiry -- all
strong phishing signals (freshly-issued free certs on lookalike
domains are extremely common in phishing kits).
"""
import ssl
import socket
import time
from datetime import datetime
from app.config import settings


def collect_tls(hostname: str, port: int = 443) -> dict:
    evidence = []
    state = "complete"
    message = "TLS certificate retrieved"
    cert_info = {}
    start = time.perf_counter()

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=settings.TLS_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                cert_info = _parse_der(der)

        if cert_info:
            evidence.append(_ev("Issuer", cert_info.get("issuer", "unknown")))
            evidence.append(_ev("Subject", cert_info.get("subject", "unknown")))
            evidence.append(_ev("Not Before", cert_info.get("not_before", "")))
            evidence.append(_ev("Not After", cert_info.get("not_after", "")))
            evidence.append(_ev("Days To Expiry", str(cert_info.get("days_to_expiry", ""))))
            evidence.append(_ev("Self-Signed", str(cert_info.get("self_signed", False))))
        else:
            state = "partial"
            message = "Connected but certificate could not be parsed"
    except Exception as exc:  # noqa: BLE001
        state = "unavailable"
        message = f"TLS handshake failed: {exc}"

    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "evidence": evidence,
        "cert_info": cert_info,
        "diagnostic": {
            "provider": "TLS Inspector",
            "category": "TLS",
            "state": state,
            "latency_ms": latency_ms,
            "message": message,
        },
    }


def _parse_der(der_bytes: bytes) -> dict:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    now = datetime.now(not_after.tzinfo) if not_after.tzinfo else datetime.utcnow()
    days_left = (not_after - now).days

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    return {
        "issuer": issuer,
        "subject": subject,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_to_expiry": days_left,
        "self_signed": issuer == subject,
    }


def _ev(label: str, value: str) -> dict:
    return {"provider": "TLS Inspector", "category": "TLS", "label": label, "value": str(value), "status": "complete"}
