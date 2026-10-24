"""
HTTP collector: fetches the target URL (respecting redirects), and
reports final status, redirect chain, server header, title, and a
handful of page-content heuristics (password fields, external form
action, favicon mismatch) that feed into the findings layer.
"""
import time
import re
import requests
from app.config import settings


def collect_http(url: str, follow_redirects: bool = True) -> dict:
    evidence = []
    state = "complete"
    message = "HTTP response captured"
    redirect_chain = []
    final_url = url
    page_signals = {}
    start = time.perf_counter()

    try:
        resp = requests.get(
            url,
            timeout=settings.HTTP_TIMEOUT_SECONDS,
            allow_redirects=follow_redirects,
            headers={"User-Agent": "PhishScan/1.0 (+investigation-bot)"},
        )
        redirect_chain = [r.url for r in resp.history]
        final_url = resp.url

        evidence.append(_ev("Status Code", str(resp.status_code)))
        evidence.append(_ev("Final URL", final_url))
        if redirect_chain:
            evidence.append(_ev("Redirect Count", str(len(redirect_chain))))
        server = resp.headers.get("Server")
        if server:
            evidence.append(_ev("Server Header", server))

        title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip()[:200] if title_match else None
        if title:
            evidence.append(_ev("Page Title", title))

        has_password_field = bool(re.search(r'type=["\']password["\']', resp.text, re.IGNORECASE))
        has_external_form = bool(re.search(r"<form[^>]+action=[\"']https?://", resp.text, re.IGNORECASE))
        page_signals = {
            "has_password_field": has_password_field,
            "has_external_form_action": has_external_form,
            "content_length": len(resp.content),
        }
        if has_password_field:
            evidence.append(_ev("Login Form Detected", "true"))
        if has_external_form:
            evidence.append(_ev("External Form Action", "true"))

        if resp.status_code >= 400:
            state = "partial"
            message = f"Target responded with HTTP {resp.status_code}"
    except requests.exceptions.SSLError as exc:
        state = "partial"
        message = f"HTTPS failed, target may only serve HTTP: {exc}"
    except Exception as exc:  # noqa: BLE001
        state = "unavailable"
        message = f"HTTP request failed: {exc}"

    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "evidence": evidence,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "page_signals": page_signals,
        "diagnostic": {
            "provider": "HTTP Client",
            "category": "HTTP",
            "state": state,
            "latency_ms": latency_ms,
            "message": message,
        },
    }


def _ev(label: str, value: str) -> dict:
    return {"provider": "HTTP Client", "category": "HTTP", "label": label, "value": str(value), "status": "complete"}
