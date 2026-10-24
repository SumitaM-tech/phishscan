"""
Generates a downloadable report for a completed investigation in
PDF, JSON or HTML format and writes it to REPORTS_DIR, then records
it in the reports table so /api/reports can list it.
"""
import json
from pathlib import Path
from sqlalchemy.orm import Session

from app.config import settings
from app.database.repository import InvestigationRepository, ReportRepository
from app.services.serializers import serialize_investigation

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_VERDICT_COLORS = {
    "malicious": "#e2708a",
    "suspicious": "#dfa561",
    "clean": "#5cc99b",
    "unknown": "#9891ab",
}


def create_report(db: Session, investigation_id: str, fmt: str) -> dict:
    inv_repo = InvestigationRepository(db)
    report_repo = ReportRepository(db)

    inv = inv_repo.get(investigation_id)
    if inv is None:
        raise ValueError("Investigation not found")

    data = serialize_investigation(inv)
    title = f"PhishScan Report - {inv.normalized_target}"
    report = report_repo.create(investigation_id=investigation_id, title=title, fmt=fmt)

    file_path = settings.REPORTS_DIR / f"{report.id}.{fmt.lower()}"
    if fmt == "JSON":
        _write_json(file_path, data)
    elif fmt == "HTML":
        _write_html(file_path, data)
    else:  # PDF
        _write_pdf(file_path, data)

    size_kb = file_path.stat().st_size / 1024
    report_repo.mark_ready(report, str(file_path), f"{size_kb:.1f} KB")
    return report


def _write_json(path: Path, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _sorted_findings(data: dict) -> list[dict]:
    return sorted(data["findings"], key=lambda f: _SEVERITY_RANK.get(f["severity"], 0), reverse=True)


def _grouped_evidence(data: dict) -> dict:
    groups: dict[str, list[dict]] = {}
    for e in data["evidence"]:
        groups.setdefault(e["category"], []).append(e)
    return groups


# --- HTML -----------------------------------------------------------------

def _write_html(path: Path, data: dict):
    findings = _sorted_findings(data)
    findings_html = "".join(
        f'<li class="f-{f["severity"]}"><span class="sev">{f["severity"].upper()}</span>'
        f'<b>{f["title"]}</b><p>{f["summary"]}</p></li>'
        for f in findings
    )
    evidence_groups = _grouped_evidence(data)
    evidence_html = ""
    for category, rows in evidence_groups.items():
        evidence_html += f"<h3>{category}</h3><table><tr><th>Provider</th><th>Label</th><th>Value</th><th>Status</th></tr>"
        for e in rows:
            evidence_html += f"<tr><td>{e['provider']}</td><td>{e['label']}</td><td>{e['value']}</td><td>{e['status']}</td></tr>"
        evidence_html += "</table>"

    verdict = data["risk"]["verdict"]
    color = _VERDICT_COLORS.get(verdict, "#9891ab")

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{data['id']} report</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", Arial, sans-serif; margin: 0; padding: 2.5rem; color: #1a1625; background: #fff; line-height: 1.5; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 .25rem; }}
  h2 {{ font-size: 1.1rem; margin: 2rem 0 .75rem; border-bottom: 2px solid #eee; padding-bottom: .4rem; }}
  h3 {{ font-size: .9rem; margin: 1.25rem 0 .5rem; color: #555; }}
  .meta {{ color: #666; font-size: .85rem; margin-bottom: 1.5rem; }}
  .verdict-banner {{ background: {color}1a; border: 1px solid {color}55; border-radius: 10px; padding: 1.25rem 1.5rem; margin: 1rem 0 1.5rem; }}
  .verdict-banner .verdict {{ font-size: 1.3rem; font-weight: 700; color: {color}; text-transform: uppercase; letter-spacing: .03em; }}
  .verdict-banner .score {{ font-size: 2.2rem; font-weight: 700; float: right; }}
  .verdict-banner p {{ margin: .75rem 0 0; font-size: .9rem; color: #333; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: .5rem; font-size: .82rem; }}
  td, th {{ border: 1px solid #e2e2e2; padding: 7px 10px; text-align: left; }}
  th {{ background: #f6f5fa; font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; color: #555; }}
  ul.findings {{ list-style: none; padding: 0; }}
  ul.findings li {{ border: 1px solid #eee; border-left: 4px solid #ccc; border-radius: 6px; padding: .75rem 1rem; margin-bottom: .6rem; }}
  ul.findings li p {{ margin: .35rem 0 0; font-size: .85rem; color: #444; }}
  .sev {{ display: inline-block; font-size: .65rem; font-weight: 700; letter-spacing: .04em; padding: 2px 8px; border-radius: 4px; margin-right: .5rem; background: #eee; }}
  .f-critical {{ border-left-color: #cf3f60; }} .f-critical .sev {{ background: #cf3f6022; color: #cf3f60; }}
  .f-high {{ border-left-color: #d9764a; }} .f-high .sev {{ background: #d9764a22; color: #b8551f; }}
  .f-medium {{ border-left-color: #c99a2e; }} .f-medium .sev {{ background: #c99a2e22; color: #96721c; }}
  .f-low {{ border-left-color: #8a8299; }} .f-low .sev {{ background: #8a829922; color: #625b73; }}
  .f-info {{ border-left-color: #6d5ce0; }} .f-info .sev {{ background: #6d5ce022; color: #6d5ce0; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #eee; font-size: .72rem; color: #999; }}
</style></head>
<body>
<h1>PhishScan Investigation Report</h1>
<p class="meta">{data['id']} &nbsp;·&nbsp; Generated {data['createdAt']}</p>

<p class="meta"><b>Target:</b> {data['normalizedTarget']}<br/>
<b>Status:</b> {data['status']} &nbsp;·&nbsp; <b>Evidence coverage:</b> {round(data['coverage']*100)}%</p>

<div class="verdict-banner">
  <span class="score">{data['risk']['score']}<span style="font-size:1rem;color:#888">/100</span></span>
  <span class="verdict">{verdict}</span>
  <p>{data['risk']['rationale']}</p>
</div>

<h2>Findings ({len(findings)})</h2>
<ul class="findings">{findings_html}</ul>

<h2>Evidence by category</h2>
{evidence_html}

<h2>Provider diagnostics</h2>
<table><tr><th>Provider</th><th>Category</th><th>State</th><th>Latency</th><th>Message</th></tr>
{''.join(f"<tr><td>{p['provider']}</td><td>{p['category']}</td><td>{p['state']}</td><td>{p['latencyMs'] or '—'} ms</td><td>{p['message']}</td></tr>" for p in data['providers'])}
</table>

<footer>Generated by PhishScan. Findings reflect automated analysis of public DNS, RDAP, TLS, HTTP and Certificate Transparency records plus a trained ML model and threat-intelligence cross-check; verify independently before acting on this report.</footer>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)


# --- PDF --------------------------------------------------------------------

def _write_pdf(path: Path, data: dict):
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )

    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=20, leading=24, spaceAfter=2, textColor=colors.HexColor("#1a1625")),
        "meta": ParagraphStyle("meta", parent=base["Normal"], fontSize=9.5, leading=14, textColor=colors.HexColor("#666666")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=14, leading=18, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1a1625")),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=10.5, leading=14, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#555555")),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=10, leading=14.5, textColor=colors.HexColor("#222222")),
        "banner_verdict": ParagraphStyle("bv", parent=base["Normal"], fontSize=15, leading=18, fontName="Helvetica-Bold"),
        "banner_score": ParagraphStyle("bs", parent=base["Normal"], fontSize=26, leading=30, fontName="Helvetica-Bold", alignment=2),
        "banner_body": ParagraphStyle("bb", parent=base["Normal"], fontSize=10, leading=14.5, textColor=colors.HexColor("#333333"), spaceBefore=6),
        "finding_title": ParagraphStyle("ft", parent=base["Normal"], fontSize=11, leading=14, fontName="Helvetica-Bold"),
        "finding_body": ParagraphStyle("fb", parent=base["Normal"], fontSize=9.5, leading=13.5, textColor=colors.HexColor("#444444"), spaceBefore=3),
        "footer": ParagraphStyle("footer", parent=base["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#999999")),
        "cell": ParagraphStyle("cell", parent=base["Normal"], fontSize=8.5, leading=11.5, textColor=colors.HexColor("#222222")),
        "cell_head": ParagraphStyle("cellh", parent=base["Normal"], fontSize=7.5, leading=10, textColor=colors.white, fontName="Helvetica-Bold"),
    }

    verdict = data["risk"]["verdict"]
    verdict_hex = _VERDICT_COLORS.get(verdict, "#9891ab")
    verdict_color = colors.HexColor(verdict_hex)

    doc = SimpleDocTemplate(
        str(path), pagesize=LETTER,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )
    story = [
        Paragraph("PhishScan Investigation Report", styles["title"]),
        Paragraph(f"{data['id']} &nbsp;·&nbsp; Generated {data['createdAt']}", styles["meta"]),
        Spacer(1, 10),
        Paragraph(f"<b>Target:</b> {data['normalizedTarget']}", styles["body"]),
        Paragraph(f"<b>Status:</b> {data['status']} &nbsp;&nbsp; <b>Evidence coverage:</b> {round(data['coverage']*100)}%", styles["body"]),
        Spacer(1, 14),
    ]

    # Verdict banner: score + verdict + rationale, in a colored table cell
    banner_table = Table(
        [[
            Paragraph(f'<font color="{verdict_hex}">{verdict.upper()}</font>', styles["banner_verdict"]),
            Paragraph(f'<font color="{verdict_hex}">{data["risk"]["score"]}<font size=11 color="#888888">/100</font></font>', styles["banner_score"]),
        ], [
            Paragraph(data["risk"]["rationale"], styles["banner_body"]),
            "",
        ]],
        colWidths=[4.3 * inch, 1.95 * inch],
    )
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#faf9fc")),
        ("BOX", (0, 0), (-1, -1), 1, verdict_color),
        ("SPAN", (0, 1), (1, 1)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 12),
    ]))
    story.append(banner_table)

    # Findings, sorted by severity, with why-this-matters detail
    findings = _sorted_findings(data)
    story.append(Paragraph(f"Findings ({len(findings)})", styles["h2"]))
    severity_colors = {
        "critical": "#cf3f60", "high": "#b8551f", "medium": "#96721c",
        "low": "#625b73", "info": "#6d5ce0",
    }
    for f in findings:
        sev_color = severity_colors.get(f["severity"], "#666666")
        block = [
            Paragraph(
                f'<font color="{sev_color}" size=8><b>{f["severity"].upper()}</b></font> &nbsp; {f["title"]}',
                styles["finding_title"],
            ),
            Paragraph(f["summary"], styles["finding_body"]),
            Spacer(1, 8),
        ]
        story.append(KeepTogether(block))

    # Evidence, grouped by category (this is the "how it found it" detail)
    story.append(Paragraph("Evidence by category", styles["h2"]))
    story.append(Paragraph(
        "Every value below was observed directly from a public record (DNS, RDAP, TLS, "
        "HTTP response, or Certificate Transparency log) during this investigation — this "
        "is the raw evidence the findings and verdict above are derived from.",
        styles["body"],
    ))
    evidence_groups = _grouped_evidence(data)
    for category, rows in evidence_groups.items():
        story.append(Paragraph(category, styles["h3"]))
        table_data = [[
            Paragraph("Provider", styles["cell_head"]), Paragraph("Label", styles["cell_head"]),
            Paragraph("Value", styles["cell_head"]), Paragraph("Status", styles["cell_head"]),
        ]]
        for e in rows[:40]:
            table_data.append([
                Paragraph(e["provider"], styles["cell"]),
                Paragraph(e["label"], styles["cell"]),
                Paragraph(str(e["value"])[:90], styles["cell"]),
                Paragraph(e["status"], styles["cell"]),
            ])
        table = Table(table_data, colWidths=[1.1 * inch, 1.3 * inch, 2.9 * inch, 0.9 * inch], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1625")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e2e2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f6fa")]),
        ]))
        story.append(table)
        story.append(Spacer(1, 6))

    # Provider diagnostics
    story.append(Paragraph("Provider diagnostics", styles["h2"]))
    diag_data = [[
        Paragraph("Provider", styles["cell_head"]), Paragraph("Category", styles["cell_head"]),
        Paragraph("State", styles["cell_head"]), Paragraph("Latency", styles["cell_head"]),
        Paragraph("Message", styles["cell_head"]),
    ]]
    for p in data["providers"]:
        diag_data.append([
            Paragraph(p["provider"], styles["cell"]),
            Paragraph(p["category"], styles["cell"]),
            Paragraph(p["state"], styles["cell"]),
            Paragraph(f'{p["latencyMs"]} ms' if p["latencyMs"] else "—", styles["cell"]),
            Paragraph(str(p["message"])[:70], styles["cell"]),
        ])
    diag_table = Table(diag_data, colWidths=[1.1 * inch, 0.9 * inch, 0.9 * inch, 0.8 * inch, 2.5 * inch], repeatRows=1)
    diag_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1625")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e2e2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f6fa")]),
    ]))
    story.append(diag_table)

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated by PhishScan. Findings reflect automated analysis of public DNS, RDAP, "
        "TLS, HTTP and Certificate Transparency records plus a trained ML model and "
        "threat-intelligence cross-check; verify independently before acting on this report.",
        styles["footer"],
    ))

    doc.build(story)
