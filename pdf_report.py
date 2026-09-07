"""Printable PDF incident reports for Packetlens analysis results."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    Preformatted,
    KeepTogether,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#5E6B7F")
NAVY = colors.HexColor("#12233F")
BLUE = colors.HexColor("#2563EB")
PALE = colors.HexColor("#EEF4FF")
LINE = colors.HexColor("#D7DEEA")
SEVERITY = {
    "critical": colors.HexColor("#B42318"),
    "high": colors.HexColor("#D04A02"),
    "medium": colors.HexColor("#B7791F"),
    "low": colors.HexColor("#34785C"),
}


def _text(value) -> str:
    """Make arbitrary report values safe for ReportLab paragraphs."""
    value = str(value if value is not None else "-")
    return escape(value.replace("\u2014", "-").replace("\u2013", "-"))


def _human_bytes(value: int) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} GB"


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=25, leading=29, textColor=NAVY, alignment=TA_LEFT,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Subtitle", parent=styles["Normal"], fontSize=10, leading=15,
        textColor=MUTED, spaceAfter=15,
    ))
    styles.add(ParagraphStyle(
        name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=15, leading=19, textColor=NAVY, spaceBefore=14, spaceAfter=8,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="Finding", parent=styles["Heading3"], fontName="Helvetica-Bold",
        fontSize=12, leading=15, textColor=INK, spaceBefore=11, spaceAfter=5,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="Body", parent=styles["BodyText"], fontSize=8.7, leading=12,
        textColor=INK, spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="Small", parent=styles["BodyText"], fontSize=7.5, leading=10,
        textColor=MUTED,
    ))
    styles.add(ParagraphStyle(
        name="Label", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=7.4, leading=9, textColor=MUTED, spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="TableHead", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=7.5, leading=9, textColor=colors.white,
    ))
    styles.add(ParagraphStyle(
        name="TableCell", parent=styles["BodyText"], fontSize=7.2, leading=9,
        textColor=INK,
    ))
    styles.add(ParagraphStyle(
        name="ReportCode", fontName="Courier", fontSize=6.2, leading=8,
        textColor=colors.HexColor("#E7EEF9"), leftIndent=0,
    ))
    return styles


def _page(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 15 * mm, width - 18 * mm, 15 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "PACKETLENS - DEFENSIVE DDoS FORENSICS")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _table(rows, widths, styles, repeat_rows=1):
    rendered = []
    for row_index, row in enumerate(rows):
        style = styles["TableHead"] if row_index == 0 else styles["TableCell"]
        rendered.append([Paragraph(_text(cell), style) for cell in row])
    table = Table(rendered, colWidths=widths, repeatRows=repeat_rows,
                  hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _code_block(value, styles):
    code = (value or "No command generated.").replace("\t", "    ")
    block = Preformatted(code, styles["ReportCode"], maxLineLength=100)
    table = Table([[block]], colWidths=[169 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#172033")),
        ("BOX", (0, 0), (-1, -1), 0.5, NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _numbered(items, styles):
    return [Paragraph(f"<b>{index}.</b> {_text(item)}", styles["Body"])
            for index, item in enumerate(items or [], 1)]


def build_pdf_report(report: dict) -> bytes:
    """Return a polished PDF for a JSON report produced by build_report()."""
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
        raise ValueError("A valid Packetlens analysis report is required.")

    styles = _styles()
    output = BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=21 * mm,
        title="Packetlens DDoS Capture Incident Report",
        author="Packetlens",
    )
    story = []
    file_info = report.get("file", {})
    summary = report["summary"]
    verdict = report.get("verdict", {})
    severity = str(verdict.get("severity") or "No findings")

    story.append(Paragraph("DDoS capture incident report", styles["ReportTitle"]))
    story.append(Paragraph(
        "Evidence-led analysis, response guidance, and vendor-specific "
        "FlowSpec change controls. Generated locally; the capture is not embedded.",
        styles["Subtitle"],
    ))
    banner = Table([[
        Paragraph("HIGHEST SEVERITY", styles["Label"]),
        Paragraph("FINDINGS", styles["Label"]),
        Paragraph("CAPTURE", styles["Label"]),
    ], [
        Paragraph(f"<b>{_text(severity.upper())}</b>", styles["Body"]),
        Paragraph(f"<b>{int(verdict.get('count', 0))}</b>", styles["Body"]),
        Paragraph(f"<b>{_text(file_info.get('name', 'capture'))}</b>", styles["Body"]),
    ]], colWidths=[45 * mm, 34 * mm, 90 * mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#B8CCF3")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([banner, Spacer(1, 8 * mm), Paragraph("Capture summary", styles["Section"])])
    story.append(_table([
        ["Packets", "Traffic", "Duration", "Average", "Peak"],
        [f"{int(summary.get('packets', 0)):,}", _human_bytes(summary.get("bytes", 0)),
         f"{summary.get('duration_s', 0)} s", f"{summary.get('avg_pps', 0):,} pps",
         f"{summary.get('peak_pps', 0):,} pps"],
    ], [31 * mm, 31 * mm, 31 * mm, 38 * mm, 38 * mm], styles))
    story.append(Paragraph(
        f"Average throughput: <b>{_text(summary.get('avg_mbps', 0))} Mbps</b> | "
        f"Analysis window: <b>{_text(summary.get('window_s', 0))} seconds</b> | "
        f"File size: <b>{_text(_human_bytes(file_info.get('size_bytes', 0)))}</b> | "
        f"Generated: <b>{_text(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}</b>",
        styles["Small"],
    ))

    findings = report.get("findings") or []
    story.append(Paragraph("Findings and response", styles["Section"]))
    if not findings:
        story.append(Paragraph(
            "No attack indicators crossed the configured rate or signature gates. "
            "This does not prove the capture is benign; correlate with interface, "
            "NetFlow, firewall, and service telemetry.", styles["Body"]))

    for index, finding in enumerate(findings, 1):
        sev = str(finding.get("severity", "unknown")).lower()
        story.append(Paragraph(
            f"{index}. {_text(finding.get('attack', 'Finding'))}", styles["Finding"]))
        meta = _table([
            ["Severity", "Victim", "Confidence", "Detection", "Peak", "Sources"],
            [sev.upper(), finding.get("victim"), finding.get("confidence"),
             finding.get("method"), f"{finding.get('peak_pps', 0):,} pps",
             f"{finding.get('unique_sources', 0):,}"],
        ], [24 * mm, 35 * mm, 27 * mm, 31 * mm, 29 * mm, 23 * mm], styles)
        meta.setStyle(TableStyle([("TEXTCOLOR", (0, 1), (0, 1), SEVERITY.get(sev, INK))]))
        story.append(meta)
        story.append(Paragraph(f"<b>Evidence:</b> {_text(finding.get('evidence'))}", styles["Body"]))
        story.append(Paragraph(f"<b>Mitigation:</b> {_text(finding.get('mitigation'))}", styles["Body"]))
        story.extend(_numbered(finding.get("mitigation_techniques"), styles))

        flowspec = finding.get("flowspec") or {}
        story.append(Paragraph("FlowSpec change plan", styles["Finding"]))
        if not flowspec.get("supported"):
            story.append(Paragraph(_text(flowspec.get("note", "No rule generated.")), styles["Body"]))
            continue
        risk = flowspec.get("risk") or {}
        monitoring = flowspec.get("monitoring") or {}
        story.append(Paragraph(
            f"<b>Collateral risk: {_text(str(risk.get('level', 'unknown')).upper())}.</b> "
            f"{_text(risk.get('reason'))}", styles["Body"]))
        story.append(Paragraph(
            f"Suggested expiry: <b>{_text(monitoring.get('suggested_expiry_minutes'))} minutes</b>; "
            f"check counters every <b>{_text(monitoring.get('check_every_seconds'))} seconds</b>.",
            styles["Body"]))
        story.extend(_numbered(flowspec.get("response_checklist"), styles))
        for vendor in (flowspec.get("vendors") or {}).values():
            intro = [
                Paragraph(_text(vendor.get("label", "Vendor syntax")), styles["Finding"]),
                Paragraph(_text(vendor.get("note", "")), styles["Body"]),
            ]
            if not vendor.get("supported"):
                story.extend(intro)
                continue
            # Keep the vendor identity attached to its configuration. Without
            # this, a page break can leave an unlabeled command block.
            intro.append(_code_block(vendor.get("config"), styles))
            story.append(KeepTogether(intro))
            story.append(KeepTogether([
                Paragraph("Verification", styles["Label"]),
                _code_block("\n".join(vendor.get("verify") or []), styles),
            ]))
            rollback = [Paragraph("Rollback / withdrawal", styles["Label"])]
            if vendor.get("withdraw_note"):
                rollback.append(Paragraph(_text(vendor.get("withdraw_note")), styles["Small"]))
            rollback.append(_code_block(vendor.get("withdraw"), styles))
            story.append(KeepTogether(rollback))

    story.append(PageBreak())
    story.append(Paragraph("Traffic inventory - leading values", styles["Section"]))
    story.append(Paragraph(
        "The PDF shows the leading 20 values in each inventory for operational "
        "readability. The dashboard and JSON export retain every observed value.",
        styles["Body"]))
    inventory_specs = (
        ("Sources", "sources", ["Source", "Packets", "pps", "Share"],
         lambda x: [x.get("ip"), f"{x.get('packets', 0):,}", x.get("pps"), f"{x.get('share', 0)}%"]),
        ("Destinations", "destinations", ["Destination", "Packets", "pps", "Share"],
         lambda x: [x.get("ip"), f"{x.get('packets', 0):,}", x.get("pps"), f"{x.get('share', 0)}%"]),
        ("Protocols", "protocols", ["Protocol", "Packets", "pps", "Share"],
         lambda x: [x.get("protocol"), f"{x.get('packets', 0):,}", x.get("pps"), f"{x.get('share', 0)}%"]),
        ("UDP destination ports", "udp_ports", ["Port", "Packets", "Share", "Known service"],
         lambda x: [x.get("port"), f"{x.get('packets', 0):,}", f"{x.get('share', 0)}%", x.get("reflector") or "-"]),
    )
    for title, key, headers, convert in inventory_specs:
        story.append(Paragraph(title, styles["Finding"]))
        values = report.get(key) or []
        rows = [headers] + [convert(item) for item in values[:20]]
        if len(rows) == 1:
            story.append(Paragraph("No values observed.", styles["Small"]))
        else:
            story.append(_table(rows, [55 * mm, 38 * mm, 34 * mm, 42 * mm], styles))

    story.extend([
        Spacer(1, 8 * mm),
        Paragraph("Operational notice", styles["Section"]),
        Paragraph(
            "This is defensive decision support, not an automated change request. "
            "Validate scope and syntax in a lab or commit-check workflow, obtain peer "
            "review, monitor counters and legitimate traffic, and retain the withdrawal "
            "commands before deployment. Packet evidence alone cannot establish intent.",
            styles["Body"],
        ),
    ])
    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return output.getvalue()
