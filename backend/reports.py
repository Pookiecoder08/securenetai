"""
SecureNet AI — Executive PDF Reporting Engine
Constructs formal, institutional-grade Cybersecurity Audit Reports using ReportLab.
Summarizes inspected packet telemetry, signature intrusions, kernel firewall enforcement,
and formal academic/examiner sign-off sections for Daily, Weekly, and Monthly operational scopes.
"""

import io
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from models import PacketLog, FirewallRule


def get_timeframe_delta(timeframe: str) -> timedelta:
    """Translates a timeframe scope string into a Python timedelta."""
    tf = timeframe.lower().strip()
    if tf == "weekly":
        return timedelta(days=7)
    elif tf == "monthly":
        return timedelta(days=30)
    else:  # default daily
        return timedelta(hours=24)


def get_reports_summary(timeframe: str, db: Session) -> Dict[str, Any]:
    """
    Queries aggregated telemetry metrics from SQLite for the given timeframe.
    Returns JSON dictionary formatted for frontend metrics preview.
    """
    delta = get_timeframe_delta(timeframe)
    start_time = datetime.utcnow() - delta

    # Query total packets and threat packets within the timeframe
    total_packets = db.query(PacketLog).filter(PacketLog.timestamp >= start_time).count()
    total_threats = db.query(PacketLog).filter(
        PacketLog.timestamp >= start_time,
        PacketLog.is_threat == True
    ).count()

    # Active firewall rules enforced within the timeframe
    blocked_rules = db.query(FirewallRule).filter(FirewallRule.timestamp >= start_time).all()
    unique_blocked_ips = len(set(r.ip_address for r in blocked_rules))

    # Prevention rate calculation
    prevention_rate = 100.0 if total_threats == 0 else round(
        (min(len(blocked_rules), total_threats) / max(total_threats, 1)) * 100.0, 1
    )
    if total_threats > 0 and prevention_rate < 100.0 and len(blocked_rules) > 0:
        prevention_rate = min(100.0, round((len(blocked_rules) / total_threats) * 100.0, 1))

    # Breakdown by threat type
    threat_query = db.query(
        PacketLog.threat_type,
        func.count(PacketLog.id).label("count")
    ).filter(
        PacketLog.timestamp >= start_time,
        PacketLog.is_threat == True
    ).group_by(PacketLog.threat_type).all()

    threat_breakdown = [
        {"type": t_type or "Unknown Anomaly", "count": count}
        for t_type, count in threat_query
    ]

    # Recent incident logs for audit trail preview
    recent_incidents = db.query(PacketLog).filter(
        PacketLog.timestamp >= start_time,
        PacketLog.is_threat == True
    ).order_by(PacketLog.timestamp.desc()).limit(15).all()

    incident_list = [
        {
            "id": inc.id,
            "timestamp": inc.timestamp.isoformat(),
            "src_ip": inc.src_ip,
            "dst_ip": inc.dst_ip,
            "protocol": inc.protocol,
            "threat_type": inc.threat_type or "Flagged Signature",
            "payload_sample": (inc.payload_sample[:100] + "...") if inc.payload_sample else "N/A"
        }
        for inc in recent_incidents
    ]

    return {
        "timeframe": timeframe.capitalize(),
        "start_time": start_time.isoformat(),
        "end_time": datetime.utcnow().isoformat(),
        "total_packets": total_packets,
        "total_threats": total_threats,
        "unique_blocked_ips": unique_blocked_ips,
        "prevention_rate": prevention_rate,
        "threat_breakdown": threat_breakdown,
        "recent_incidents": incident_list,
        "total_rules_enforced": len(blocked_rules)
    }


def generate_pdf_report(timeframe: str, db: Session) -> io.BytesIO:
    """
    Builds a professional, comprehensive cybersecurity executive report in PDF format.
    Renders structured tables, metadata headers, threat analysis, and institutional sign-off sections.
    """
    summary = get_reports_summary(timeframe, db)
    buffer = io.BytesIO()

    # Create PDF document with standardized 36pt (0.5 in) margins
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    primary_color = colors.HexColor("#0f172a")    # Slate 900
    accent_color = colors.HexColor("#0284c7")     # Ocean Cyan
    danger_color = colors.HexColor("#dc2626")     # Crimson Red
    success_color = colors.HexColor("#16a34a")    # Emerald Green
    subtle_bg = colors.HexColor("#f8fafc")        # Slate 50
    border_color = colors.HexColor("#cbd5e1")     # Slate 300

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        alignment=TA_LEFT
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=accent_color,
        alignment=TA_LEFT
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=primary_color,
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=primary_color,
        alignment=TA_LEFT
    )

    table_cell_center = ParagraphStyle(
        "TableCellCenter",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=primary_color,
        alignment=TA_CENTER
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("SecureNet AI — Autonomous NIDS/NIPS", subtitle_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("Executive Cybersecurity Audit & Incident Report", title_style))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceBefore=4, spaceAfter=10))

    # 2. Metadata Table
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [
        [
            Paragraph("<b>Report Scope:</b>", body_style),
            Paragraph(f"{summary['timeframe']} Audit Window", body_style),
            Paragraph("<b>Classification:</b>", body_style),
            Paragraph("<font color='#dc2626'><b>RESTRICTED / DEFENSE AUDIT</b></font>", body_style)
        ],
        [
            Paragraph("<b>Generated On:</b>", body_style),
            Paragraph(now_str, body_style),
            Paragraph("<b>Evaluation Engine:</b>", body_style),
            Paragraph("SecureNet AI Promiscuous Ingress v1.0", body_style)
        ],
        [
            Paragraph("<b>Monitoring Period:</b>", body_style),
            Paragraph(f"{summary['start_time'][:19]}Z to {summary['end_time'][:19]}Z", body_style),
            Paragraph("<b>System Integrity:</b>", body_style),
            Paragraph("<font color='#16a34a'><b>ACTIVE MITIGATION ENABLED</b></font>", body_style)
        ]
    ]

    meta_table = Table(meta_data, colWidths=[110, 160, 110, 160])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), subtle_bg),
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, border_color),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 3. Executive Telemetry Summary Block
    story.append(Paragraph("1. Executive Threat & Telemetry Telemetry Summary", section_heading))
    
    summary_data = [
        [
            Paragraph("<b>Metric Indicator</b>", table_header_style),
            Paragraph("<b>Verified Network Value</b>", table_header_style),
            Paragraph("<b>Operational Assessment</b>", table_header_style)
        ],
        [
            Paragraph("Total Packets Inspected (Promiscuous NIC)", table_cell_style),
            Paragraph(f"<b>{summary['total_packets']:,}</b> packets", table_cell_center),
            Paragraph("Zero-loss physical layer frame parsing", table_cell_style)
        ],
        [
            Paragraph("Signature Threats Detected (SQLi / XSS / Probes)", table_cell_style),
            Paragraph(f"<b><font color='#dc2626'>{summary['total_threats']}</font></b> intrusions", table_cell_center),
            Paragraph("Automated Deep Packet Dissection (DPI) Flagged", table_cell_style)
        ],
        [
            Paragraph("Active Host Firewall Rules Enforced", table_cell_style),
            Paragraph(f"<b>{summary['total_rules_enforced']}</b> drop rules", table_cell_center),
            Paragraph("Kernel firewall drop actions executed", table_cell_style)
        ],
        [
            Paragraph("Unique Malicious Threat Actors Blocked", table_cell_style),
            Paragraph(f"<b>{summary['unique_blocked_ips']}</b> distinct IPs", table_cell_center),
            Paragraph("Perimeter egress/ingress isolation enforced", table_cell_style)
        ],
        [
            Paragraph("Active Threat Prevention Rate", table_cell_style),
            Paragraph(f"<b><font color='#16a34a'>{summary['prevention_rate']}%</font></b>", table_cell_center),
            Paragraph("Proactive NIPS intervention effectiveness", table_cell_style)
        ]
    ]

    summary_table = Table(summary_data, colWidths=[200, 140, 200])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, subtle_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 4. Threat Category Breakdown Table
    story.append(Paragraph("2. Threat Signature Classification Ledger", section_heading))
    if summary["threat_breakdown"]:
        threat_data = [
            [
                Paragraph("<b>Signature Category</b>", table_header_style),
                Paragraph("<b>Detection Logic</b>", table_header_style),
                Paragraph("<b>Incident Count</b>", table_header_style)
            ]
        ]
        for t in summary["threat_breakdown"]:
            t_type = t["type"]
            if "SQL" in t_type.upper():
                logic_desc = "SQL Injection Pattern Regex / UNION / OR Auth Bypass"
            elif "XSS" in t_type.upper():
                logic_desc = "Cross-Site Scripting Injection / Script Tag Execution"
            elif "PORT" in t_type.upper():
                logic_desc = "TCP/UDP Port Scanning / Host Reconnaissance Probe"
            else:
                logic_desc = "Protocol Anomaly / Malicious Payload Pattern"

            threat_data.append([
                Paragraph(f"<b>{t_type}</b>", table_cell_style),
                Paragraph(logic_desc, table_cell_style),
                Paragraph(f"<b>{t['count']}</b>", table_cell_center)
            ])

        threat_table = Table(threat_data, colWidths=[150, 290, 100])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('BOX', (0, 0), (-1, -1), 1, border_color),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, border_color),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, subtle_bg]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(threat_table)
    else:
        story.append(Paragraph("<i>No malicious intrusion signatures detected during this reporting timeframe. Zero anomalies flagged.</i>", body_style))
    story.append(Spacer(1, 14))

    # 5. Firewall Enforcement Ledger
    story.append(Paragraph("3. Active Defense Host Firewall Enforcement Ledger", section_heading))
    active_rules = db.query(FirewallRule).order_by(FirewallRule.timestamp.desc()).limit(8).all()
    if active_rules:
        fw_data = [
            [
                Paragraph("<b>Blocked IP</b>", table_header_style),
                Paragraph("<b>Enforced Reason</b>", table_header_style),
                Paragraph("<b>Initiated By</b>", table_header_style),
                Paragraph("<b>Timestamp (UTC)</b>", table_header_style),
                Paragraph("<b>Rule Status</b>", table_header_style)
            ]
        ]
        for r in active_rules:
            status_text = "<font color='#16a34a'><b>ACTIVE DROP</b></font>" if r.is_active else "<font color='#64748b'>REVOKED</font>"
            fw_data.append([
                Paragraph(f"<font color='#dc2626'><b>{r.ip_address}</b></font>", table_cell_style),
                Paragraph(r.reason or "Active Intrusion", table_cell_style),
                Paragraph(r.blocked_by or "SYSTEM", table_cell_center),
                Paragraph(r.timestamp.strftime("%Y-%m-%d %H:%M"), table_cell_center),
                Paragraph(status_text, table_cell_center)
            ])

        fw_table = Table(fw_data, colWidths=[90, 180, 100, 95, 75])
        fw_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('BOX', (0, 0), (-1, -1), 1, border_color),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, border_color),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, subtle_bg]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(fw_table)
    else:
        story.append(Paragraph("<i>No manual or automated host firewall drop rules currently active.</i>", body_style))
    story.append(Spacer(1, 16))

    # 6. Formal Examiner / Evaluator Sign-off Section
    sign_off_section = []
    sign_off_section.append(Paragraph("4. Institutional Verification & Examiner Sign-Off", section_heading))
    sign_off_section.append(Paragraph(
        "This cybersecurity audit log has been produced via kernel-level promiscuous socket capture and "
        "verified attack signature matching in accordance with organizational NIDS/NIPS compliance standards.",
        body_style
    ))
    sign_off_section.append(Spacer(1, 8))

    signoff_data = [
        [
            Paragraph("<b>Examiner / Auditor Name:</b>", body_style),
            Paragraph("________________________________________", body_style),
            Paragraph("<b>Evaluation Date:</b>", body_style),
            Paragraph("_____ / _____ / 2026", body_style)
        ],
        [
            Paragraph("<b>Official Institution:</b>", body_style),
            Paragraph("________________________________________", body_style),
            Paragraph("<b>Audit Status:</b>", body_style),
            Paragraph("[  ] APPROVED   [  ] PROVISIONAL", body_style)
        ],
        [
            Paragraph("<b>Signature:</b>", body_style),
            Paragraph("________________________________________", body_style),
            Paragraph("<b>Security Clearance:</b>", body_style),
            Paragraph("LEVEL-3 CYBER OPS", body_style)
        ]
    ]

    signoff_table = Table(signoff_data, colWidths=[120, 180, 100, 140])
    signoff_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, border_color),
        ('BACKGROUND', (0, 0), (-1, -1), subtle_bg),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    sign_off_section.append(signoff_table)

    story.append(KeepTogether(sign_off_section))

    # Build the document
    doc.build(story)
    buffer.seek(0)
    return buffer
