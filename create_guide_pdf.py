"""
Generate BlueShield Professional PDF Guide
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    Image, KeepTogether, HRFlowable
)
from reportlab.platypus.frames import Frame
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate
from reportlab.pdfgen import canvas as pdfcanvas
from pathlib import Path
import os

PROJ = Path(__file__).parent
LOGO = str(PROJ / "assets" / "logo.png")
OUTPUT = str(PROJ / "BlueShield_Guide.pdf")

# Colors
NAVY = HexColor("#0B0F19")
BLUE = HexColor("#1A6BB5")
CYAN = HexColor("#00D4FF")
DARK_BLUE = HexColor("#121A2E")
LIGHT_GRAY = HexColor("#F5F7FA")
MED_GRAY = HexColor("#6B7280")
DARK_TEXT = HexColor("#1F2937")
ACCENT = HexColor("#1A6BB5")


def build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='DocTitle', fontName='Helvetica-Bold', fontSize=28,
        textColor=BLUE, alignment=TA_CENTER, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name='DocSubtitle', fontName='Helvetica', fontSize=14,
        textColor=MED_GRAY, alignment=TA_CENTER, spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        name='SectionTitle', fontName='Helvetica-Bold', fontSize=18,
        textColor=BLUE, spaceBefore=24, spaceAfter=10,
        borderPadding=(0, 0, 4, 0),
    ))
    styles.add(ParagraphStyle(
        name='SubSection', fontName='Helvetica-Bold', fontSize=13,
        textColor=DARK_TEXT, spaceBefore=14, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name='Body', fontName='Helvetica', fontSize=10,
        textColor=DARK_TEXT, alignment=TA_JUSTIFY,
        spaceBefore=4, spaceAfter=6, leading=14,
    ))
    styles.add(ParagraphStyle(
        name='BodyBold', fontName='Helvetica-Bold', fontSize=10,
        textColor=DARK_TEXT, spaceBefore=4, spaceAfter=4, leading=14,
    ))
    styles.add(ParagraphStyle(
        name='CodeBlock', fontName='Courier', fontSize=9,
        textColor=DARK_TEXT, backColor=LIGHT_GRAY,
        spaceBefore=4, spaceAfter=8, leading=13,
        leftIndent=20, borderPadding=8,
    ))
    styles.add(ParagraphStyle(
        name='BulletItem', fontName='Helvetica', fontSize=10,
        textColor=DARK_TEXT, leftIndent=24, bulletIndent=12,
        spaceBefore=2, spaceAfter=2, leading=14,
        bulletFontName='Helvetica', bulletFontSize=10,
    ))
    styles.add(ParagraphStyle(
        name='Footer', fontName='Helvetica', fontSize=8,
        textColor=MED_GRAY, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name='Warning', fontName='Helvetica-Bold', fontSize=10,
        textColor=HexColor("#DC2626"), spaceBefore=8, spaceAfter=8,
        leftIndent=12, borderPadding=8,
    ))
    styles.add(ParagraphStyle(
        name='TableHeader', fontName='Helvetica-Bold', fontSize=9,
        textColor=white, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name='TableCell', fontName='Helvetica', fontSize=9,
        textColor=DARK_TEXT, alignment=TA_LEFT,
    ))
    return styles


class BlueShieldTemplate(BaseDocTemplate):
    def __init__(self, filename, **kwargs):
        BaseDocTemplate.__init__(self, filename, **kwargs)
        page_w, page_h = letter
        margin_left = 0.75 * inch
        margin_bottom = 0.85 * inch
        frame_w = page_w - 1.5 * inch   # 0.75" margins on each side
        frame_h = page_h - 1.6 * inch   # room for header + footer
        frame = Frame(
            margin_left, margin_bottom,
            frame_w, frame_h,
            id='main',
            leftPadding=0, rightPadding=0,
            topPadding=0, bottomPadding=0,
        )
        self.addPageTemplates([
            PageTemplate(id='main', frames=[frame], onPage=self._draw_page)
        ])

    def _draw_page(self, canvas, doc):
        canvas.saveState()
        # Header line
        canvas.setStrokeColor(BLUE)
        canvas.setLineWidth(1.5)
        canvas.line(0.75 * inch, letter[1] - 0.55 * inch,
                    letter[0] - 0.75 * inch, letter[1] - 0.55 * inch)

        # Header text
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(BLUE)
        canvas.drawString(0.75 * inch, letter[1] - 0.45 * inch, "BLUESHIELD")

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MED_GRAY)
        canvas.drawRightString(letter[0] - 0.75 * inch, letter[1] - 0.45 * inch,
                               "Bluetooth Security Monitoring Platform")

        # Footer
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MED_GRAY)
        canvas.drawCentredString(letter[0] / 2, 0.45 * inch,
                                 f"BlueShield Guide  |  Confidential  |  Page {doc.page}")

        # Footer line
        canvas.setStrokeColor(HexColor("#E5E7EB"))
        canvas.setLineWidth(0.5)
        canvas.line(0.75 * inch, 0.6 * inch, letter[0] - 0.75 * inch, 0.6 * inch)

        canvas.restoreState()


def hr():
    return HRFlowable(width="100%", thickness=1, color=HexColor("#E5E7EB"),
                       spaceBefore=8, spaceAfter=8)


def bullet(text, styles):
    return Paragraph(f"\u2022  {text}", styles['BulletItem'])


def code_block(text, styles):
    # Replace < and > for XML safety
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\n", "<br/>")
    return Paragraph(text, styles['CodeBlock'])


def make_table(headers, rows, col_widths=None):
    """Create a styled table."""
    data = [headers] + rows
    if col_widths is None:
        col_widths = [2.0 * inch] * len(headers)

    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('TEXTCOLOR', (0, 1), (-1, -1), DARK_TEXT),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, LIGHT_GRAY]),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#D1D5DB")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    return t


def build_pdf():
    styles = build_styles()

    doc = BlueShieldTemplate(
        OUTPUT,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        title="BlueShield Product Guide",
        author="BlueShield Team",
    )

    story = []

    # ── COVER PAGE ────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5 * inch))

    if os.path.exists(LOGO):
        story.append(Image(LOGO, width=2.0 * inch, height=2.0 * inch, hAlign='CENTER'))
        story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("BlueShield", styles['DocTitle']))
    story.append(Paragraph("Bluetooth Security Monitoring Platform", styles['DocSubtitle']))
    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="40%", thickness=2, color=BLUE, spaceBefore=0, spaceAfter=20, hAlign='CENTER'))
    story.append(Paragraph("Product & Technical Guide", ParagraphStyle(
        'CoverSub', fontName='Helvetica', fontSize=14, textColor=DARK_TEXT, alignment=TA_CENTER, spaceAfter=8)))
    story.append(Paragraph("Version 0.2.0  |  March 2026", ParagraphStyle(
        'CoverVer', fontName='Helvetica', fontSize=10, textColor=MED_GRAY, alignment=TA_CENTER, spaceAfter=30)))

    story.append(Spacer(1, 1.0 * inch))

    # Team info box
    team_data = [
        ["Team Members"],
        ["Mathias Vera  \u2022  Daniel Halbleib Jr  \u2022  Andrew Sauls"],
    ]
    team_table = Table(team_data, colWidths=[5.0 * inch])
    team_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_GRAY),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TEXTCOLOR', (0, 1), (-1, -1), DARK_TEXT),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('BOX', (0, 0), (-1, -1), 1, BLUE),
    ]))
    story.append(team_table)

    story.append(PageBreak())

    # ── TABLE OF CONTENTS ─────────────────────────────────────────────
    story.append(Paragraph("Table of Contents", styles['SectionTitle']))
    story.append(hr())

    toc_items = [
        ("1.", "Executive Summary"),
        ("2.", "The Problem"),
        ("3.", "Product Overview"),
        ("4.", "Technical Architecture"),
        ("5.", "Installation & Setup"),
        ("6.", "Web Dashboard Guide"),
        ("7.", "Jammer Module (Research)"),
        ("8.", "Raspberry Pi Deployment"),
        ("9.", "API Reference"),
        ("10.", "Revenue Model"),
        ("11.", "Roadmap & Future Work"),
    ]
    for num, title in toc_items:
        story.append(Paragraph(f"<b>{num}</b>  {title}", ParagraphStyle(
            'TOCItem', fontName='Helvetica', fontSize=11, textColor=DARK_TEXT,
            spaceBefore=6, spaceAfter=6, leftIndent=20)))

    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", styles['SectionTitle']))
    story.append(hr())
    story.append(Paragraph(
        "BlueShield is a research-grade Bluetooth security monitoring platform built on "
        "Raspberry Pi hardware. It provides real-time detection, analysis, and alerting "
        "for Bluetooth Low Energy (BLE) and Classic Bluetooth devices operating in a "
        "monitored environment.",
        styles['Body']))
    story.append(Paragraph(
        "The platform addresses a critical gap in enterprise security: most organizations "
        "have zero visibility into Bluetooth activity within their facilities. BlueShield "
        "fills this gap with an affordable, easy-to-deploy solution that combines passive "
        "BLE/Classic BT scanning with an intuitive web dashboard and comprehensive audit logging.",
        styles['Body']))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Key Capabilities", styles['SubSection']))
    for item in [
        "Real-time BLE and Classic Bluetooth device scanning with manufacturer identification",
        "Automatic device classification: phones, AirPods, watches, speakers, IoT, mice, keyboards",
        "Apple continuity protocol decoding (identifies AirPods, Apple Watch, iPhone, HomePod, etc.)",
        "GATT-based device name resolution for user-assigned names",
        "Web-based dashboard with live device tracking and RSSI visualization",
        "Automatic unknown device detection with configurable alert thresholds",
        "Research-grade BLE jamming with raw HCI sockets (4 modes: sweep, continuous, reactive, targeted)",
        "Comprehensive JSON audit logging for compliance and incident response",
        "Device whitelisting and trust management",
        "Cross-platform: Windows (BLE), Linux/Raspberry Pi (full BLE + Classic BT + jamming)",
    ]:
        story.append(bullet(item, styles))

    story.append(PageBreak())

    # ── 2. THE PROBLEM ────────────────────────────────────────────────
    story.append(Paragraph("2. The Problem", styles['SectionTitle']))
    story.append(hr())
    story.append(Paragraph(
        "Bluetooth devices are ubiquitous in modern workplaces: wireless headphones, keyboards, "
        "speakers, fitness trackers, and IoT sensors. Despite this proliferation, most organizations "
        "have absolutely no monitoring or visibility into what Bluetooth devices are operating "
        "within their facilities.",
        styles['Body']))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Threat Landscape", styles['SubSection']))

    threats = [
        ["Threat", "Description", "Impact"],
        ["Eavesdropping", "Attackers intercept audio from BT headsets/speakers in sensitive meetings", "Data breach, IP theft"],
        ["BlueBorne", "Remote code execution via unpatched BT stacks without user interaction", "System compromise"],
        ["Unauthorized Pairing", "Rogue devices pair with company hardware to exfiltrate data", "Data exfiltration"],
        ["BLE Tracking", "BLE advertisement packets used to track personnel movements", "Privacy violation"],
        ["MITM Attacks", "Man-in-the-middle attacks on BT connections to intercept/modify data", "Data integrity loss"],
    ]
    story.append(make_table(threats[0], threats[1:], [1.3*inch, 3.2*inch, 1.8*inch]))

    story.append(PageBreak())

    # ── 3. PRODUCT OVERVIEW ───────────────────────────────────────────
    story.append(Paragraph("3. Product Overview", styles['SectionTitle']))
    story.append(hr())

    story.append(Paragraph("How It Works", styles['SubSection']))
    story.append(Paragraph(
        "BlueShield operates in three phases: Detect, Analyze, and Respond.",
        styles['Body']))

    phases = [
        ["Phase", "Description", "Technology"],
        ["1. DETECT", "Passive BLE + Classic BT scanning using dedicated hardware", "Bleak, hcitool, hcidump"],
        ["2. ANALYZE", "Real-time pattern detection and unknown device identification", "Python, JSON logging"],
        ["3. RESPOND", "Admin alerts via web dashboard, optional reactive jamming", "Flask, Socket.IO, HCI"],
    ]
    story.append(make_table(phases[0], phases[1:], [1.2*inch, 3.0*inch, 2.0*inch]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Hardware Requirements", styles['SubSection']))
    hw = [
        ["Component", "Specification", "Cost"],
        ["Raspberry Pi 4/5", "2GB+ RAM, Debian/Ubuntu", "~$35-45"],
        ["Bluetooth Adapter", "Built-in or USB BT 5.0+", "$0-15"],
        ["MicroSD Card", "16GB+ Class 10", "~$8"],
        ["Power Supply", "USB-C 5V/3A", "~$10"],
        ["Optional: External BT Antenna", "Extended range up to 100m", "~$15"],
    ]
    story.append(make_table(hw[0], hw[1:], [1.8*inch, 2.5*inch, 1.0*inch]))

    story.append(PageBreak())

    # ── 4. TECHNICAL ARCHITECTURE ─────────────────────────────────────
    story.append(Paragraph("4. Technical Architecture", styles['SectionTitle']))
    story.append(hr())

    story.append(Paragraph(
        "BlueShield is built with a modular Python architecture. Each module operates "
        "independently and communicates through well-defined interfaces.",
        styles['Body']))
    story.append(Spacer(1, 8))

    story.append(code_block(
        "blueshield/\n"
        "  __init__.py          # Package metadata\n"
        "  __main__.py          # Entry point\n"
        "  config/\n"
        "    settings.py        # Configuration management\n"
        "    known_devices.json # Device whitelist\n"
        "  scanner/\n"
        "    bt_scanner.py      # BLE + Classic BT scanning\n"
        "  jammer/\n"
        "    bt_jammer.py       # BLE jamming (research only)\n"
        "  dashboard/\n"
        "    app.py             # Flask + Socket.IO web server\n"
        "    static/            # HTML, CSS, JS frontend\n"
        "  logs/\n"
        "    logger.py          # JSON event logging",
        styles))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Module Descriptions", styles['SubSection']))

    modules = [
        ["Module", "File", "Purpose"],
        ["Scanner", "scanner/bt_scanner.py", "BLE scanning via Bleak + Classic BT via hcitool. Device identification, Apple decoding, GATT name resolution, manufacturer + category classification."],
        ["Jammer", "jammer/bt_jammer.py", "BLE jamming via raw HCI sockets (fast) or hcitool fallback. Modes: sweep, continuous, reactive, targeted."],
        ["Dashboard", "dashboard/app.py", "Flask + Socket.IO web server. REST API + real-time WebSocket updates."],
        ["Logger", "logs/logger.py", "Structured JSON logging. Scan results, alerts, jammer sessions, audit trail."],
        ["Config", "config/settings.py", "Centralized configuration. Known device whitelist. Scan parameters."],
    ]
    story.append(make_table(modules[0], modules[1:], [1.0*inch, 1.8*inch, 3.5*inch]))

    story.append(PageBreak())

    # ── 5. INSTALLATION & SETUP ───────────────────────────────────────
    story.append(Paragraph("5. Installation & Setup", styles['SectionTitle']))
    story.append(hr())

    story.append(Paragraph("Windows (Development/Testing)", styles['SubSection']))
    story.append(code_block(
        "# Clone the repository\n"
        "git clone https://github.com/pineconegoat/BlueShield.git\n"
        "cd blueshield\n"
        "\n"
        "# Install dependencies\n"
        "pip install -r requirements.txt\n"
        "\n"
        "# Run with real BLE hardware\n"
        "python -m blueshield --port 8080\n"
        "\n"
        "# Run with simulated data (no hardware)\n"
        "python -m blueshield --sim --port 8080\n"
        "\n"
        "# Open dashboard\n"
        "# http://localhost:8080",
        styles))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Raspberry Pi (Production)", styles['SubSection']))
    story.append(code_block(
        "# Install system dependencies\n"
        "sudo apt update\n"
        "sudo apt install bluez python3-pip\n"
        "\n"
        "# Clone and install\n"
        "git clone https://github.com/pineconegoat/BlueShield.git\n"
        "cd blueshield\n"
        "pip3 install -r requirements.txt\n"
        "\n"
        "# Run with full hardware access\n"
        "sudo python3 -m blueshield --port 8080\n"
        "\n"
        "# Auto-start on boot (systemd)\n"
        "sudo cp blueshield.service /etc/systemd/system/\n"
        "sudo systemctl enable blueshield\n"
        "sudo systemctl start blueshield",
        styles))

    story.append(PageBreak())

    # ── 6. WEB DASHBOARD GUIDE ────────────────────────────────────────
    story.append(Paragraph("6. Web Dashboard Guide", styles['SectionTitle']))
    story.append(hr())
    story.append(Paragraph(
        "The web dashboard provides a real-time view of all Bluetooth activity in the "
        "monitored environment. It updates automatically via WebSocket connections.",
        styles['Body']))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Dashboard Sections", styles['SubSection']))
    sections = [
        ["Section", "Description"],
        ["Summary Cards", "Total devices, known/trusted, unknown, alerts, scan count"],
        ["Device Table", "Live table: address, name, category, manufacturer, type, RSSI, signal bar, alert, seen count, trust action"],
        ["Jammer Controls", "Mode selection (sweep/continuous/reactive/targeted), channel, target address, backend indicator"],
        ["RSSI Chart", "Signal strength bars with device category icons for top detected devices"],
        ["Alert Feed", "Scrolling log of security alerts with timestamps and severity"],
        ["Scan Controls", "Manual scan button, auto-scan toggle, interval slider"],
    ]
    story.append(make_table(sections[0], sections[1:], [1.5*inch, 4.8*inch]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Alert Levels", styles['SubSection']))
    alerts = [
        ["Level", "Trigger", "Action"],
        ["OK (Green)", "Device is in the known/trusted whitelist", "No action needed"],
        ["WARNING (Orange)", "Unknown device detected (below threshold)", "Review and whitelist or investigate"],
        ["CRITICAL (Red)", "Unknown devices exceed alert threshold (default: 3)", "Immediate investigation recommended"],
    ]
    story.append(make_table(alerts[0], alerts[1:], [1.5*inch, 2.5*inch, 2.3*inch]))

    story.append(PageBreak())

    # ── 7. JAMMER MODULE ──────────────────────────────────────────────
    story.append(Paragraph("7. Jammer Module (Research Only)", styles['SectionTitle']))
    story.append(hr())
    story.append(Paragraph(
        "WARNING: Bluetooth jamming is regulated by the FCC and equivalent agencies worldwide. "
        "The jammer module is intended ONLY for authorized penetration testing, academic research "
        "in controlled environments, and defensive security testing with proper authorization.",
        styles['Warning']))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Jamming Modes", styles['SubSection']))
    modes = [
        ["Mode", "Description", "Use Case"],
        ["Sweep", "Cycles across all BLE advertising channels (37, 38, 39)", "General disruption testing"],
        ["Continuous", "Jams a single BLE advertising channel continuously", "Targeted channel testing"],
        ["Reactive", "Alternates between scan and jam bursts when threats detected", "Automated defense research"],
        ["Targeted", "Focuses jamming on a specific device MAC address", "Isolating a rogue device"],
    ]
    story.append(make_table(modes[0], modes[1:], [1.3*inch, 3.0*inch, 2.0*inch]))
    story.append(Spacer(1, 8))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Jammer Backends", styles['SubSection']))
    story.append(Paragraph(
        "The jammer supports two backends. On Linux with root access, it first attempts a "
        "raw HCI socket connection for maximum speed (~1000+ packets/sec). If raw sockets are "
        "unavailable, it falls back to hcitool subprocess calls. On Windows, the jammer operates "
        "in simulated mode for dashboard testing only.",
        styles['Body']))

    backends = [
        ["Backend", "Speed", "Requirements"],
        ["Raw HCI Socket", "~1000+ pkt/sec", "Linux, root, AF_BLUETOOTH support"],
        ["hcitool (fallback)", "~100 pkt/sec", "Linux, BlueZ, hcitool installed"],
        ["Simulated", "N/A (counter only)", "Any OS (dashboard testing)"],
    ]
    story.append(make_table(backends[0], backends[1:], [1.5*inch, 1.5*inch, 3.3*inch]))

    story.append(PageBreak())

    # ── 8. RASPBERRY PI DEPLOYMENT ────────────────────────────────────
    story.append(Paragraph("8. Raspberry Pi Deployment", styles['SectionTitle']))
    story.append(hr())

    story.append(Paragraph("Systemd Service File", styles['SubSection']))
    story.append(code_block(
        "[Unit]\n"
        "Description=BlueShield Bluetooth Monitor\n"
        "After=network.target bluetooth.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=root\n"
        "WorkingDirectory=/opt/blueshield\n"
        "ExecStart=/usr/bin/python3 -m blueshield --port 8080\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target",
        styles))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Network Access", styles['SubSection']))
    story.append(Paragraph(
        "By default, the dashboard binds to 0.0.0.0:8080, making it accessible from any "
        "device on the same network. Access the dashboard from any browser at "
        "http://&lt;raspberry-pi-ip&gt;:8080.",
        styles['Body']))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Recommended Setup", styles['SubSection']))
    for item in [
        "Use a dedicated Raspberry Pi 4 or 5 with at least 2GB RAM",
        "Connect via Ethernet for reliable network access (Wi-Fi can interfere with BT)",
        "Use an external USB Bluetooth 5.0 adapter for extended range",
        "Place the device centrally in the monitored area",
        "Configure known_devices.json with authorized devices before deployment",
        "Set up log rotation to prevent disk space issues on long deployments",
    ]:
        story.append(bullet(item, styles))

    story.append(PageBreak())

    # ── 9. API REFERENCE ──────────────────────────────────────────────
    story.append(Paragraph("9. API Reference", styles['SectionTitle']))
    story.append(hr())
    story.append(Paragraph(
        "The dashboard exposes a REST API for programmatic access and a Socket.IO "
        "interface for real-time event streaming.",
        styles['Body']))
    story.append(Spacer(1, 8))

    story.append(Paragraph("REST Endpoints", styles['SubSection']))
    endpoints = [
        ["Method", "Endpoint", "Description"],
        ["GET", "/api/status", "Full dashboard state snapshot"],
        ["GET", "/api/devices", "All discovered devices"],
        ["GET", "/api/summary", "Device count summary"],
        ["POST", "/api/scan", "Trigger manual scan"],
        ["GET", "/api/jammer", "Jammer status"],
        ["POST", "/api/jammer/start", "Start jamming (body: {mode, channel})"],
        ["POST", "/api/jammer/stop", "Stop jamming"],
        ["POST", "/api/whitelist", "Add device to whitelist (body: {address})"],
        ["DELETE", "/api/whitelist", "Remove from whitelist (body: {address})"],
        ["POST", "/api/export", "Export and download JSON report"],
        ["POST", "/api/reset", "Clear all scanner state"],
    ]
    story.append(make_table(endpoints[0], endpoints[1:], [0.8*inch, 2.0*inch, 3.5*inch]))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Socket.IO Events (Server to Client)", styles['SubSection']))
    events = [
        ["Event", "Payload", "Description"],
        ["scan_result", "Scan result dict", "Emitted after each scan cycle"],
        ["device_update", "{summary, devices}", "Device list and summary update"],
        ["alert", "{timestamp, data}", "New security alert"],
        ["jammer_update", "Jammer status dict", "Jammer state change"],
    ]
    story.append(make_table(events[0], events[1:], [1.5*inch, 1.8*inch, 3.0*inch]))

    story.append(PageBreak())

    # ── 10. REVENUE MODEL ─────────────────────────────────────────────
    story.append(Paragraph("10. Revenue Model", styles['SectionTitle']))
    story.append(hr())

    tiers = [
        ["Tier", "Price", "Includes"],
        ["Research License", "$0", "Open-source. Full scanner + dashboard. Community support."],
        ["Professional", "$299/unit", "Pre-configured RPi hardware + software. 1 year support + updates."],
        ["Enterprise", "$999/year", "Multi-device deployment. Central management. Custom integrations."],
        ["Managed Service", "Custom", "Fully managed 24/7 monitoring. SOC integration. Compliance reporting."],
    ]
    story.append(make_table(tiers[0], tiers[1:], [1.3*inch, 1.0*inch, 4.0*inch]))

    story.append(PageBreak())

    # ── 11. ROADMAP ───────────────────────────────────────────────────
    story.append(Paragraph("11. Roadmap & Future Work", styles['SectionTitle']))
    story.append(hr())

    story.append(Paragraph("Phase 1: Research MVP (Current)", styles['SubSection']))
    for item in [
        "BLE + Classic BT passive scanning",
        "Web dashboard with real-time updates",
        "JSON audit logging and report export",
        "Device whitelisting and alert thresholds",
        "Research-grade BLE jamming",
    ]:
        story.append(bullet(item, styles))

    story.append(Paragraph("Phase 2: Enhanced Detection", styles['SubSection']))
    for item in [
        "Bluetooth 5.x extended advertisement parsing",
        "Device fingerprinting and classification",
        "Anomaly detection using ML-based pattern analysis",
        "Multi-sensor mesh network support",
    ]:
        story.append(bullet(item, styles))

    story.append(Paragraph("Phase 3: Enterprise Platform", styles['SubSection']))
    for item in [
        "Centralized multi-site management console",
        "SIEM integration (Splunk, Elastic, Sentinel)",
        "Mobile app for alerts and device management",
        "Compliance reporting templates (HIPAA, PCI-DSS, NIST)",
        "Cloud-hosted dashboard option",
    ]:
        story.append(bullet(item, styles))

    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="40%", thickness=2, color=BLUE, hAlign='CENTER'))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "BlueShield  \u2022  Mathias Vera  \u2022  Daniel Halbleib Jr  \u2022  Andrew Sauls",
        ParagraphStyle('EndNote', fontName='Helvetica', fontSize=10, textColor=MED_GRAY, alignment=TA_CENTER)))
    story.append(Paragraph(
        "For questions or partnership inquiries, contact the BlueShield team.",
        ParagraphStyle('EndNote2', fontName='Helvetica', fontSize=9, textColor=MED_GRAY, alignment=TA_CENTER, spaceBefore=4)))

    # Build
    doc.build(story)
    print(f"PDF Guide saved: {OUTPUT}")


if __name__ == "__main__":
    build_pdf()
