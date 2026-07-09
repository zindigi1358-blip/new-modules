"""
Module 4 — Professional PDF Report Generator
==============================================
Consumes JSON outputs from Module 1, 2.5, and 3 to produce a professional
penetration testing report — the kind pentest firms charge $5,000–$15,000 for.

Generates:
  • Executive Summary   — non-technical language, risk overview, key metrics
  • Technical Findings  — evidence, CVEs, exposure context, code snippets
  • Remediation Steps   — prioritized, actionable, copy-paste commands
  • Risk Trend Graph    — score over time (when multiple Module 3 reports exist)
  • Appendix            — full asset inventory, raw CVE table

Usage:
    python3 report_generator.py --module1 reports/example.com_latest.json \\
                                 --module3 module3_reports/example.com_risk_report.json \\
                                 --leaks  module2_5_reports/example.com_leaks.json \\
                                 --client "Acme Corp" --assessor "Your Firm Name" \\
                                 --confirm
"""

import argparse
import json
import os
import sys
import time
import textwrap
import io
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image, KeepTogether
)
from reportlab.platypus import ListFlowable, ListItem
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.pdfgen import canvas as rl_canvas

# ── Brand / theme colours ──────────────────────────────────────────────────

C_DARK      = colors.HexColor("#0D1117")   # near-black (header bg)
C_ACCENT    = colors.HexColor("#E84C3D")   # red accent
C_BLUE      = colors.HexColor("#1A6EBD")   # info blue
C_GRAY_DARK = colors.HexColor("#2D3748")   # dark gray
C_GRAY_MID  = colors.HexColor("#718096")   # medium gray
C_GRAY_LITE = colors.HexColor("#EDF2F7")   # light gray bg
C_WHITE     = colors.white
C_CRITICAL  = colors.HexColor("#C0392B")
C_HIGH      = colors.HexColor("#E67E22")
C_MEDIUM    = colors.HexColor("#F1C40F")
C_LOW       = colors.HexColor("#27AE60")
C_INFO      = colors.HexColor("#95A5A6")

LEVEL_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "INFO":     C_INFO,
}

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


# ══════════════════════════════════════════════════════════════════════════════
#  STYLE SHEET
# ══════════════════════════════════════════════════════════════════════════════

def build_styles():
    base = getSampleStyleSheet()
    s = {}

    s["cover_title"] = ParagraphStyle(
        "cover_title", parent=base["Normal"],
        fontSize=32, leading=38, textColor=C_WHITE,
        fontName="Helvetica-Bold", alignment=TA_LEFT,
    )
    s["cover_sub"] = ParagraphStyle(
        "cover_sub", parent=base["Normal"],
        fontSize=13, leading=18, textColor=colors.HexColor("#A0AEC0"),
        fontName="Helvetica", alignment=TA_LEFT,
    )
    s["cover_meta"] = ParagraphStyle(
        "cover_meta", parent=base["Normal"],
        fontSize=10, leading=14, textColor=colors.HexColor("#CBD5E0"),
        fontName="Helvetica",
    )
    s["section_h1"] = ParagraphStyle(
        "section_h1", parent=base["Normal"],
        fontSize=18, leading=24, textColor=C_DARK,
        fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6,
    )
    s["section_h2"] = ParagraphStyle(
        "section_h2", parent=base["Normal"],
        fontSize=13, leading=18, textColor=C_DARK,
        fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4,
    )
    s["section_h3"] = ParagraphStyle(
        "section_h3", parent=base["Normal"],
        fontSize=11, leading=15, textColor=C_GRAY_DARK,
        fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=2,
    )
    s["body"] = ParagraphStyle(
        "body", parent=base["Normal"],
        fontSize=9.5, leading=14, textColor=C_GRAY_DARK,
        fontName="Helvetica", alignment=TA_JUSTIFY, spaceAfter=4,
    )
    s["body_small"] = ParagraphStyle(
        "body_small", parent=base["Normal"],
        fontSize=8.5, leading=12, textColor=C_GRAY_MID,
        fontName="Helvetica",
    )
    s["mono"] = ParagraphStyle(
        "mono", parent=base["Normal"],
        fontSize=8, leading=11, textColor=colors.HexColor("#24292E"),
        fontName="Courier", backColor=colors.HexColor("#F6F8FA"),
        leftIndent=8, rightIndent=8, spaceBefore=4, spaceAfter=4,
    )
    s["bullet"] = ParagraphStyle(
        "bullet", parent=base["Normal"],
        fontSize=9.5, leading=13, textColor=C_GRAY_DARK,
        fontName="Helvetica", leftIndent=16, spaceAfter=2,
        bulletIndent=6, bulletText="•",
    )
    s["finding_title"] = ParagraphStyle(
        "finding_title", parent=base["Normal"],
        fontSize=11, leading=15, textColor=C_WHITE,
        fontName="Helvetica-Bold",
    )
    s["label"] = ParagraphStyle(
        "label", parent=base["Normal"],
        fontSize=8, leading=10, textColor=C_GRAY_MID,
        fontName="Helvetica-Bold", spaceAfter=1,
    )
    s["toc_entry"] = ParagraphStyle(
        "toc_entry", parent=base["Normal"],
        fontSize=10, leading=16, textColor=C_GRAY_DARK,
        fontName="Helvetica",
    )
    s["footer_text"] = ParagraphStyle(
        "footer_text", parent=base["Normal"],
        fontSize=7.5, leading=10, textColor=C_GRAY_MID,
        fontName="Helvetica",
    )

    return s


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE TEMPLATE (header / footer on each page)
# ══════════════════════════════════════════════════════════════════════════════

class ReportCanvas(rl_canvas.Canvas):
    """Custom canvas that draws the header/footer on every page."""

    def __init__(self, *args, client_name="", domain="", total_pages=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_name  = client_name
        self.domain       = domain
        self._total_pages = total_pages
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_chrome(self._pageNumber, num_pages)
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)

    def _draw_chrome(self, page_num, total):
        self.saveState()

        # --- header strip (skip cover page = page 1)
        if page_num > 1:
            self.setFillColor(C_DARK)
            self.rect(0, PAGE_H - 1.1 * cm, PAGE_W, 1.1 * cm, fill=1, stroke=0)
            self.setFillColor(C_WHITE)
            self.setFont("Helvetica-Bold", 8)
            self.drawString(MARGIN, PAGE_H - 0.72 * cm, "CONFIDENTIAL SECURITY ASSESSMENT REPORT")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#A0AEC0"))
            self.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.72 * cm,
                                 f"{self.client_name}  |  {self.domain}")

        # --- footer line
        if page_num > 1:
            self.setStrokeColor(C_GRAY_LITE)
            self.setLineWidth(0.5)
            self.line(MARGIN, 1.2 * cm, PAGE_W - MARGIN, 1.2 * cm)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(C_GRAY_MID)
            self.drawString(MARGIN, 0.75 * cm,
                            f"Security Assessment  —  {self.domain}  —  {datetime.now(timezone.utc).strftime('%B %Y')}")
            self.drawRightString(PAGE_W - MARGIN, 0.75 * cm, f"Page {page_num} of {total}")

        self.restoreState()


def make_canvas_factory(client_name, domain):
    def factory(*args, **kwargs):
        return ReportCanvas(*args, client_name=client_name, domain=domain, **kwargs)
    return factory


# ══════════════════════════════════════════════════════════════════════════════
#  CHART HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _fig_to_image(fig, width_cm=14, height_cm=7):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor="white", edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=width_cm * cm, height=height_cm * cm)


def make_severity_donut(counts: dict):
    labels  = [k for k, v in counts.items() if v > 0]
    values  = [v for v in counts.values() if v > 0]
    palette = {
        "CRITICAL": "#C0392B", "HIGH": "#E67E22",
        "MEDIUM":   "#F1C40F", "LOW": "#27AE60", "INFO": "#95A5A6"
    }
    clrs = [palette.get(l, "#999") for l in labels]

    fig, ax = plt.subplots(figsize=(4, 4))
    wedges, _ = ax.pie(values, colors=clrs, startangle=90,
                        wedgeprops=dict(width=0.55, edgecolor="white", linewidth=2))
    total = sum(values)
    ax.text(0, 0, str(total), ha="center", va="center",
            fontsize=22, fontweight="bold", color="#2D3748")
    ax.text(0, -0.22, "Findings", ha="center", va="center",
            fontsize=9, color="#718096")
    legend_patches = [mpatches.Patch(color=palette[l], label=f"{l} ({counts.get(l, 0)})")
                      for l in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if counts.get(l, 0) > 0]
    ax.legend(handles=legend_patches, loc="lower center",
              bbox_to_anchor=(0.5, -0.22), ncol=3, fontsize=8,
              frameon=False)
    ax.set_aspect("equal")
    fig.patch.set_facecolor("white")
    return _fig_to_image(fig, width_cm=9, height_cm=8)


def make_risk_bar_chart(findings: list, top_n: int = 12):
    sorted_f = sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)[:top_n]
    labels   = [f"{f.get('subdomain','?')[:22]}\n{f.get('technology','?')[:16]}"
                for f in sorted_f]
    scores   = [f.get("risk_score", 0) for f in sorted_f]
    levels   = [f.get("risk_level", "INFO") for f in sorted_f]
    palette  = {"CRITICAL": "#C0392B", "HIGH": "#E67E22",
                "MEDIUM": "#F1C40F", "LOW": "#27AE60", "INFO": "#95A5A6"}
    bar_clrs = [palette.get(l, "#999") for l in levels]

    fig, ax = plt.subplots(figsize=(10, max(3.5, len(labels) * 0.55)))
    bars = ax.barh(range(len(labels)), scores, color=bar_clrs, edgecolor="none", height=0.6)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=7.5)
    ax.set_xlim(0, 105)
    ax.set_xlabel("Composite Risk Score (0–100)", fontsize=8, color="#718096")
    ax.set_title("Top Findings by Risk Score", fontsize=10, fontweight="bold", color="#2D3748", pad=8)
    ax.invert_yaxis()
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="x", colors="#718096", labelsize=8)
    ax.tick_params(axis="y", length=0)
    ax.xaxis.grid(True, color="#EDF2F7", linewidth=0.8, zorder=0)
    for bar, score in zip(bars, scores):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                f"{score:.0f}", va="center", fontsize=7.5, color="#2D3748")
    fig.patch.set_facecolor("white")
    fig.tight_layout()
    return _fig_to_image(fig, width_cm=15, height_cm=max(5, len(labels) * 0.65))


def make_tech_distribution(findings: list):
    tech_counts = defaultdict(int)
    for f in findings:
        t = f.get("technology", "Unknown")
        if t and t != "N/A":
            tech_counts[t.split()[0]] += 1
    if not tech_counts:
        return None
    top = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    labels, vals = zip(*top)

    fig, ax = plt.subplots(figsize=(8, 3.5))
    bar_clrs = plt.cm.RdYlGn_r([i / len(labels) for i in range(len(labels))])
    ax.bar(labels, vals, color=bar_clrs, edgecolor="none", width=0.6)
    ax.set_ylabel("Findings Count", fontsize=8, color="#718096")
    ax.set_title("Vulnerable Technologies Distribution", fontsize=10,
                  fontweight="bold", color="#2D3748", pad=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(axis="x", colors="#2D3748", labelsize=8, rotation=25)
    ax.tick_params(axis="y", colors="#718096", labelsize=8)
    ax.yaxis.grid(True, color="#EDF2F7", linewidth=0.8, zorder=0)
    fig.patch.set_facecolor("white")
    fig.tight_layout()
    return _fig_to_image(fig, width_cm=13, height_cm=5.5)


# ══════════════════════════════════════════════════════════════════════════════
#  CONTENT HELPERS (flowable builders)
# ══════════════════════════════════════════════════════════════════════════════

def section_divider(styles, title: str):
    return [
        Spacer(1, 0.5 * cm),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=4),
        Paragraph(title, styles["section_h1"]),
    ]


def severity_badge_table(level: str):
    """Coloured inline badge cell for a severity level."""
    clr = LEVEL_COLORS.get(level, C_INFO)
    tbl = Table([[Paragraph(f"<b> {level} </b>",
                            ParagraphStyle("badge", fontSize=8, textColor=C_WHITE,
                                           fontName="Helvetica-Bold", leading=10))]],
                colWidths=[1.8 * cm], rowHeights=[0.45 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), clr),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("BOX", (0, 0), (-1, -1), 0, C_WHITE),
    ]))
    return tbl


def kv_table(rows: list, col_ratio=(0.30, 0.70)):
    """Two-column label / value table used throughout the report."""
    w1 = (PAGE_W - 2 * MARGIN) * col_ratio[0]
    w2 = (PAGE_W - 2 * MARGIN) * col_ratio[1]
    styles = build_styles()
    data = [[Paragraph(f"<b>{k}</b>", styles["body_small"]),
             Paragraph(str(v), styles["body"])]
            for k, v in rows]
    tbl = Table(data, colWidths=[w1, w2])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_GRAY_LITE),
    ]))
    return tbl


def metric_cards(metrics: list):
    """
    4-up card row.  metrics = [(label, value, sub_label, color), ...]
    """
    card_style = ParagraphStyle("cs", fontSize=8, fontName="Helvetica",
                                textColor=C_GRAY_MID, leading=10)
    val_style  = ParagraphStyle("vs", fontSize=22, fontName="Helvetica-Bold",
                                textColor=C_DARK, leading=26, alignment=TA_CENTER)
    lbl_style  = ParagraphStyle("ls", fontSize=8, fontName="Helvetica-Bold",
                                textColor=C_GRAY_MID, leading=10, alignment=TA_CENTER)

    cells = []
    for label, value, sub, color in metrics:
        inner = Table(
            [[Paragraph(str(value), val_style)],
             [Paragraph(label, lbl_style)]],
            colWidths=[(PAGE_W - 2 * MARGIN) / len(metrics) - 0.4 * cm],
        )
        inner.setStyle(TableStyle([
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        cells.append(inner)

    card_widths = [(PAGE_W - 2 * MARGIN) / len(metrics)] * len(metrics)
    tbl = Table([cells], colWidths=card_widths, rowHeights=[2.4 * cm])
    style_cmds = [
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("BOX", (0, 0), (-1, -1), 0.5, C_GRAY_LITE),
    ]
    for i, (_, _, _, clr) in enumerate(metrics):
        style_cmds += [
            ("LINEABOVE", (i, 0), (i, 0), 3, clr),
        ]
    tbl.setStyle(TableStyle(style_cmds))
    return tbl


# ══════════════════════════════════════════════════════════════════════════════
#  REMEDIATION DATABASE
# ══════════════════════════════════════════════════════════════════════════════

REMEDIATIONS = {
    "git_exposed": {
        "title": "Exposed .git Directory",
        "priority": "CRITICAL — fix within 24 hours",
        "description": (
            "A publicly accessible .git directory allows any attacker to reconstruct "
            "the full source code and commit history, revealing credentials, "
            "API keys, database connection strings, and internal business logic."
        ),
        "steps": [
            "Block web access to .git immediately in your web server config.",
            "Rotate ALL credentials, API keys, and secrets found in git history.",
            "Audit full commit history with `git log -p` or truffleHog for leaked secrets.",
            "Add `.git` to your WAF block list at the CDN level as a defence-in-depth measure.",
        ],
        "code": {
            "Apache (.htaccess)": "RedirectMatch 404 /\\.git",
            "Nginx":              "location ~ /\\.git { deny all; return 404; }",
        },
    },
    "env_file_exposed": {
        "title": "Exposed .env / Secrets File",
        "priority": "CRITICAL — fix within 24 hours",
        "description": (
            "Environment files contain database credentials, API keys, encryption "
            "salts, and service tokens in plain text. Exposure is equivalent to "
            "direct database access and full service account compromise."
        ),
        "steps": [
            "Remove or block the file via web server config immediately.",
            "Rotate every secret listed in the file — assume all are compromised.",
            "Never store .env files in the web root; move them one level above public_html.",
            "Use a secrets manager (AWS Secrets Manager, Vault, Doppler) instead of flat files.",
        ],
        "code": {
            "Nginx": "location ~ /\\.env { deny all; return 404; }",
        },
    },
    "backup_file_exposed": {
        "title": "Exposed Backup / Archive File",
        "priority": "HIGH — fix within 48 hours",
        "description": (
            "Publicly downloadable backup archives commonly contain full database dumps, "
            "source code, or configuration including credentials. Even compressed files "
            "can be trivially downloaded and extracted."
        ),
        "steps": [
            "Remove or move backup files outside of the web root immediately.",
            "Audit backup naming conventions — avoid predictable names like domain.zip.",
            "Configure web server to block common archive extensions.",
            "Store backups in private cloud storage with access control (private S3 bucket, etc.).",
        ],
        "code": {
            "Nginx": 'location ~* \\.(zip|tar\\.gz|sql|bak|rar|7z)$ { deny all; return 404; }',
        },
    },
    "database_port_open": {
        "title": "Database Port Exposed to Internet",
        "priority": "CRITICAL — restrict immediately",
        "description": (
            "Database services (MySQL, PostgreSQL, MongoDB, Redis) listening on public "
            "interfaces are directly exposed to brute-force, credential stuffing, "
            "and unauthenticated exploitation of known CVEs."
        ),
        "steps": [
            "Immediately restrict DB ports (3306, 5432, 27017, 6379, 9200) with firewall rules.",
            "Allow only application server IPs via security group / iptables.",
            "Enable authentication on all database services (Redis in particular often ships with it disabled).",
            "Place database servers in a private subnet with no public IP.",
        ],
        "code": {
            "iptables": "iptables -A INPUT -p tcp --dport 6379 -s <APP_SERVER_IP> -j ACCEPT\niptables -A INPUT -p tcp --dport 6379 -j DROP",
        },
    },
    "admin_panel_public": {
        "title": "Admin Panel Exposed to Public Internet",
        "priority": "HIGH — restrict within 48 hours",
        "description": (
            "Administrative interfaces exposed publicly are prime targets for "
            "credential stuffing and brute-force attacks. Compromise grants "
            "full application control to an attacker."
        ),
        "steps": [
            "Restrict admin paths (/admin, /dashboard, /wp-admin) by IP allowlist.",
            "Enforce Multi-Factor Authentication on all admin accounts.",
            "Move admin access behind a VPN or private network.",
            "Implement account lockout after 5 failed login attempts.",
        ],
        "code": {
            "Nginx IP allowlist": "location /admin {\n  allow <YOUR_OFFICE_IP>;\n  deny all;\n}",
        },
    },
    "missing_security_headers": {
        "title": "Missing HTTP Security Headers",
        "priority": "MEDIUM — fix within 1 week",
        "description": (
            "Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) "
            "leave users vulnerable to clickjacking, MIME-type sniffing attacks, and "
            "downgrade attacks on HTTPS connections."
        ),
        "steps": [
            "Add the recommended headers below to your web server or application.",
            "Validate headers at securityheaders.com after deployment.",
            "Implement a Content Security Policy (CSP) to restrict resource origins.",
            "Set HSTS max-age to at least 31536000 (1 year) and include subdomains.",
        ],
        "code": {
            "Nginx": (
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Content-Security-Policy \"default-src 'self'\" always;"
            ),
        },
    },
    "docker_api_open": {
        "title": "Docker API Exposed",
        "priority": "CRITICAL — isolate immediately",
        "description": (
            "An exposed Docker daemon API grants unauthenticated root-equivalent access "
            "to the host system. Attackers can deploy containers, mount the host filesystem, "
            "and achieve full host compromise in minutes."
        ),
        "steps": [
            "Immediately take the host offline or apply firewall rules to port 2375/2376.",
            "Never expose the Docker socket or API to a public interface.",
            "Use TLS mutual authentication if the API must be remotely accessible.",
            "Audit for container escapes and lateral movement since the exposure occurred.",
        ],
        "code": {
            "iptables block": "iptables -I INPUT -p tcp --dport 2375 -j DROP\niptables -I INPUT -p tcp --dport 2376 -j DROP",
        },
    },
    "outdated_tls": {
        "title": "Outdated TLS Protocol in Use",
        "priority": "MEDIUM — fix within 1 week",
        "description": (
            "TLS 1.0 and 1.1 are deprecated and vulnerable to protocol downgrade attacks "
            "(POODLE, BEAST). Modern browsers will warn users or block connections entirely."
        ),
        "steps": [
            "Disable TLS 1.0 and TLS 1.1 in web server configuration.",
            "Enable only TLS 1.2 and TLS 1.3.",
            "Use a strong cipher suite — refer to Mozilla SSL Configuration Generator.",
            "Validate configuration at ssllabs.com/ssltest after deployment.",
        ],
        "code": {
            "Nginx": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers off;",
        },
    },
}


def _normalise_flag(raw_flag: str) -> str:
    """
    Convert free-text exposure notes to the snake_case keys used in
    REMEDIATIONS.  e.g. 'missing security headers' -> 'missing_security_headers'
                        'git exposed'              -> 'git_exposed'
    """
    return raw_flag.lower().strip().replace(" ", "_").replace("-", "_")


# Technologies that require software patching, not just header tweaks.
_PATCH_TECHNOLOGIES = {
    "apache", "nginx", "iis", "lighttpd",  # web servers
    "php", "python", "ruby", "perl",        # runtimes
    "wordpress", "joomla", "drupal",        # CMS
    "openssl", "libssl",                    # crypto
}

# Frontend-only technologies: CVEs from NVD keyword search are almost always
# false positives for the web framework itself.
_FRONTEND_ONLY = {"bootstrap", "jquery", "react", "vue", "angular", "ember"}


def get_remediation(exposure_flags: list, technology: str, cves: list) -> dict:
    """
    Pick the most relevant remediation dict for a finding.

    Priority order:
      1. Exact exposure-flag match in REMEDIATIONS (e.g. git_exposed).
      2. Technology-specific CVE patching advice when real server/runtime CVEs exist.
      3. Missing security headers (only when the technology is NOT a frontend-only lib).
      4. Generic low-priority review.
    """
    normalised_flags = [_normalise_flag(f) for f in (exposure_flags or []) if f.strip()]
    tech_lower = (technology or "").lower().split()[0]  # e.g. "apache 2.4.6" -> "apache"

    # 1. High-specificity flags (git_exposed, env_file_exposed, etc.) always win,
    #    but skip generic 'missing_security_headers' here so CVE patching advice
    #    for real server software takes priority.
    _HEADER_ONLY_FLAGS = {"missing_security_headers"}
    for flag in normalised_flags:
        if flag in REMEDIATIONS and flag not in _HEADER_ONLY_FLAGS:
            return REMEDIATIONS[flag]

    # 2. Real server/runtime with matched CVEs -> patching advice
    if cves and tech_lower in _PATCH_TECHNOLOGIES:
        max_cvss = max((_sanitise_score(c.get("cvss", 0)) for c in cves), default=0)
        priority = (
            "CRITICAL — patch within 24 hours" if max_cvss >= 9.0 else
            "HIGH — patch within 1 week"       if max_cvss >= 7.0 else
            "MEDIUM — patch within 30 days"
        )
        return {
            "title": f"Update {technology} to latest stable version",
            "priority": priority,
            "description": (
                f"The detected version of {technology} is affected by {len(cves)} known CVE(s) "
                f"(highest CVSS: {max_cvss:.1f}). "
                "Upgrading to the latest stable release resolves all matched vulnerabilities."
            ),
            "steps": [
                f"Update {technology} to the latest stable version immediately.",
                "Review CVE details at nvd.nist.gov for any configuration-level mitigations "
                "that can be applied while patching is scheduled.",
                "Subscribe to the vendor's security advisory mailing list for future alerts.",
                "Re-scan after patching to confirm all matched CVEs are resolved.",
            ],
            "code": {},
        }

    # 3. Frontend-only tech (Bootstrap, jQuery …) with CVEs — the CVEs are
    #    almost certainly false positives from keyword matching; advise CPE-
    #    scoped verification and header hardening instead.
    if cves and tech_lower in _FRONTEND_ONLY:
        return {
            "title": f"Verify {technology} CVE Applicability and Harden Headers",
            "priority": "MEDIUM — review within 30 days",
            "description": (
                f"CVEs were matched for '{technology}' via keyword search. "
                "Many of these may be false positives because the NVD keyword "
                f"'{tech_lower}' also matches unrelated projects (e.g. Bitdefender BOX "
                "bootstrap stage, Singularity container bootstrap). "
                "Confirm applicability using the exact CPE "
                f"(cpe:2.3:a:getbootstrap:{tech_lower}:*) before treating these as confirmed findings. "
                "Independently of CVE status, apply the security headers below."
            ),
            "steps": [
                f"Cross-check each CVE against the official {technology} changelog and CPE entries.",
                "Discard any CVE whose CPE does not match cpe:2.3:a:getbootstrap:* (or equivalent).",
                f"Upgrade {technology} to the latest stable release as a precaution.",
                "Add HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).",
                "Validate headers at securityheaders.com after deployment.",
            ],
            "code": {
                "Nginx": (
                    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                    "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;\n"
                    "add_header Content-Security-Policy \"default-src 'self'\" always;"
                ),
            },
        }

    # 4. Missing headers flag without specific CVEs
    if "missing_security_headers" in normalised_flags:
        return REMEDIATIONS["missing_security_headers"]

    return {
        "title": "Review and Harden Configuration",
        "priority": "LOW — review within 30 days",
        "description": "No specific CVE was matched, but the asset has exposure signals worth reviewing.",
        "steps": [
            "Review exposure flags and apply principle of least privilege.",
            "Implement network-level access controls where applicable.",
        ],
        "code": {},
    }


# ══════════════════════════════════════════════════════════════════════════════
#  COVER PAGE
# ══════════════════════════════════════════════════════════════════════════════

def build_cover(styles, meta: dict) -> list:
    story = []
    label = meta.get("report_label", "PENETRATION TESTING REPORT")

    # Big dark cover block via a coloured table
    cover_data = [[
        Paragraph(
            f"<font color='#E84C3D'>■</font> {label}",
            ParagraphStyle("cl", fontSize=11, fontName="Helvetica-Bold",
                           textColor=colors.HexColor("#A0AEC0"), leading=14)
        ),
    ], [
        Paragraph(meta.get("client_name", "Client Organisation"), styles["cover_title"]),
    ], [
        Spacer(1, 0.3 * cm),
    ], [
        Paragraph(f"Target Domain: {meta.get('domain', 'target.com')}", styles["cover_sub"]),
    ], [
        Spacer(1, 1.2 * cm),
    ], [
        Table([[
            Table([[Paragraph("Assessment Date", styles["cover_meta"]),
                    Paragraph(meta.get("date", datetime.now().strftime("%B %d, %Y")),
                              ParagraphStyle("cv", fontSize=10, fontName="Helvetica-Bold",
                                            textColor=C_WHITE, leading=14))]],
                  colWidths=[3.5 * cm, 5 * cm]),
            Table([[Paragraph("Prepared By", styles["cover_meta"]),
                    Paragraph(meta.get("assessor", "Security Team"),
                              ParagraphStyle("cv", fontSize=10, fontName="Helvetica-Bold",
                                            textColor=C_WHITE, leading=14))]],
                  colWidths=[3 * cm, 5 * cm]),
            Table([[Paragraph("Classification", styles["cover_meta"]),
                    Paragraph("CONFIDENTIAL",
                              ParagraphStyle("cv", fontSize=10, fontName="Helvetica-Bold",
                                            textColor=C_ACCENT, leading=14))]],
                  colWidths=[3 * cm, 4 * cm]),
        ]], colWidths=[(PAGE_W - 2 * MARGIN) / 3] * 3),
    ]]

    cover_tbl = Table(cover_data, colWidths=[PAGE_W - 2 * MARGIN],
                      rowHeights=[1 * cm, 2.5 * cm, 0.5 * cm,
                                  0.8 * cm, 1 * cm, 2 * cm])
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK),
        ("LEFTPADDING",   (0, 0), (-1, -1), 28),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 28),
        ("TOPPADDING",    (0, 0), (0, 0), 28),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 28),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    story.append(Spacer(1, 1.5 * cm))
    story.append(cover_tbl)
    story.append(Spacer(1, 0.6 * cm))

    # Disclaimer box
    disc = (
        "<b>IMPORTANT — AUTHORISED USE ONLY.</b>  This report is prepared exclusively for "
        f"{meta.get('client_name', 'the named client')} and contains confidential security "
        "information. Distribution, reproduction, or use by unauthorised parties is strictly "
        "prohibited. The findings and recommendations herein reflect the state of the assessed "
        "systems at the time of testing and should not be used as a guarantee of security."
    )
    disc_tbl = Table([[Paragraph(disc, styles["body_small"])]],
                     colWidths=[PAGE_W - 2 * MARGIN])
    disc_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FFF5F5")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BOX",           (0, 0), (-1, -1), 1, C_ACCENT),
    ]))
    story.append(disc_tbl)
    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  TABLE OF CONTENTS
# ══════════════════════════════════════════════════════════════════════════════

def build_toc(styles) -> list:
    story = []
    story += section_divider(styles, "Table of Contents")
    story.append(Spacer(1, 0.3 * cm))

    sections = [
        ("1.", "Executive Summary"),
        ("2.", "Assessment Scope & Methodology"),
        ("3.", "Risk Overview"),
        ("4.", "Technical Findings"),
        ("5.", "Exposed Asset Inventory"),
        ("6.", "Remediation Roadmap"),
        ("7.", "Appendix — Full CVE Table"),
    ]
    for num, title in sections:
        row = Table([[
            Paragraph(f"<b>{num}</b>", styles["toc_entry"]),
            Paragraph(title, styles["toc_entry"]),
        ]], colWidths=[1.2 * cm, PAGE_W - 2 * MARGIN - 2.2 * cm])
        row.setStyle(TableStyle([
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(row)

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — EXECUTIVE SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def _sanitise_score(raw) -> float:
    """
    Strip any stray LaTeX/markdown math characters from a score value
    and return a clean float.  e.g. '$74.6/100$' or '74.6100/' -> 74.6
    """
    import re
    s = str(raw).replace("$", "").replace("`", "").strip()
    # grab the first decimal / integer number in the string
    m = re.search(r"\d+(?:\.\d+)?", s)
    return float(m.group()) if m else 0.0


def _live_counts(m3_findings: list, leak_findings: list) -> dict:
    """
    Recount severity levels directly from finding objects so that the
    Executive Summary and Technical Findings sections are always in sync.
    Leak findings whose risk field is 'critical' or 'high' are included.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in m3_findings:
        lvl = (f.get("risk_level") or "INFO").upper().strip()
        if lvl in counts:
            counts[lvl] += 1
    for lf in leak_findings:
        lvl = (lf.get("risk") or "INFO").upper().strip()
        if lvl in counts:
            counts[lvl] += 1
    return counts


def build_executive_summary(styles, data: dict) -> list:
    story = []
    story += section_divider(styles, "1. Executive Summary")

    m1      = data.get("module1", {})
    m3      = data.get("module3", {})
    leaks   = data.get("leaks", {})

    domain          = m1.get("domain", "target.com")
    total_subs      = m1.get("total_subdomains", 0)
    alive_subs      = m1.get("alive_subdomains", 0)
    cloud_assets    = len(m1.get("cloud_assets", []))
    cred_leaks      = len(m1.get("leaked_credentials", []))
    kev_matches     = m3.get("kev_matches", 0)
    leak_findings_list = leaks.get("findings", [])
    leak_findings   = len(leak_findings_list)
    total_leak_crit = leaks.get("critical_count", 0)

    # ── Bug 1 fix: recount severity from raw findings, not stale JSON fields ──
    live = _live_counts(m3.get("findings", []), leak_findings_list)
    critical_count = live["CRITICAL"]
    high_count     = live["HIGH"]
    medium_count   = live["MEDIUM"]
    low_count      = live["LOW"]
    total_findings = sum(live.values())

    # Overall risk verdict
    if critical_count > 0 or kev_matches > 0:
        verdict      = "CRITICAL"
        verdict_desc = "Critical vulnerabilities were identified that require immediate remediation. Active exploitation by attackers is a realistic and imminent threat."
    elif high_count > 3:
        verdict      = "HIGH"
        verdict_desc = "Multiple high-severity vulnerabilities were found. The attack surface presents significant risk and must be addressed urgently."
    elif high_count > 0:
        verdict      = "MEDIUM-HIGH"
        verdict_desc = "High-severity findings require prioritised attention within this sprint cycle. No critical issues were identified."
    else:
        verdict      = "MEDIUM"
        verdict_desc = "The assessment identified medium-severity findings. While not immediately exploitable, they represent meaningful risk if left unaddressed."

    story.append(Spacer(1, 0.2 * cm))

    # Verdict banner
    verdict_color = LEVEL_COLORS.get(verdict.split("-")[0], C_MEDIUM)
    vb_tbl = Table([[
        Paragraph(f"Overall Risk Rating: <b>{verdict}</b>", 
                  ParagraphStyle("vb", fontSize=14, fontName="Helvetica-Bold",
                                 textColor=C_WHITE, leading=18)),
    ]], colWidths=[PAGE_W - 2 * MARGIN])
    vb_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), verdict_color),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(vb_tbl)
    story.append(Spacer(1, 0.4 * cm))

    # Metric cards
    story.append(metric_cards([
        ("Critical Findings",   critical_count, "", C_CRITICAL),
        ("High Findings",       high_count,     "", C_HIGH),
        ("Actively Exploited",  kev_matches,    "CISA KEV", C_CRITICAL),
        ("Credential Leaks",    cred_leaks + leak_findings, "", C_HIGH),
    ]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(metric_cards([
        ("Total Findings",   total_findings, "", C_BLUE),
        ("Alive Subdomains", alive_subs,     f"of {total_subs} discovered", C_BLUE),
        ("Cloud Assets",     cloud_assets,   "", C_GRAY_MID),
        ("File Leaks",       leak_findings,  "", C_HIGH),
    ]))
    story.append(Spacer(1, 0.5 * cm))

    # Narrative
    narrative = (
        f"A comprehensive security assessment of <b>{domain}</b> was conducted to evaluate the "
        f"external attack surface. The engagement discovered <b>{total_subs} subdomains</b>, of which "
        f"<b>{alive_subs}</b> were alive and responsive. "
    )
    if cloud_assets:
        narrative += f"<b>{cloud_assets} cloud asset(s)</b> were enumerated across major providers. "
    if cred_leaks:
        narrative += f"<b>{cred_leaks} potential credential leak(s)</b> were identified in public GitHub repositories. "
    if leak_findings:
        narrative += (
            f"Directory fuzzing uncovered <b>{leak_findings} exposed file(s)</b>"
            + (f", including <b>{total_leak_crit} critical</b> file(s) such as .env or .git directories" if total_leak_crit else "")
            + ". "
        )
    if kev_matches:
        narrative += (
            f"<b>{kev_matches} finding(s) are confirmed in the CISA Known Exploited Vulnerabilities "
            f"(KEV) catalog</b>, meaning they are being actively weaponised by threat actors right now. "
        )
    narrative += verdict_desc

    story.append(Paragraph(narrative, styles["body"]))
    story.append(Spacer(1, 0.4 * cm))

    # Key Recommendations
    story.append(Paragraph("<b>Priority Actions</b>", styles["section_h2"]))
    recos = []
    if kev_matches:
        recos.append(f"<b>[IMMEDIATE]</b> Patch {kev_matches} CVE(s) in the CISA KEV list — these are actively exploited in the wild.")
    if cred_leaks or (total_leak_crit > 0):
        recos.append("<b>[IMMEDIATE]</b> Rotate all credentials found in GitHub or exposed configuration files.")
    if critical_count:
        recos.append("<b>[24 hrs]</b> Remediate all CRITICAL findings before any other development work proceeds.")
    if high_count:
        recos.append(f"<b>[1 week]</b> Address {high_count} HIGH findings within the next sprint.")
    if medium_count:
        recos.append(f"<b>[1 month]</b> Schedule remediation of {medium_count} MEDIUM findings.")
    recos.append("<b>[Ongoing]</b> Implement continuous monitoring (Module 2) to detect new attack surfaces as infrastructure evolves.")

    for r in recos:
        story.append(Paragraph(r, styles["bullet"]))

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — SCOPE & METHODOLOGY
# ══════════════════════════════════════════════════════════════════════════════

def build_methodology(styles, data: dict) -> list:
    story = []
    story += section_divider(styles, "2. Assessment Scope & Methodology")

    m1   = data.get("module1", {})
    meta = data.get("meta", {})

    story.append(Paragraph("<b>Scope</b>", styles["section_h2"]))
    story.append(kv_table([
        ("Target Domain",  m1.get("domain", "N/A")),
        ("Assessment Type","Black-box External Penetration Test"),
        ("Test Date",      meta.get("date", datetime.now().strftime("%B %d, %Y"))),
        ("Duration",       f"{m1.get('scan_duration_seconds', 'N/A')}s (automated) + manual review"),
        ("Assessor",       meta.get("assessor", "Security Team")),
        ("Classification", "CONFIDENTIAL"),
    ]))

    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("<b>Tools & Data Sources</b>", styles["section_h2"]))

    tools = [
        ("Subdomain Discovery",  "Certificate transparency logs (crt.sh), AlienVault OTX, URLScan.io, DNS bruteforce"),
        ("Technology Fingerprint", "Wappalyzer-style header & response analysis"),
        ("Port Scanning",        "Async TCP connect scan — top ports"),
        ("Cloud Enumeration",    "DNS permutation & public bucket probing (S3, Azure Blob, GCP)"),
        ("Credential Scanning",  "GitHub dork search for tokens, API keys, connection strings"),
        ("Leak Detection",       "Wordlist-based HTTP path fuzzing with content-signature validation"),
        ("CVE Matching",         "NIST NVD API v2.0 with version-range filtering, OSV.dev, Vulners.com"),
        ("Active Exploit Check", "CISA Known Exploited Vulnerabilities (KEV) catalog"),
        ("Risk Scoring",         "Composite 0-100 score: CVSS + KEV status + exposure context + asset criticality"),
    ]
    story.append(kv_table(tools))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("<b>Methodology Summary</b>", styles["section_h2"]))
    methodology_text = (
        "The assessment follows a four-phase methodology aligned with PTES (Penetration Testing Execution "
        "Standard) and OWASP Testing Guide. "
        "<b>Phase 1 — Reconnaissance:</b> Passive and active asset discovery to enumerate the full "
        "external attack surface without direct exploitation. "
        "<b>Phase 2 — Enumeration:</b> Technology fingerprinting, port scanning, and cloud asset "
        "enumeration to build a detailed picture of exposed services. "
        "<b>Phase 3 — Vulnerability Identification:</b> Automated CVE matching against detected versions, "
        "credential leak detection, and exposed file discovery with content-validated evidence. "
        "<b>Phase 4 — Risk Scoring:</b> Each finding is scored 0-100 using a composite model that "
        "weights CVSS severity, active exploitation status, asset criticality, and exposure context "
        "— the same model used by commercial vulnerability management platforms."
    )
    story.append(Paragraph(methodology_text, styles["body"]))
    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — RISK OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════

def build_risk_overview(styles, data: dict) -> list:
    story = []
    story += section_divider(styles, "3. Risk Overview")

    m3 = data.get("module3", {})
    findings = m3.get("findings", [])

    counts = {
        "CRITICAL": m3.get("critical_count", 0),
        "HIGH":     m3.get("high_count", 0),
        "MEDIUM":   m3.get("medium_count", 0),
        "LOW":      m3.get("low_count", 0),
        "INFO":     sum(1 for f in findings if f.get("risk_level") == "INFO"),
    }

    # Charts side by side
    if findings:
        donut = make_severity_donut(counts)
        bar   = make_risk_bar_chart(findings)

        chart_row = Table(
            [[donut, bar]],
            colWidths=[(PAGE_W - 2 * MARGIN) * 0.36,
                       (PAGE_W - 2 * MARGIN) * 0.64],
        )
        chart_row.setStyle(TableStyle([
            ("VALIGN",  (0, 0), (-1, -1), "TOP"),
            ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(chart_row)
        story.append(Spacer(1, 0.3 * cm))

        tech_chart = make_tech_distribution(findings)
        if tech_chart:
            story.append(tech_chart)

    # Findings table summary
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("<b>Finding Count by Severity</b>", styles["section_h2"]))

    hdr_style = ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold",
                                textColor=C_WHITE, leading=12)
    cell_style = ParagraphStyle("tc", fontSize=9, fontName="Helvetica",
                                 textColor=C_GRAY_DARK, leading=12)

    table_data = [[
        Paragraph("Severity", hdr_style),
        Paragraph("Count", hdr_style),
        Paragraph("SLA Target", hdr_style),
        Paragraph("Business Impact", hdr_style),
    ]]
    sla = {
        "CRITICAL": "Immediate (< 24 hours)",
        "HIGH":     "Urgent (< 1 week)",
        "MEDIUM":   "Planned (< 30 days)",
        "LOW":      "Scheduled (< 90 days)",
        "INFO":     "Informational",
    }
    impact = {
        "CRITICAL": "System compromise, data breach, full loss of confidentiality",
        "HIGH":     "Significant service disruption or unauthorised data access",
        "MEDIUM":   "Limited data exposure or potential privilege escalation",
        "LOW":      "Minor information disclosure, defence-in-depth weakening",
        "INFO":     "Informational observation, no direct security impact",
    }
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        table_data.append([
            Paragraph(f"<b>{level}</b>", cell_style),
            Paragraph(str(counts[level]), cell_style),
            Paragraph(sla[level], cell_style),
            Paragraph(impact[level], cell_style),
        ])

    # Column widths chosen so "Count" (5 chars) never wraps:
    # Severity=0.16, Count=0.10, SLA Target=0.30, Business Impact=0.44
    col_w = PAGE_W - 2 * MARGIN
    sev_tbl = Table(table_data, colWidths=[col_w * 0.16, col_w * 0.10,
                                            col_w * 0.30, col_w * 0.44])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
        ("BACKGROUND",    (0, 1), (-1, 1), colors.HexColor("#FEF5F5")),
        ("BACKGROUND",    (0, 2), (-1, 2), colors.HexColor("#FEF0E8")),
        ("BACKGROUND",    (0, 3), (-1, 3), colors.HexColor("#FFFCE8")),
        ("BACKGROUND",    (0, 4), (-1, 4), colors.HexColor("#F0FFF4")),
        ("ROWBACKGROUNDS",(0, 5), (-1, 5), [C_GRAY_LITE]),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_GRAY_LITE),
    ]))
    story.append(sev_tbl)
    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — TECHNICAL FINDINGS
# ══════════════════════════════════════════════════════════════════════════════

def build_technical_findings(styles, data: dict) -> list:
    story = []
    story += section_divider(styles, "4. Technical Findings")

    m3       = data.get("module3", {})
    leaks_d  = data.get("leaks", {})
    findings = m3.get("findings", [])
    leak_f   = leaks_d.get("findings", [])

    # Merge leak findings in
    for lf in leak_f:
        lf_risk = (lf.get("risk") or "").upper().strip()
        if lf_risk in ("CRITICAL", "HIGH"):
            findings.append({
                "subdomain":    lf.get("subdomain", lf.get("url", "?")),
                "technology":   "File Exposure",
                "version":      None,
                "risk_level":   lf_risk,
                "risk_score":   _sanitise_score(lf.get("risk_score", 90 if lf_risk == "CRITICAL" else 70)),
                "matched_cves": [],
                "in_kev":       False,
                "exposure_notes": lf.get("type", ""),
                "breakdown":    {"exposure_notes": lf.get("evidence", "")},
                "_from_leak":   True,
                "_leak_url":    lf.get("url", ""),
                "_leak_path":   lf.get("path", ""),
            })

    # Sort by risk score descending
    findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    if not findings:
        story.append(Paragraph("No findings to report.", styles["body"]))
        story.append(PageBreak())
        return story

    for idx, finding in enumerate(findings, 1):
        level      = (finding.get("risk_level") or "INFO").upper().strip()
        color      = LEVEL_COLORS.get(level, C_INFO)
        subdomain  = finding.get("subdomain", "Unknown")
        technology = finding.get("technology", "N/A")
        version    = finding.get("version") or ""
        score      = _sanitise_score(finding.get("risk_score", 0))
        cves       = finding.get("matched_cves", [])
        in_kev     = finding.get("in_kev", False)
        exp_notes  = finding.get("exposure_notes", "") or finding.get("breakdown", {}).get("exposure_notes", "")
        breakdown  = finding.get("breakdown", {})

        # Determine exposure flags from exposure notes text
        exposure_flags = [f.strip().replace(" ", "_") for f in exp_notes.split(",") if f.strip()]
        remediation    = get_remediation(exposure_flags, technology, cves)

        # Header bar
        title_text = f"Finding #{idx:02d} — {technology} {version} on {subdomain}"
        if finding.get("_from_leak"):
            title_text = f"Finding #{idx:02d} — Exposed File: {finding.get('_leak_path', '')} on {subdomain}"

        header_tbl = Table([[
            Paragraph(title_text, styles["finding_title"]),
            Paragraph(f"Score: {score}/100", 
                      ParagraphStyle("sc", fontSize=11, fontName="Helvetica-Bold",
                                     textColor=C_WHITE, leading=14, alignment=TA_RIGHT)),
        ]], colWidths=[(PAGE_W - 2 * MARGIN) * 0.80, (PAGE_W - 2 * MARGIN) * 0.20])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), color),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))

        # Details table
        detail_rows = [
            ("Affected Asset",   subdomain),
            ("Technology",       f"{technology} {version}".strip()),
            ("Risk Level",       level),
            ("Risk Score",       f"{score} / 100"),
            ("Exposure Context", exp_notes or "None detected"),
        ]
        if in_kev:
            detail_rows.append(("⚠ CISA KEV", "ACTIVELY EXPLOITED IN THE WILD — patch immediately"))
        if finding.get("_leak_url"):
            detail_rows.append(("Evidence URL", finding["_leak_url"]))

        details_tbl = kv_table(detail_rows)

        # CVE list
        cve_elements = []
        if cves:
            cve_elements.append(Paragraph("<b>Matched CVEs</b>", styles["section_h3"]))
            cve_data = [[
                Paragraph("<b>CVE ID</b>",   ParagraphStyle("ch", fontSize=8, fontName="Helvetica-Bold", textColor=C_WHITE, leading=10)),
                Paragraph("<b>CVSS</b>",     ParagraphStyle("ch", fontSize=8, fontName="Helvetica-Bold", textColor=C_WHITE, leading=10)),
                Paragraph("<b>Sources</b>",  ParagraphStyle("ch", fontSize=8, fontName="Helvetica-Bold", textColor=C_WHITE, leading=10)),
                Paragraph("<b>Summary</b>",  ParagraphStyle("ch", fontSize=8, fontName="Helvetica-Bold", textColor=C_WHITE, leading=10)),
            ]]
            for cve in cves[:8]:
                cvss_val = _sanitise_score(cve.get("cvss", 0))
                cvss_col = C_CRITICAL if cvss_val >= 9 else C_HIGH if cvss_val >= 7 else C_MEDIUM if cvss_val >= 4 else C_LOW
                kev_mark = " ☠" if cve.get("kev") else ""
                cve_data.append([
                    Paragraph(f"<a href='{cve.get('url','#')}'><b>{cve.get('cve_id','?')}</b></a>{kev_mark}",
                              ParagraphStyle("cv", fontSize=7.5, fontName="Helvetica", textColor=C_BLUE, leading=10)),
                    Paragraph(f"<b>{cvss_val}</b>",
                              ParagraphStyle("cv", fontSize=8, fontName="Helvetica-Bold", textColor=cvss_col, leading=10)),
                    Paragraph(", ".join(cve.get("sources", ["NVD"])),
                              ParagraphStyle("cv", fontSize=7.5, fontName="Helvetica", textColor=C_GRAY_MID, leading=10)),
                    Paragraph((cve.get("summary") or "")[:120],
                              ParagraphStyle("cv", fontSize=7.5, fontName="Helvetica", textColor=C_GRAY_DARK, leading=10)),
                ])
            cw = PAGE_W - 2 * MARGIN
            cve_tbl = Table(cve_data, colWidths=[cw * 0.20, cw * 0.08, cw * 0.14, cw * 0.58])
            cve_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_GRAY_DARK),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GRAY_LITE]),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("GRID",          (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
            ]))
            cve_elements.append(cve_tbl)

        # Remediation steps
        rem_elements = []
        rem_elements.append(Spacer(1, 0.2 * cm))
        rem_elements.append(Paragraph("<b>Remediation</b>", styles["section_h3"]))
        rem_elements.append(Paragraph(remediation["description"], styles["body"]))
        rem_elements.append(Paragraph(f"<b>Priority:</b> {remediation['priority']}", styles["body"]))
        for i, step in enumerate(remediation["steps"], 1):
            rem_elements.append(Paragraph(f"{i}. {step}", styles["body"]))
        for platform, cmd in (remediation.get("code") or {}).items():
            rem_elements.append(Paragraph(f"<i>{platform}:</i>", styles["body_small"]))
            rem_elements.append(Paragraph(cmd.replace("\n", "<br/>"), styles["mono"]))

        block = KeepTogether([
            header_tbl,
            Spacer(1, 0.1 * cm),
            details_tbl,
        ] + cve_elements + rem_elements + [
            HRFlowable(width="100%", thickness=0.5, color=C_GRAY_LITE, spaceAfter=8),
            Spacer(1, 0.2 * cm),
        ])
        story.append(block)

        # Page break every 2 critical/high findings to keep pages readable
        if idx % 3 == 0:
            story.append(PageBreak())

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — EXPOSED ASSET INVENTORY
# ══════════════════════════════════════════════════════════════════════════════

def build_asset_inventory(styles, data: dict) -> list:
    story = []
    story += section_divider(styles, "5. Exposed Asset Inventory")

    m1 = data.get("module1", {})
    subdomains   = m1.get("subdomains", [])
    cloud_assets = m1.get("cloud_assets", [])
    leaked_creds = m1.get("leaked_credentials", [])

    alive = [s for s in subdomains if s.get("is_alive")]

    story.append(Paragraph(f"<b>Alive Subdomains</b> ({len(alive)} of {len(subdomains)} discovered)", styles["section_h2"]))

    if alive:
        hdr_s = ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=C_WHITE, leading=10)
        cell_s = ParagraphStyle("tc", fontSize=8, fontName="Helvetica", textColor=C_GRAY_DARK, leading=10)
        inv_data = [[
            Paragraph("Subdomain", hdr_s),
            Paragraph("Status", hdr_s),
            Paragraph("Open Ports", hdr_s),
            Paragraph("Technologies", hdr_s),
        ]]
        for sub in sorted(alive, key=lambda x: (x.get("https_status") or x.get("http_status") or 999)):
            status = sub.get("https_status") or sub.get("http_status") or "?"
            ports  = ", ".join(str(p) for p in (sub.get("open_ports") or [])[:6])
            techs  = ", ".join((sub.get("technologies") or [])[:4])
            inv_data.append([
                Paragraph(sub.get("subdomain", "?"), cell_s),
                Paragraph(str(status), cell_s),
                Paragraph(ports or "—", cell_s),
                Paragraph(techs or "—", cell_s),
            ])
        cw = PAGE_W - 2 * MARGIN
        inv_tbl = Table(inv_data, colWidths=[cw * 0.38, cw * 0.09, cw * 0.17, cw * 0.36],
                        repeatRows=1)
        inv_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GRAY_LITE]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
        ]))
        story.append(inv_tbl)

    # Cloud assets
    if cloud_assets:
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(f"<b>Cloud Assets</b> ({len(cloud_assets)} found)", styles["section_h2"]))
        for asset in cloud_assets:
            pub = "🔴 PUBLIC" if asset.get("is_public") else "🟡 Private"
            story.append(Paragraph(
                f"{pub}  <b>{asset.get('provider','?')}/{asset.get('asset_type','?')}</b>  "
                f"— {asset.get('url','?')}",
                styles["body"]
            ))

    # Credential leaks
    if leaked_creds:
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(f"<b>GitHub Credential Leaks</b> ({len(leaked_creds)} found)", styles["section_h2"]))
        for leak in leaked_creds[:20]:
            story.append(Paragraph(
                f"[{leak.get('credential_type','?')}]  {leak.get('repo_url','?')}<br/>"
                f"File: {leak.get('file_path','?')}",
                styles["body"]
            ))
            story.append(HRFlowable(width="100%", thickness=0.3, color=C_GRAY_LITE))

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — REMEDIATION ROADMAP
# ══════════════════════════════════════════════════════════════════════════════

def build_remediation_roadmap(styles, data: dict) -> list:
    story = []
    story += section_divider(styles, "6. Remediation Roadmap")

    m3       = data.get("module3", {})
    findings = m3.get("findings", [])

    lanes = {"IMMEDIATE": [], "1 WEEK": [], "1 MONTH": [], "90 DAYS": []}

    for f in sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True):
        level = f.get("risk_level", "INFO")
        if level == "CRITICAL":
            lanes["IMMEDIATE"].append(f)
        elif level == "HIGH":
            lanes["1 WEEK"].append(f)
        elif level == "MEDIUM":
            lanes["1 MONTH"].append(f)
        else:
            lanes["90 DAYS"].append(f)

    lane_colors = {
        "IMMEDIATE": C_CRITICAL,
        "1 WEEK":    C_HIGH,
        "1 MONTH":   C_MEDIUM,
        "90 DAYS":   C_LOW,
    }

    for lane, lane_findings in lanes.items():
        if not lane_findings:
            continue

        lane_hdr = Table([[
            Paragraph(f"⏱ {lane}", ParagraphStyle("lh", fontSize=10, fontName="Helvetica-Bold",
                                                   textColor=C_WHITE, leading=13)),
            Paragraph(f"{len(lane_findings)} item(s)",
                      ParagraphStyle("lc", fontSize=9, fontName="Helvetica",
                                     textColor=C_WHITE, leading=13, alignment=TA_RIGHT)),
        ]], colWidths=[(PAGE_W - 2 * MARGIN) * 0.85, (PAGE_W - 2 * MARGIN) * 0.15])
        lane_hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), lane_colors[lane]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(Spacer(1, 0.3 * cm))
        story.append(lane_hdr)

        for f in lane_findings[:10]:
            exp_notes  = f.get("exposure_notes", "") or ""
            exp_flags  = [e.strip().replace(" ", "_") for e in exp_notes.split(",") if e.strip()]
            tech       = f.get("technology", "N/A")
            cves       = f.get("matched_cves", [])
            rem        = get_remediation(exp_flags, tech, cves)

            story.append(Paragraph(
                f"<b>{f.get('subdomain','?')}</b>  —  {tech} {f.get('version') or ''}  "
                f"(score {_sanitise_score(f.get('risk_score', 0)):.0f})",
                styles["section_h3"]
            ))
            story.append(Paragraph(rem["description"], styles["body"]))
            for i, step in enumerate(rem["steps"], 1):
                story.append(Paragraph(f"  {i}. {step}", styles["body"]))
            story.append(HRFlowable(width="100%", thickness=0.3, color=C_GRAY_LITE, spaceAfter=4))

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — APPENDIX: FULL CVE TABLE
# ══════════════════════════════════════════════════════════════════════════════

def build_appendix(styles, data: dict) -> list:
    story = []
    story += section_divider(styles, "7. Appendix — Full CVE Table")

    m3       = data.get("module3", {})
    findings = m3.get("findings", [])

    all_cves = {}
    for f in findings:
        for cve in f.get("matched_cves", []):
            cid = cve.get("cve_id", "")
            if cid and cid not in all_cves:
                all_cves[cid] = {**cve, "_subdomain": f.get("subdomain", "?")}

    if not all_cves:
        story.append(Paragraph("No CVEs were matched in this scan.", styles["body"]))
        return story

    sorted_cves = sorted(all_cves.values(), key=lambda x: _sanitise_score(x.get("cvss", 0)), reverse=True)

    hdr_s  = ParagraphStyle("th", fontSize=7.5, fontName="Helvetica-Bold", textColor=C_WHITE, leading=10)
    cell_s = ParagraphStyle("tc", fontSize=7.5, fontName="Helvetica", textColor=C_GRAY_DARK, leading=10)
    link_s = ParagraphStyle("lk", fontSize=7.5, fontName="Helvetica", textColor=C_BLUE, leading=10)

    tbl_data = [[
        Paragraph("CVE ID", hdr_s),
        Paragraph("CVSS", hdr_s),
        Paragraph("KEV", hdr_s),
        Paragraph("Sources", hdr_s),
        Paragraph("Affected Asset", hdr_s),
        Paragraph("Summary", hdr_s),
    ]]
    for cve in sorted_cves:
        cvss_val = _sanitise_score(cve.get("cvss", 0))
        tbl_data.append([
            Paragraph(f"<a href='{cve.get('url','#')}'>{cve.get('cve_id','?')}</a>", link_s),
            Paragraph(f"{cvss_val:.1f}", cell_s),
            Paragraph("☠" if cve.get("kev") else "—", cell_s),
            Paragraph(", ".join(cve.get("sources", ["NVD"])), cell_s),
            Paragraph(cve.get("_subdomain", "?")[:30], cell_s),
            Paragraph((cve.get("summary") or "")[:100], cell_s),
        ])

    cw = PAGE_W - 2 * MARGIN
    app_tbl = Table(tbl_data,
                    colWidths=[cw * 0.19, cw * 0.07, cw * 0.06,
                               cw * 0.12, cw * 0.22, cw * 0.34],
                    repeatRows=1)
    app_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GRAY_LITE]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
    ]))
    story.append(app_tbl)
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(data: dict, output_path: str) -> str:
    styles  = build_styles()
    meta    = data.get("meta", {})
    domain  = data.get("module1", {}).get("domain", "target.com")
    client  = meta.get("client_name", "Client")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.6 * cm, bottomMargin=1.8 * cm,
        title=f"Security Assessment Report — {domain}",
        author=meta.get("assessor", "Security Team"),
        subject="Penetration Testing Report",
        creator="Asset Discovery Engine — Module 4",
    )

    story = []
    story += build_cover(styles, meta)
    story += build_toc(styles)
    story += build_executive_summary(styles, data)
    story += build_methodology(styles, data)
    story += build_risk_overview(styles, data)
    story += build_technical_findings(styles, data)
    story += build_asset_inventory(styles, data)
    story += build_remediation_roadmap(styles, data)
    story += build_appendix(styles, data)

    canvas_factory = make_canvas_factory(client, domain)
    doc.build(story, canvasmaker=canvas_factory)
    return output_path


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT LOADERS
# ══════════════════════════════════════════════════════════════════════════════

def load_json(path: Optional[str], label: str) -> dict:
    if not path:
        return {}
    if not os.path.isfile(path):
        print(f"  WARNING: {label} not found at {path} — section will be empty.")
        return {}
    with open(path) as f:
        return json.load(f)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  MODULE 4 — Professional PDF Report Generator                ║
║  The $5k–$15k pentest deliverable, automated.                ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Module 4 — Generate a professional PDF pentest report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full report from all three module outputs:
  python3 report_generator.py \\
      --module1 reports/example.com_latest.json \\
      --module3 module3_reports/example.com_risk_report.json \\
      --leaks   module2_5_reports/example.com_leaks.json \\
      --client "Acme Corp" --assessor "Hawk Security Ltd" --confirm

  # Module 1 only (no risk scoring yet):
  python3 report_generator.py \\
      --module1 reports/example.com_latest.json \\
      --client "Beta Co" --confirm
        """,
    )
    parser.add_argument("--module1",  default=None, help="Path to Module 1 JSON report")
    parser.add_argument("--module3",  default=None, help="Path to Module 3 risk-report JSON")
    parser.add_argument("--leaks",    default=None, help="Path to Module 2.5 leak-scan JSON")
    parser.add_argument("--client",   default="Client Organisation", help="Client company name")
    parser.add_argument("--assessor", default="Security Team", help="Your firm or assessor name")
    parser.add_argument("--label",    default="PENETRATION TESTING REPORT",
                        help="Report label shown on cover page")
    parser.add_argument("--output-dir", default="module4_reports", help="Output directory")
    parser.add_argument("--confirm",  action="store_true",
                        help="Confirm you have authorization to process and report on this data")
    args = parser.parse_args()

    if not args.confirm:
        print("ERROR: Add --confirm to certify you are authorized to generate this report.")
        sys.exit(1)

    if not args.module1 and not args.module3:
        print("ERROR: Provide at least --module1 or --module3 JSON report.")
        sys.exit(1)

    m1_data  = load_json(args.module1, "Module 1 report")
    m3_data  = load_json(args.module3, "Module 3 report")
    lk_data  = load_json(args.leaks,   "Module 2.5 leaks")

    domain = (m1_data.get("domain") or m3_data.get("domain") or "unknown")
    date_str = datetime.now().strftime("%B %d, %Y")
    ts = int(time.time())

    data = {
        "meta": {
            "client_name":   args.client,
            "assessor":      args.assessor,
            "domain":        domain,
            "date":          date_str,
            "report_label":  args.label,
        },
        "module1": m1_data,
        "module3": m3_data,
        "leaks":   lk_data,
    }

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    out_path = os.path.join(args.output_dir, f"{domain}_pentest_report_{ts}.pdf")

    print(f"  Client   : {args.client}")
    print(f"  Domain   : {domain}")
    print(f"  Assessor : {args.assessor}")
    print(f"  Output   : {out_path}")
    print("\n  Generating PDF...")

    generate_report(data, out_path)

    print(f"  ✓ Report saved: {out_path}")
    print(f"\n  Pages: full report with cover, exec summary, findings,")
    print(f"         remediation roadmap, asset inventory, CVE appendix.\n")


if __name__ == "__main__":
    main()
