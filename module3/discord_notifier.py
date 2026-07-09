"""
Module 3 — Multi-Platform Webhook Notifier
=============================================
Broadcasts risk alerts to ALL configured webhooks (up to 5+ slots in
config.DISCORD_WEBHOOKS, no hard cap). Each URL is auto-detected and sent
in the CORRECT format for its own platform — Discord, Slack, or a generic
JSON payload for anything else — so you can mix Discord + Slack + custom
endpoints across the 5 slots and every one of them actually works.

(Module named discord_notifier.py for backward compatibility with
run_module3.py's existing --discord-webhook flag and imports — the
config variable/flag names are unchanged, only the delivery logic
inside is now platform-aware.)
"""
import requests
import config

RISK_COLORS = {
    "CRITICAL": 10038562,   # dark red
    "HIGH":     15158332,   # red
    "MEDIUM":   16776960,   # yellow
    "LOW":      3066993,    # green
    "INFO":     9807270,    # gray
    "CLEAN":    3066993,    # green — used only for a 0-finding summary embed
}

RISK_LEVEL_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _meets_threshold(level: str) -> bool:
    try:
        return RISK_LEVEL_ORDER.index(level) >= RISK_LEVEL_ORDER.index(config.DISCORD_ALERT_MIN_LEVEL)
    except ValueError:
        return False


def _active_webhooks() -> list:
    """Returns only the non-empty configured webhook URLs."""
    return [w.strip() for w in config.DISCORD_WEBHOOKS if w and w.strip()]


# ── Platform detection + payload conversion ──────────────────────────────
# BUG FIX: the old _send_embed() always POSTed Discord's {"embeds": [...]}
# format to every configured URL. Discord understands that format fine, but
# Slack's Incoming Webhooks do NOT recognize "embeds" at all — a Slack URL
# dropped into one of the 5 slots would silently receive a payload it can't
# render (empty message or a 400 depending on Slack's validation), which is
# exactly the "only 1 slot works" symptom reported. Each URL is now
# inspected and sent in the format its own platform actually understands.

def _detect_platform(url: str) -> str:
    u = url.lower()
    if "discord.com/api/webhooks" in u or "discordapp.com/api/webhooks" in u:
        return "discord"
    if "hooks.slack.com" in u:
        return "slack"
    return "generic"


def _embed_to_slack_payload(embed: dict) -> dict:
    """Converts a Discord-style embed dict into Slack's legacy 'attachments'
    format, which Incoming Webhooks still render with the same colored
    sidebar + field layout as a Discord embed."""
    color_int = embed.get("color", 0)
    color_hex = f"#{color_int:06x}"
    slack_fields = [
        {"title": f["name"], "value": f["value"], "short": bool(f.get("inline", False))}
        for f in embed.get("fields", [])
    ]
    return {
        "attachments": [{
            "color":  color_hex,
            "title":  embed.get("title", ""),
            "fields": slack_fields,
            "footer": embed.get("footer", {}).get("text", ""),
        }]
    }


def _embed_to_generic_payload(embed: dict) -> dict:
    """For any URL that isn't recognized as Discord or Slack specifically —
    sends BOTH the Discord embed shape and the Slack attachment shape in
    one payload. Unknown/extra JSON keys are universally ignored by
    webhook receivers, so this maximizes the chance a custom endpoint
    (n8n, Zapier, a homegrown listener, etc.) finds a field it understands,
    the same dual-field approach used by Module 2's alert sender."""
    payload = {"embeds": [embed]}
    payload.update(_embed_to_slack_payload(embed))
    return payload


def _send_embed(embed: dict):
    """Sends one embed to every configured webhook, in each one's own
    correct format. Never raises — a failed webhook (bad URL, deleted
    channel, wrong platform) shouldn't crash the scan."""
    webhooks = _active_webhooks()
    if not webhooks:
        return

    for url in webhooks:
        platform = _detect_platform(url)
        if platform == "discord":
            payload = {"embeds": [embed]}
        elif platform == "slack":
            payload = _embed_to_slack_payload(embed)
        else:
            payload = _embed_to_generic_payload(embed)

        try:
            resp = requests.post(url, json=payload, timeout=6)
            if resp.status_code >= 300:
                print(f"⚠️ Webhook ({platform}) returned HTTP {resp.status_code} "
                      f"({url[:40]}...)")
        except Exception as e:
            print(f"⚠️ Webhook ({platform}) failed ({url[:40]}...): {e}")


def build_summary_embed(summary: dict) -> dict:
    if summary["critical_count"] > 0:
        color = RISK_COLORS["CRITICAL"]
    elif summary["high_count"] > 0:
        color = RISK_COLORS["HIGH"]
    elif summary["medium_count"] > 0:
        color = RISK_COLORS["MEDIUM"]
    elif summary["low_count"] > 0:
        color = RISK_COLORS["LOW"]
    else:
        color = RISK_COLORS["CLEAN"]

    return {
        "title": f"🛡️ Risk Scan Complete — {summary['domain']}",
        "color": color,
        "fields": [
            {"name": "🔴 Critical", "value": str(summary["critical_count"]), "inline": True},
            {"name": "🟠 High",     "value": str(summary["high_count"]),     "inline": True},
            {"name": "🟡 Medium",   "value": str(summary["medium_count"]),   "inline": True},
            {"name": "🟢 Low",      "value": str(summary["low_count"]),      "inline": True},
            {"name": "☠️ Actively Exploited (KEV)", "value": str(summary["kev_matches"]), "inline": True},
            {"name": "📊 Total Findings", "value": str(summary["total_findings"]), "inline": True},
        ],
        "footer": {"text": "Module 3 — Risk Scoring & CVE Matching Engine"},
    }


def build_finding_embed(finding: dict) -> dict:
    cves_text = "\n".join(
        f"• {c['cve_id']} (CVSS {c['cvss']}) — {', '.join(c.get('sources', ['NVD']))}"
        for c in finding["matched_cves"][:5]
    ) or "No specific CVE — flagged on exposure context alone"

    fields = [
        {"name": "🎯 Subdomain",  "value": finding["subdomain"], "inline": True},
        {"name": "⚙️ Technology", "value": f"{finding['technology']} {finding['version'] or ''}", "inline": True},
        {"name": "📈 Risk Score", "value": f"{finding['risk_score']}/100", "inline": True},
        {"name": "🔍 Matched CVEs", "value": cves_text[:1000], "inline": False},
    ]
    if finding.get("exposure_notes"):
        fields.append({"name": "⚠️ Exposure Context", "value": finding["exposure_notes"][:500], "inline": False})
    if finding.get("in_kev"):
        fields.append({"name": "☠️ CISA KEV", "value": "**ACTIVELY EXPLOITED IN THE WILD** — patch immediately", "inline": False})

    return {
        "title": f"[{finding['risk_level']}] Vulnerability Finding",
        "color": RISK_COLORS.get(finding["risk_level"], RISK_COLORS["INFO"]),
        "fields": fields,
        "footer": {"text": "Module 3 — Risk Scoring & CVE Matching Engine"},
    }


def send_alert(summary: dict):
    """
    Main entry point — call this after a scan completes.
    Sends: 1 summary embed + 1 embed per finding that meets DISCORD_ALERT_MIN_LEVEL,
    to every configured webhook (Discord, Slack, or generic — auto-detected per URL).
    """
    if not _active_webhooks():
        return  # no webhooks configured — nothing to do, not an error

    _send_embed(build_summary_embed(summary))

    alertable = [f for f in summary["findings"] if _meets_threshold(f["risk_level"])]
    for finding in alertable:
        _send_embed(build_finding_embed(finding))
