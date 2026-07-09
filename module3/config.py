"""
Module 3 — Risk Scoring & CVE Matching Engine
Configuration
================================================
Sab settings yahan — env vars se override ho sakti hain.

╔══════════════════════════════════════════════════════════════╗
║  API KEYS YAHAN PASTE KARO (seedha quotes ke andar)            ║
╚══════════════════════════════════════════════════════════════╝
"""
import os

# ── NVD (National Vulnerability Database) API ───────────────────────────────
# Free, official US government CVE database. Works WITHOUT a key too:
#   - No key : 5 requests / rolling 30s window
#   - With key: 50 requests / rolling 30s window  (10x faster)
# Free key: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")          # ← 👈 apni NVD key yahan paste karo
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_WINDOW_SECONDS   = 30
NVD_MAX_REQ_NO_KEY   = 5
NVD_MAX_REQ_WITH_KEY = 50
NVD_REQUEST_TIMEOUT  = 25

# ── OSV.dev (Open Source Vulnerabilities — maintained by Google) ───────────
# Bilkul FREE, koi key/signup nahi chahiye. Open-source package ecosystems
# (npm, PyPI, Packagist, RubyGems, Go, crates.io) ke liye best coverage —
# NVD/Vulners se alag CVEs bhi mil jaate hain isse.
OSV_BASE_URL = "https://api.osv.dev/v1/query"
OSV_REQUEST_TIMEOUT = 20

# ── Vulners.com (aggregated CVE database + exploit-availability flag) ──────
# Free tier key: https://vulners.com/api-keys  (signup required)
VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY", "")   # ← 👈 apni Vulners key yahan paste karo
VULNERS_BASE_URL = "https://vulners.com/api/v3/burp/softwareapi/"
VULNERS_REQUEST_TIMEOUT = 20

# ── CISA KEV (Known Exploited Vulnerabilities) ───────────────────────────────
# Free, no key needed. Confirms a CVE is ACTIVELY exploited right now.
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_MAX_AGE = 12 * 60 * 60

# ── ALERT WEBHOOKS — up to 5+ slots, mix Discord + Slack + custom URLs ────
# Each URL is auto-detected by its domain and sent in ITS OWN correct
# format (discord.com/api/webhooks -> Discord embed, hooks.slack.com ->
# Slack attachment, anything else -> generic dual-format payload). You can
# freely mix platforms across the 5 slots below — all of them will work.
# Khali ("") wale automatically skip ho jaate hain. Jitni chahiye utni daalo.
DISCORD_WEBHOOKS = [
    os.environ.get("DISCORD_WEBHOOK_1", ""),   # ← 👈 slot #1 — Discord, Slack, or any URL
    os.environ.get("DISCORD_WEBHOOK_2", ""),   # ← 👈 slot #2
    os.environ.get("DISCORD_WEBHOOK_3", ""),   # ← 👈 slot #3
    os.environ.get("DISCORD_WEBHOOK_4", ""),   # ← 👈 slot #4
    os.environ.get("DISCORD_WEBHOOK_5", ""),   # ← 👈 slot #5
]
# Sirf isi level ya usse zyada severe findings hi Discord pe jaayengi:
DISCORD_ALERT_MIN_LEVEL = "HIGH"   # options: CRITICAL, HIGH, MEDIUM, LOW, INFO

# ── Local cache (avoids re-querying CVE sources for same product+version) ──
CACHE_DB_PATH   = os.environ.get("MODULE3_CACHE_DB", "module3_cache.db")
CVE_CACHE_TTL   = 7 * 24 * 60 * 60   # 7 days

# ── Risk scoring weights ─────────────────────────────────────────────────────
# Final score (0-100) = weighted combination of these factors.
WEIGHTS = {
    "cvss_base":        0.45,   # highest CVSS among matched CVEs
    "kev_bonus":         25,    # flat points added if ANY matched CVE is in CISA KEV
    "exposure_context":  0.20,  # how exposed is the asset (admin panel, db port, etc.)
    "asset_criticality": 0.15,  # prod/api/admin subdomains weigh more than dev/staging
    "cve_count_bonus":   0.20,  # more matched CVEs = slightly higher risk
}

# Exposure context scores (0-10) based on what Module 1/2.5 detected
EXPOSURE_SCORES = {
    "admin_panel_public":     10,
    "database_port_open":     10,
    "git_exposed":            10,
    "env_file_exposed":       10,
    "backup_file_exposed":     9,
    "docker_api_open":        10,
    "outdated_tls":            5,
    "missing_security_headers":3,
    "directory_listing":       6,
    "default":                 2,
}

# Asset criticality by subdomain naming pattern (simple heuristic)
CRITICALITY_PATTERNS = {
    "prod":     10, "www":  9, "api":   9, "admin": 10, "portal": 8,
    "payment":  10, "auth": 10, "sso":  9, "vpn":    9, "db":     10,
    "staging":   4, "dev":  3, "test":  3, "qa":     3, "demo":   3,
    "internal":  6, "backup": 7,
}
DEFAULT_CRITICALITY = 5

# Risk level bands (0-100 composite score)
RISK_BANDS = [
    (85, "CRITICAL"),
    (65, "HIGH"),
    (40, "MEDIUM"),
    (15, "LOW"),
    (0,  "INFO"),
]

USER_AGENT = "Mozilla/5.0 (compatible; ASM-Module3-RiskEngine/1.0)"
OUTPUT_DIR = "module3_reports"
