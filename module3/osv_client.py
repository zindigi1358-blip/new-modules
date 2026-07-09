"""
Module 3 — OSV.dev Client (Open Source Vulnerabilities)
===========================================================
Maintained by Google: https://osv.dev — fully free, no API key/signup at all.

Best coverage for open-source PACKAGE ecosystems (npm, PyPI, Packagist,
RubyGems, Go, crates.io) — often has CVEs that NVD hasn't indexed yet,
since maintainers report straight to OSV.

Limitation (honest): OSV is ecosystem-based, so it works well for things
like "Django 4.1" (PyPI) or "Express 4.17" (npm), but has no data for
non-package software like raw Nginx/Apache binaries — those stay covered
by NVD instead. This module returns an empty list gracefully in that case,
it does not error out.
"""
import math
import requests

import config          # `import config` (module reference, not `from config
                        # import X`) — kept consistent with nvd_client.py so
                        # none of these values go stale if ever overridden
                        # after this module is first imported.
import database as db

# Best-effort mapping: product name (as parsed by tech_parser) -> OSV ecosystem
# Extend this table any time you notice a product OSV should cover.
ECOSYSTEM_MAP = {
    "django":          "PyPI",
    "flask":           "PyPI",
    "requests":        "PyPI",
    "express.js":      "npm",
    "vue.js":          "npm",
    "react":           "npm",
    "angular":         "npm",
    "next.js":         "npm",
    "nuxt.js":         "npm",
    "laravel":         "Packagist",
    "symfony":         "Packagist",
    "wordpress":       "Packagist",   # some WP core/plugin CVEs are indexed under Packagist mirrors
    "ruby on rails":   "RubyGems",
    "jekyll":          "RubyGems",
}


# ── CVSS v3.x vector -> base score calculator ────────────────────────────────
# BUG FIX: OSV's severity[].score field for type "CVSS_V3" is the FULL VECTOR
# STRING (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), not a bare
# number. The old code did `float(vector_string)`, which always raised
# ValueError, was silently swallowed, and left cvss=0.0 for every single
# OSV-sourced finding — undercutting the entire point of including OSV
# (surfacing CVEs NVD hasn't indexed yet, now permanently scored as harmless).
# This implements the official FIRST.org CVSS v3.1 base-score formula so
# OSV-only findings get their real severity instead of a silent zero.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss_roundup(value: float) -> float:
    """Official CVSS spec 'round up to nearest 0.1' — avoids float precision
    issues from naive round()/ceil() on values like 4.0000000001."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (math.floor(int_value / 10000) + 1) / 10.0


def _parse_cvss_vector(value: str) -> float:
    """
    Computes a CVSS v3.x Base Score from a vector string, e.g.
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8

    Falls back to treating `value` as an already-numeric score if it
    doesn't look like a vector string, so this stays correct even if a
    future OSV record (or a different ecosystem) provides a bare number
    instead. Never raises — returns 0.0 on anything unparseable.
    """
    if not value:
        return 0.0
    value = str(value).strip()

    if not value.startswith("CVSS:"):
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    try:
        parts = {}
        for segment in value.split("/"):
            if ":" not in segment:
                continue
            key, val = segment.split(":", 1)
            parts[key] = val

        scope = parts.get("S")
        pr_table = _PR_CHANGED if scope == "C" else _PR_UNCHANGED

        av = _AV.get(parts.get("AV"))
        ac = _AC.get(parts.get("AC"))
        ui = _UI.get(parts.get("UI"))
        pr = pr_table.get(parts.get("PR"))
        c  = _CIA.get(parts.get("C"))
        i  = _CIA.get(parts.get("I"))
        a  = _CIA.get(parts.get("A"))

        if scope not in ("U", "C") or None in (av, ac, ui, pr, c, i, a):
            return 0.0  # incomplete/unrecognized vector — fail safe, not crash

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui

        if scope == "U":
            return _cvss_roundup(min(impact + exploitability, 10.0))
        return _cvss_roundup(min(1.08 * (impact + exploitability), 10.0))
    except Exception:
        return 0.0  # never let a malformed vector crash the scan


def query_osv(product: str, version: str = None) -> list:
    """
    Returns list of {cve_id, cvss, summary, url, source} — same shape as
    nvd_client so risk_engine can merge them transparently. Returns []
    (not an error) if the product has no known OSV ecosystem mapping.
    """
    if not product:
        return []

    ecosystem = ECOSYSTEM_MAP.get(product.lower())
    if not ecosystem:
        return []  # not a package-ecosystem product — OSV has no data path for this

    query_key = f"osv|{product}|{version or ''}"
    cached = db.get_cached_cves(query_key)
    if cached is not None:
        return cached

    body = {"package": {"name": product, "ecosystem": ecosystem}}
    if version:
        body["version"] = version

    try:
        resp = requests.post(
            config.OSV_BASE_URL, json=body,
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.OSV_REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        return []
    except Exception:
        return []

    if resp.status_code != 200:
        return []

    try:
        data = resp.json()
    except Exception:
        return []

    results = []
    for vuln in data.get("vulns", []):
        osv_id = vuln.get("id", "")
        if not osv_id:
            continue

        # OSV aliases often include the matching CVE ID — prefer that for
        # cross-source deduplication with NVD/Vulners; fall back to OSV's
        # own ID (e.g. "GHSA-xxxx") if no CVE alias exists.
        cve_id = osv_id
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        cvss = 0.0
        for severity in vuln.get("severity", []):
            if severity.get("type") == "CVSS_V3":
                cvss = _parse_cvss_vector(severity.get("score", ""))
                break

        results.append({
            "cve_id":  cve_id,
            "cvss":    cvss,
            "summary": (vuln.get("summary") or vuln.get("details", ""))[:300],
            "url":     f"https://osv.dev/vulnerability/{osv_id}",
            "source":  "OSV.dev",
        })

    results.sort(key=lambda x: x["cvss"], reverse=True)
    db.set_cached_cves(query_key, results)
    return results
