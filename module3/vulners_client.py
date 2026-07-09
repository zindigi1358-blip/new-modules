"""
Module 3 — Vulners.com Client
================================
Aggregated vulnerability database: https://vulners.com
Free tier key required: https://vulners.com/api-keys

Uses Vulners' "Software API" (the same endpoint the official Burp Suite
Vulners plugin uses) — you give it a software name + version, it returns
matching CVEs. Also flags whether Vulners has indexed a PUBLIC reference
to an exploit for that CVE (informational flag only — this module never
fetches or displays exploit code itself, just a yes/no risk signal similar
to CISA KEV).
"""
import requests
import config
import database as db


def query_vulners(product: str, version: str = None) -> list:
    """
    Returns list of {cve_id, cvss, summary, url, exploit_available} —
    same base shape as nvd_client/osv_client for easy merging.
    Returns [] gracefully if no API key is configured or the request fails.
    """
    if not product:
        return []
    if not config.VULNERS_API_KEY:
        return []  # no key configured — skip silently, NVD/OSV still cover this

    query_key = f"vulners|{product}|{version or ''}"
    cached = db.get_cached_cves(query_key)
    if cached is not None:
        return cached

    params = {
        "software": product,
        "version":  version or "",
        "type":     "software",
        "apiKey":   config.VULNERS_API_KEY,
    }

    try:
        resp = requests.get(
            config.VULNERS_BASE_URL, params=params,
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.VULNERS_REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        return []
    except Exception:
        return []

    if resp.status_code == 401:
        return []  # invalid/expired key — fail silently, other sources still work
    if resp.status_code != 200:
        return []

    try:
        data = resp.json()
    except Exception:
        return []

    # Vulners' v3 software API returns results under data.search[]
    search_results = data.get("data", {}).get("search", [])

    results = []
    for item in search_results:
        source = item.get("_source", {})
        vuln_id = source.get("id", "") or source.get("cvelist", [""])[0]
        if not vuln_id:
            continue

        # Prefer the actual CVE ID if Vulners lists one, for cross-source dedup
        cve_list_field = source.get("cvelist", [])
        cve_id = cve_list_field[0] if cve_list_field else vuln_id

        cvss = 0.0
        cvss_data = source.get("cvss", {})
        if isinstance(cvss_data, dict):
            cvss = float(cvss_data.get("score", 0.0) or 0.0)

        # Exploit availability — informational signal only (mirrors what
        # KEV does for NVD matches), no exploit code is fetched or shown.
        exploit_available = bool(source.get("exploitCount", 0)) or "exploit" in (source.get("type", "") or "").lower()

        results.append({
            "cve_id":  cve_id,
            "cvss":    cvss,
            "summary": (source.get("description") or source.get("title", ""))[:300],
            "url":     f"https://vulners.com/{source.get('bulletinFamily', 'cve').lower()}/{vuln_id}",
            "source":  "Vulners",
            "exploit_available": exploit_available,
        })

    results.sort(key=lambda x: x["cvss"], reverse=True)
    db.set_cached_cves(query_key, results)
    return results
