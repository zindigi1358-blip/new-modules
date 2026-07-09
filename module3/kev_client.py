"""
Module 3 — CISA KEV (Known Exploited Vulnerabilities) Client
================================================================
Free, official US government feed — no API key ever needed:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Confirms whether a matched CVE is CURRENTLY being exploited in the wild —
one of the strongest real-world prioritization signals available. A CVSS
9.8 sitting unexploited matters less right now than a 6.5 under active
attack, which is why risk_engine.py gives KEV membership a flat +25 point
bonus regardless of the underlying CVSS score.
"""
import time
import requests

import config
import database as db


def refresh_kev_cache() -> int:
    """
    Downloads the CISA KEV catalog if the local cache is older than
    config.KEV_CACHE_MAX_AGE (default 12h).

    Returns:
        -1   cache already fresh, nothing downloaded
         N   downloaded successfully, N vulnerabilities now cached
         0   download/parse failed — caller continues the scan without
             KEV enrichment rather than aborting entirely
    """
    catalog, fetched_at = db.load_kev_catalog()
    if catalog is not None and (time.time() - fetched_at) < config.KEV_CACHE_MAX_AGE:
        return -1  # still fresh, no need to hit the network

    try:
        resp = requests.get(
            config.KEV_FEED_URL,
            headers={"User-Agent": config.USER_AGENT},
            timeout=20,
        )
    except requests.exceptions.Timeout:
        return 0
    except Exception:
        return 0

    if resp.status_code != 200:
        return 0

    try:
        data = resp.json()
    except Exception:
        return 0

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return 0

    # Index by CVE ID for O(1) lookup during enrichment
    kev_map = {}
    for v in vulnerabilities:
        cve_id = v.get("cveID", "")
        if not cve_id:
            continue
        kev_map[cve_id] = {
            "date_added":         v.get("dateAdded", ""),
            "due_date":           v.get("dueDate", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "required_action":    v.get("requiredAction", ""),
        }

    db.save_kev_catalog(kev_map)
    return len(kev_map)


def enrich_with_kev(cve_list: list) -> tuple:
    """
    Checks each CVE in a merged list against the cached CISA KEV catalog.
    Attaches a "kev" dict to any matching entry (date_added, due_date, etc.)
    and returns (updated_list, any_in_kev: bool).

    Fails safe: if the KEV cache hasn't been populated yet (e.g. the very
    first run, before refresh_kev_cache() has ever succeeded), this returns
    the list unchanged with in_kev=False rather than raising.
    """
    catalog, _ = db.load_kev_catalog()
    if not catalog:
        return cve_list, False

    any_in_kev = False
    for cve in cve_list:
        cve_id = cve.get("cve_id", "")
        kev_entry = catalog.get(cve_id)
        if kev_entry:
            cve["kev"] = kev_entry
            any_in_kev = True

    return cve_list, any_in_kev
