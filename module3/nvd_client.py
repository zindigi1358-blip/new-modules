"""
Module 3 — NVD (National Vulnerability Database) Client
===========================================================
Official US government CVE database: https://nvd.nist.gov
Free, no key required (but a free key gives 10x the rate limit).

This module ONLY reads public vulnerability metadata (CVE ID, CVSS score,
description) — it does not generate or fetch exploit code.
"""
import re
import time
import threading
import requests

import config          # `import config` (not `from config import X`) so every
                        # call below reads config.NVD_API_KEY etc. FRESH, even
                        # if it gets set after this module was first imported
                        # (e.g. via --nvd-key or a config.py edit read later).
import database as db


class RateLimiter:
    """Sliding-window rate limiter — recomputes its own limit every call
    based on whether an API key is currently configured, so it stays
    correct even if the key gets set after this module was imported."""
    def __init__(self):
        self.timestamps = []
        self.lock       = threading.Lock()

    def wait_if_needed(self):
        max_requests = config.NVD_MAX_REQ_WITH_KEY if config.NVD_API_KEY else config.NVD_MAX_REQ_NO_KEY
        with self.lock:
            now = time.time()
            self.timestamps = [t for t in self.timestamps if now - t < config.NVD_WINDOW_SECONDS]
            if len(self.timestamps) >= max_requests:
                sleep_for = config.NVD_WINDOW_SECONDS - (now - self.timestamps[0]) + 0.5
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.time()
                self.timestamps = [t for t in self.timestamps if now - t < config.NVD_WINDOW_SECONDS]
            self.timestamps.append(time.time())


_limiter = RateLimiter()


def _extract_cvss(cve_item: dict) -> float:
    """
    NVD 2.0 API can return CVSS v3.1, v3.0, or v2 metrics — try in order
    of preference. Wrapped defensively so one malformed/incomplete CVE
    record never crashes the whole scan.
    """
    metrics = cve_item.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError, IndexError):
                continue
    return 0.0


def _extract_summary(cve_item: dict) -> str:
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")[:300]
    return ""


# ── Version-range filtering ───────────────────────────────────────────────
# BUG FIX: NVD's `keywordSearch` param is a plain FULL-TEXT search over CVE
# descriptions — it has ZERO awareness of which software versions a CVE
# actually affects. Searching "nginx 1.24.0" would return every CVE that
# ever mentions "nginx" anywhere in its text, including CVEs from 2013-2015
# that only affect nginx 1.0-1.4 — long since patched — while the tool kept
# reporting them as if they applied to whatever current version was
# actually detected. This was reported as: "purana CVE dikhata tha jo tha
# hi nahi, aur jis version mein woh already fix ho chuka tha usko bhi flag
# kar raha tha."
#
# Fix: each CVE record includes `configurations` -> CPE match entries with
# real version ranges (versionStartIncluding/Excluding, versionEndIncluding/
# Excluding). We now parse those ranges and only keep a CVE if the detected
# version actually falls inside them. If NVD provides no version data for a
# CVE at all, we keep it (fail permissive — a security tool should risk one
# extra finding to manually check rather than silently hide a real one).

def _parse_version_tuple(v: str, length: int = 6) -> tuple:
    """'1.24.0' -> (1,24,0,0,0,0) — fixed-length so 1.2 and 1.2.0 compare equal."""
    parts = []
    for chunk in re.split(r"[.\-_+]", v or ""):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group()) if m else 0)
        if len(parts) >= length:
            break
    while len(parts) < length:
        parts.append(0)
    return tuple(parts[:length])


def _version_in_range(version: str, start_inc, start_exc, end_inc, end_exc) -> bool:
    v = _parse_version_tuple(version)
    if start_inc and v < _parse_version_tuple(start_inc):
        return False
    if start_exc and v <= _parse_version_tuple(start_exc):
        return False
    if end_inc and v > _parse_version_tuple(end_inc):
        return False
    if end_exc and v >= _parse_version_tuple(end_exc):
        return False
    return True


def _is_version_affected(cve_item: dict, product: str, version: str) -> bool:
    """
    Returns False only when NVD's CPE data POSITIVELY shows this version is
    outside every known-affected range for this product (the false-positive
    case being fixed). Returns True whenever there's no CPE data to check,
    or the version genuinely falls inside an affected range.
    """
    if not version:
        return True  # nothing to filter against

    configs = cve_item.get("configurations", [])
    if not configs:
        return True  # NVD gave us no CPE data for this CVE — can't filter, keep it

    found_product_cpe = False
    any_matched = False

    for config_block in configs:
        for node in config_block.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", True):
                    continue
                criteria = cpe_match.get("criteria", "")
                if product.lower() not in criteria.lower():
                    continue
                found_product_cpe = True

                start_inc = cpe_match.get("versionStartIncluding")
                start_exc = cpe_match.get("versionStartExcluding")
                end_inc   = cpe_match.get("versionEndIncluding")
                end_exc   = cpe_match.get("versionEndExcluding")

                if not any([start_inc, start_exc, end_inc, end_exc]):
                    # No explicit range — the CPE criteria string may itself
                    # pin an exact version (5th colon-separated field).
                    cpe_parts = criteria.split(":")
                    if len(cpe_parts) > 5 and cpe_parts[5] not in ("*", "-", ""):
                        if _parse_version_tuple(cpe_parts[5]) == _parse_version_tuple(version):
                            any_matched = True
                        continue
                    any_matched = True  # no version constraint at all -> applies to any version
                    continue

                if _version_in_range(version, start_inc, start_exc, end_inc, end_exc):
                    any_matched = True

    if not found_product_cpe:
        return True  # couldn't locate product-specific CPE data — keep permissively

    return any_matched


def query_nvd(product: str, version: str = None, results_limit: int = 10) -> list:
    """
    Queries NVD using keyword search (product name, optionally + version),
    then filters results to only CVEs whose CPE version range actually
    covers the detected version. Returns a list of {cve_id, cvss, summary,
    url} dicts, sorted by CVSS descending.
    """
    if not product:
        return []

    query_key = f"{product}|{version or ''}"
    cached = db.get_cached_cves(query_key)
    if cached is not None:
        return cached

    keyword = f"{product} {version}" if version else product
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_limit * 3,  # over-fetch since some will be filtered out below
    }
    headers = {"User-Agent": config.USER_AGENT}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    _limiter.wait_if_needed()

    try:
        resp = requests.get(config.NVD_BASE_URL, params=params, headers=headers,
                            timeout=config.NVD_REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        return []
    except Exception:
        return []

    if resp.status_code == 429:
        time.sleep(config.NVD_WINDOW_SECONDS)
        try:
            resp = requests.get(config.NVD_BASE_URL, params=params, headers=headers,
                                timeout=config.NVD_REQUEST_TIMEOUT)
        except Exception:
            return []

    if resp.status_code != 200:
        return []

    try:
        data = resp.json()
    except Exception:
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        cve_id   = cve_item.get("id", "")
        if not cve_id:
            continue

        # BUG FIX: reject CVEs whose CPE version range doesn't cover what
        # we actually detected, instead of trusting NVD's free-text match.
        if not _is_version_affected(cve_item, product, version):
            continue

        results.append({
            "cve_id":  cve_id,
            "cvss":    _extract_cvss(cve_item),
            "summary": _extract_summary(cve_item),
            "url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    results.sort(key=lambda x: x["cvss"], reverse=True)
    results = results[:results_limit]

    db.set_cached_cves(query_key, results)
    return results
