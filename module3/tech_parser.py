"""
Module 3 — Technology String Parser
=======================================
Converts Module 1's raw fingerprint strings (e.g. "Nginx 1.18.0",
"⚠ Missing HSTS", "WordPress", "jQuery") into structured
{product, version, raw} dicts that nvd_client / osv_client / vulners_client
can query CVE databases with.

Some strings Module 1 emits are NOT software+version at all — security
header warnings, or third-party services with no locally-hosted CVE
surface (Cloudflare, Stripe, Google Analytics, AWS S3 as a fingerprint
label) — those are filtered out here rather than wasting API calls on them.
"""
import re

# Strings to skip entirely — never worth a CVE lookup.
_SKIP_PATTERNS = [
    r"^⚠",                    # any "⚠ Missing ..." security-header warning
    r"^missing\s",
    r"^google analytics$",
    r"^stripe$",
    r"^cloudflare$",
    r"^aws s3$",
]
_SKIP_RE = re.compile("|".join(_SKIP_PATTERNS), re.IGNORECASE)

# Normalizes product name variants to match osv_client.ECOSYSTEM_MAP keys
# and generally tidy up spacing/capitalization Module 1 might produce.
_PRODUCT_ALIASES = {
    "express":       "express.js",
    "expressjs":     "express.js",
    "vue":           "vue.js",
    "vuejs":         "vue.js",
    "next":          "next.js",
    "nextjs":        "next.js",
    "nuxt":          "nuxt.js",
    "nuxtjs":        "nuxt.js",
    "rails":         "ruby on rails",
    "ruby on rails": "ruby on rails",
}

# Matches "Name 1.2.3", "Name v1.2.3" — the common formats Module 1's
# fingerprinting emits (e.g. "Apache 2.4.41", "Nginx 1.18.0", "PHP 7.4.3").
_VERSION_RE = re.compile(r"^(.+?)[\s/]v?(\d+(?:\.\d+){0,3}[\w\-]*)$")


def parse_one(raw: str) -> dict:
    """
    Parses a single technology string.
    Always returns a dict with product/version/raw keys.
    `product` is None when the string should be skipped entirely.
    """
    raw = (raw or "").strip()
    if not raw or _SKIP_RE.search(raw):
        return {"product": None, "version": None, "raw": raw}

    match = _VERSION_RE.match(raw)
    if match:
        product_raw = match.group(1).strip()
        version = match.group(2).strip()
    else:
        product_raw = raw
        version = None

    product_key = product_raw.lower().strip()
    product = _PRODUCT_ALIASES.get(product_key, product_key)

    return {"product": product, "version": version, "raw": raw}


def parse_all(technologies: list) -> list:
    """
    Parses a list of raw technology strings (Module 1's
    SubdomainResult.technologies) into a de-duplicated list of
    {product, version, raw} dicts, dropping entries that should be skipped.
    """
    seen = set()
    results = []
    for raw in (technologies or []):
        parsed = parse_one(raw)
        if not parsed["product"]:
            continue
        dedup_key = (parsed["product"], parsed["version"])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        results.append(parsed)
    return results
