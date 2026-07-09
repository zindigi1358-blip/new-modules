"""
Module 3 — SQLite Persistence Layer
=======================================
Two jobs:
  1. Cache CVE lookup results (7-day TTL) so re-scanning the same domain
     doesn't re-hit NVD/OSV/Vulners for every tech string every time.
  2. Store the CISA KEV catalog + every finding, for history/audit.

Thread-safety: run_module3.py uses a ThreadPoolExecutor, so multiple threads
call these functions concurrently. SQLite connections are NOT safe to share
across threads — each thread gets its own connection (thread-local storage),
and the database file is opened in WAL mode so readers/writer don't block
each other as much as the default rollback-journal mode would.
"""
import sqlite3
import json
import time
import threading

import config

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """One SQLite connection per thread — created lazily on first use."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(config.CACHE_DB_PATH, timeout=30)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass  # older SQLite / unusual filesystem — safe to continue without WAL
        _local.conn = conn
    return conn


def init_db():
    """Creates all tables if they don't already exist. Safe to call every run."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            query_key    TEXT PRIMARY KEY,
            results_json TEXT NOT NULL,
            cached_at    REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kev_catalog (
            id           INTEGER PRIMARY KEY CHECK (id = 1),
            catalog_json TEXT NOT NULL,
            fetched_at   REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        TEXT,
            domain         TEXT,
            subdomain      TEXT,
            technology     TEXT,
            version        TEXT,
            cve_list_json  TEXT,
            in_kev         INTEGER,
            risk_score     REAL,
            risk_level     TEXT,
            exposure_notes TEXT,
            created_at     REAL
        )
    """)
    conn.commit()


# ─────────────────────────────────────────────
# CVE lookup cache (used by nvd_client / osv_client / vulners_client)
# ─────────────────────────────────────────────

def get_cached_cves(query_key: str):
    """
    Returns the cached list if present and not expired, else None
    (None specifically means "go query the live API").
    An empty list [] is a valid, meaningful cached result (product
    genuinely has no known CVEs) and is returned as-is, not re-queried.
    """
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT results_json, cached_at FROM cve_cache WHERE query_key = ?",
            (query_key,),
        ).fetchone()
        if row is None:
            return None
        results_json, cached_at = row
        if time.time() - cached_at > config.CVE_CACHE_TTL:
            return None  # expired — treat as a cache miss
        return json.loads(results_json)
    except Exception:
        return None  # any cache read problem should never block a live query


def set_cached_cves(query_key: str, results: list):
    """Best-effort cache write — a failure here must never break a scan."""
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (query_key, results_json, cached_at) "
            "VALUES (?, ?, ?)",
            (query_key, json.dumps(results), time.time()),
        )
        conn.commit()
    except Exception as e:
        print(f"⚠️  Could not cache CVE results for '{query_key}': {e}")


# ─────────────────────────────────────────────
# Findings history (used by run_module3.py)
# ─────────────────────────────────────────────

def save_finding(scan_id: str, domain: str, subdomain: str, technology: str,
                  version: str, cve_list: list, in_kev: bool,
                  risk_score: float, risk_level: str, exposure_notes: str):
    """Persists one finding row. Failure here is logged but never fatal —
    the JSON report file is always the primary source of truth."""
    try:
        conn = _get_conn()
        conn.execute(
            """INSERT INTO findings
               (scan_id, domain, subdomain, technology, version,
                cve_list_json, in_kev, risk_score, risk_level,
                exposure_notes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, domain, subdomain, technology, version,
             json.dumps(cve_list), int(bool(in_kev)), risk_score, risk_level,
             exposure_notes, time.time()),
        )
        conn.commit()
    except Exception as e:
        print(f"⚠️  Could not save finding to database: {e}")


# ─────────────────────────────────────────────
# CISA KEV catalog storage (used by kev_client.py)
# ─────────────────────────────────────────────

def load_kev_catalog():
    """Returns (catalog_dict, fetched_at_timestamp) or (None, 0) if never cached."""
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT catalog_json, fetched_at FROM kev_catalog WHERE id = 1"
        ).fetchone()
        if row is None:
            return None, 0
        return json.loads(row[0]), row[1]
    except Exception:
        return None, 0


def save_kev_catalog(catalog: dict):
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO kev_catalog (id, catalog_json, fetched_at) "
            "VALUES (1, ?, ?)",
            (json.dumps(catalog), time.time()),
        )
        conn.commit()
    except Exception as e:
        print(f"⚠️  Could not save KEV catalog: {e}")
