"""
Module 5 — FastAPI Backend Server
====================================
Production-ready REST API that bridges the browser dashboard to
Modules 1, 2, 3, and 4. Designed to run on the same Ubuntu server.

Start:
    pip3 install fastapi uvicorn aiofiles python-multipart
    python3 main.py

API base: http://localhost:8000/api/v1
Docs:     http://localhost:8000/docs   (Swagger UI)

Architecture:
    browser ←→ FastAPI (this file) ←→ modules 1/2/3/4 (subprocess)
                                    ←→ SQLite (state + findings)
                                    ←→ Webhooks (Discord/Slack)
"""

import asyncio
import json
import os
import subprocess
import sys
import time
import uuid
import hashlib
import hmac
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# ─────────────────────────────────────────────
# Config — edit these paths to match your server
# ─────────────────────────────────────────────

BASE_DIR       = Path(__file__).resolve().parent.parent
MODULE1_DIR    = BASE_DIR / "module1"
MODULE2_DIR    = BASE_DIR / "module2"
MODULE2_5_DIR  = BASE_DIR / "module2_5"
MODULE3_DIR    = BASE_DIR / "module3"
MODULE4_DIR    = BASE_DIR / "module4"

REPORTS_DIR    = BASE_DIR / "module1" / "reports"
LEAKS_DIR      = BASE_DIR / "module2_5" / "module2_5_reports"
RISK_DIR       = BASE_DIR / "module3" / "module3_reports"
PDF_DIR        = BASE_DIR / "module4" / "pdf_reports"
DB_PATH        = BASE_DIR / "module5_state.db"

# API key settings — override via environment
API_KEY_SECRET = os.getenv("SENTINEL_API_SECRET", "change-me-in-production")

# CORS — add your dashboard URL here
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "*",  # remove in production, add specific origins instead
]

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS orgs (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            created_at  REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL,
            name        TEXT NOT NULL,
            key_prefix  TEXT NOT NULL,
            key_hash    TEXT NOT NULL,
            scopes      TEXT NOT NULL,  -- JSON list
            created_at  REAL NOT NULL,
            last_used   REAL,
            FOREIGN KEY (org_id) REFERENCES orgs(id)
        );

        CREATE TABLE IF NOT EXISTS domains (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL,
            domain      TEXT NOT NULL,
            added_at    REAL NOT NULL,
            UNIQUE(org_id, domain)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id            TEXT PRIMARY KEY,
            org_id        TEXT NOT NULL,
            domain        TEXT NOT NULL,
            scan_type     TEXT NOT NULL DEFAULT 'full',
            status        TEXT NOT NULL DEFAULT 'queued',
            progress      INTEGER NOT NULL DEFAULT 0,
            phase         TEXT NOT NULL DEFAULT 'queued',
            started_at    REAL,
            completed_at  REAL,
            report_path   TEXT,
            findings_count INTEGER DEFAULT 0,
            subdomains     INTEGER DEFAULT 0,
            alive          INTEGER DEFAULT 0,
            error_msg      TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id             TEXT PRIMARY KEY,
            org_id         TEXT NOT NULL,
            scan_id        TEXT NOT NULL,
            domain         TEXT NOT NULL,
            subdomain      TEXT NOT NULL,
            severity       TEXT NOT NULL,
            finding_type   TEXT NOT NULL,
            technology     TEXT,
            version        TEXT,
            cve_id         TEXT,
            risk_score     REAL NOT NULL DEFAULT 0,
            in_kev         INTEGER NOT NULL DEFAULT 0,
            status         TEXT NOT NULL DEFAULT 'open',
            description    TEXT,
            evidence       TEXT,
            remediation    TEXT,
            detected_at    REAL NOT NULL,
            resolved_at    REAL
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL,
            title       TEXT NOT NULL,
            body        TEXT NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'info',
            read        INTEGER NOT NULL DEFAULT 0,
            created_at  REAL NOT NULL
        );

        INSERT OR IGNORE INTO orgs (id, name, created_at)
        VALUES ('org_default', 'OrgSpace Inc', unixepoch());

        INSERT OR IGNORE INTO api_keys
            (id, org_id, name, key_prefix, key_hash, scopes, created_at)
        VALUES ('key_demo', 'org_default', 'Demo key', 'sk_live_demo',
                'demo_hash', '["scan:read","findings:read"]', unixepoch());
    """)
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────

def hash_key(raw: str) -> str:
    return hmac.new(API_KEY_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()


def verify_api_key(authorization: str = Header(None)) -> dict:
    """
    Bearer token auth — validates against api_keys table.
    In dev mode, accept the literal string 'dev' for testing.
    """
    if authorization == "Bearer dev":
        return {"org_id": "org_default", "scopes": ["*"]}

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    raw_key = authorization.removeprefix("Bearer ").strip()
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?",
            (hash_key(raw_key),)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        conn.execute(
            "UPDATE api_keys SET last_used = ? WHERE id = ?",
            (time.time(), row["id"])
        )
        conn.commit()
        return {"org_id": row["org_id"], "scopes": json.loads(row["scopes"])}
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str
    scan_type: str = Field("full", pattern="^(full|quick|ports|leaks|cve)$")
    github_token: Optional[str] = None
    no_ports: bool = False
    no_cloud: bool = False
    no_github: bool = False


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|in_review|accepted|resolved|false_positive)$")


class ApiKeyCreate(BaseModel):
    name: str
    scopes: List[str] = ["scan:read", "findings:read"]


class DomainAdd(BaseModel):
    domain: str


class ReportRequest(BaseModel):
    scan_id: str
    client_name: str = "Client"
    assessor_name: str = "Sentinel ASM"
    classification: str = "Confidential"
    include_executive_summary: bool = True
    include_technical_findings: bool = True
    include_remediation: bool = True
    include_appendix: bool = False

# ─────────────────────────────────────────────
# Background scan runner
# ─────────────────────────────────────────────

async def _run_scan(scan_id: str, domain: str, request: ScanRequest, org_id: str):
    """
    Runs Module 1 → Module 2.5 → Module 3 in sequence.
    Updates the scans table with live progress so the dashboard can poll it.
    """
    conn = get_db()
    report_path = None

    def update(phase: str, progress: int, **kwargs):
        conn.execute(
            "UPDATE scans SET phase=?, progress=?, started_at=COALESCE(started_at,?) WHERE id=?",
            (phase, progress, time.time(), scan_id)
        )
        for k, v in kwargs.items():
            conn.execute(f"UPDATE scans SET {k}=? WHERE id=?", (v, scan_id))
        conn.commit()

    try:
        # ── Phase 1: Module 1 — Asset Discovery
        update("subdomain_enumeration", 5)
        cmd1 = [
            sys.executable,
            str(MODULE1_DIR / "run.py"),
            "--domain", domain,
            "--output-dir", str(REPORTS_DIR),
            "--confirm",
        ]
        if request.github_token:
            cmd1 += ["--github-token", request.github_token]
        if request.no_ports:
            cmd1.append("--no-ports")
        if request.no_cloud:
            cmd1.append("--no-cloud")
        if request.no_github:
            cmd1.append("--no-github")

        proc1 = await asyncio.create_subprocess_exec(
            *cmd1,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(MODULE1_DIR),
        )
        stdout1, _ = await proc1.communicate()
        if proc1.returncode != 0:
            raise RuntimeError(f"Module 1 failed: {stdout1.decode()[-800:]}")
        update("port_scanning", 35)

        # Find the report file Module 1 just wrote
        report_files = sorted(REPORTS_DIR.glob(f"{domain}_*.json"), key=lambda p: p.stat().st_mtime)
        if not report_files:
            raise RuntimeError("Module 1 completed but no report file found")
        report_path = str(report_files[-1])

        # Read basic stats from Module 1 output
        with open(report_path) as f:
            m1data = json.load(f)
        subdomains = m1data.get("total_subdomains", 0)
        alive      = m1data.get("alive_subdomains", 0)
        update("port_scanning", 55, subdomains=subdomains, alive=alive, report_path=report_path)

        # ── Phase 2: Module 2.5 — Leak Scanner
        leaks_path = None
        update("leak_scanning", 65)
        m25_script = MODULE2_5_DIR / "run_module2_5.py"
        if m25_script.exists():
            leaks_out = LEAKS_DIR / f"{domain}_leaks_{int(time.time())}.json"
            leaks_out.parent.mkdir(parents=True, exist_ok=True)
            cmd25 = [
                sys.executable, str(m25_script),
                "--report", report_path,
                "--output", str(leaks_out),
                "--confirm",
            ]
            proc25 = await asyncio.create_subprocess_exec(
                *cmd25,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(MODULE2_5_DIR),
            )
            await proc25.communicate()
            if leaks_out.exists():
                leaks_path = str(leaks_out)
        update("cve_correlation", 75)

        # ── Phase 3: Module 3 — Risk Scoring + CVE
        risk_path = None
        m3_script = MODULE3_DIR / "run_module3.py"
        if m3_script.exists():
            risk_out_dir = RISK_DIR
            risk_out_dir.mkdir(parents=True, exist_ok=True)
            cmd3 = [
                sys.executable, str(m3_script),
                "--report", report_path,
                "--output-dir", str(risk_out_dir),
            ]
            if leaks_path:
                cmd3 += ["--leaks", leaks_path]
            proc3 = await asyncio.create_subprocess_exec(
                *cmd3,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(MODULE3_DIR),
            )
            await proc3.communicate()
            risk_files = sorted(risk_out_dir.glob(f"{domain}_risk_*.json"),
                                key=lambda p: p.stat().st_mtime)
            if risk_files:
                risk_path = str(risk_files[-1])
        update("finalizing", 92)

        # ── Ingest findings into our DB
        findings_count = 0
        if risk_path and Path(risk_path).exists():
            with open(risk_path) as f:
                rdata = json.load(f)
            for item in rdata.get("findings", []):
                fid = f"f_{uuid.uuid4().hex[:12]}"
                conn.execute("""
                    INSERT OR IGNORE INTO findings
                    (id, org_id, scan_id, domain, subdomain, severity,
                     finding_type, technology, version, cve_id, risk_score,
                     in_kev, status, description, detected_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    fid, org_id, scan_id, domain,
                    item.get("subdomain", domain),
                    item.get("risk_level", "INFO").upper(),
                    item.get("exposure_notes", "")[:50] or "vulnerability",
                    item.get("technology"),
                    item.get("version"),
                    (item.get("matched_cves") or [{}])[0].get("cve_id"),
                    item.get("risk_score", 0),
                    int(item.get("in_kev", False)),
                    "open",
                    item.get("matched_cves", [{}])[0].get("summary", ""),
                    time.time(),
                ))
                findings_count += 1
            conn.commit()

        # ── Done
        conn.execute("""
            UPDATE scans
            SET status='completed', phase='done', progress=100,
                completed_at=?, findings_count=?, report_path=?
            WHERE id=?
        """, (time.time(), findings_count, report_path, scan_id))
        conn.commit()

        # Notify
        _add_notification(conn, org_id,
            title=f"Scan complete — {domain}",
            body=f"{subdomains} subdomains · {alive} alive · {findings_count} findings",
            severity="info" if findings_count == 0 else "warning",
        )

    except Exception as exc:
        conn.execute(
            "UPDATE scans SET status='failed', phase='error', error_msg=? WHERE id=?",
            (str(exc)[:500], scan_id)
        )
        conn.commit()
        _add_notification(conn, org_id,
            title=f"Scan failed — {domain}",
            body=str(exc)[:200],
            severity="critical",
        )
    finally:
        conn.close()


def _add_notification(conn, org_id, title, body, severity="info"):
    nid = f"n_{uuid.uuid4().hex[:10]}"
    conn.execute(
        "INSERT INTO notifications (id, org_id, title, body, severity, created_at) VALUES (?,?,?,?,?,?)",
        (nid, org_id, title, body, severity, time.time())
    )
    conn.commit()

# ─────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    LEAKS_DIR.mkdir(parents=True, exist_ok=True)
    RISK_DIR.mkdir(parents=True, exist_ok=True)
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="Sentinel ASM API",
    description="Attack Surface Management — REST API v1",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/v1/me")
def me(auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        org = conn.execute("SELECT * FROM orgs WHERE id=?", (auth["org_id"],)).fetchone()
        if not org:
            raise HTTPException(404, "Organization not found")
        return {"org_id": org["id"], "org_name": org["name"], "scopes": auth["scopes"]}
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Domains
# ─────────────────────────────────────────────

@app.get("/api/v1/domains")
def list_domains(auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM domains WHERE org_id=? ORDER BY added_at DESC", (auth["org_id"],)
        ).fetchall()
        return {"data": [dict(r) for r in rows], "total": len(rows)}
    finally:
        conn.close()


@app.post("/api/v1/domains", status_code=201)
def add_domain(body: DomainAdd, auth: dict = Depends(verify_api_key)):
    domain = body.domain.lower().strip().lstrip("https://").lstrip("http://").split("/")[0]
    did = f"d_{uuid.uuid4().hex[:10]}"
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO domains (id, org_id, domain, added_at) VALUES (?,?,?,?)",
            (did, auth["org_id"], domain, time.time())
        )
        conn.commit()
        return {"domain": domain, "id": did}
    except Exception as e:
        raise HTTPException(400, str(e))
    finally:
        conn.close()


@app.delete("/api/v1/domains/{domain_id}")
def remove_domain(domain_id: str, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        conn.execute("DELETE FROM domains WHERE id=? AND org_id=?", (domain_id, auth["org_id"]))
        conn.commit()
        return {"deleted": True}
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────

@app.get("/api/v1/scans")
def list_scans(
    domain: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    auth: dict = Depends(verify_api_key),
):
    conn = get_db()
    try:
        q = "SELECT * FROM scans WHERE org_id=?"
        params = [auth["org_id"]]
        if domain:
            q += " AND domain=?"
            params.append(domain)
        q += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(q, params).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE org_id=?" + (" AND domain=?" if domain else ""),
            [auth["org_id"]] + ([domain] if domain else [])
        ).fetchone()[0]
        return {"data": [dict(r) for r in rows], "total": total, "has_more": offset + limit < total}
    finally:
        conn.close()


@app.post("/api/v1/scans", status_code=202)
async def start_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(verify_api_key),
):
    # Validate domain belongs to org
    conn = get_db()
    try:
        domain = body.domain.lower().strip().lstrip("https://").split("/")[0]
        # Auto-add domain if not exists
        did = f"d_{uuid.uuid4().hex[:10]}"
        conn.execute(
            "INSERT OR IGNORE INTO domains (id, org_id, domain, added_at) VALUES (?,?,?,?)",
            (did, auth["org_id"], domain, time.time())
        )
        scan_id = f"sc_{uuid.uuid4().hex[:12]}"
        conn.execute("""
            INSERT INTO scans (id, org_id, domain, scan_type, status, phase, started_at)
            VALUES (?,?,?,?,?,?,?)
        """, (scan_id, auth["org_id"], domain, body.scan_type, "running", "initializing", time.time()))
        conn.commit()
    finally:
        conn.close()

    background_tasks.add_task(_run_scan, scan_id, domain, body, auth["org_id"])
    return {"scan_id": scan_id, "domain": domain, "status": "running",
            "message": "Scan started. Poll GET /api/v1/scans/{scan_id} for progress."}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id=? AND org_id=?", (scan_id, auth["org_id"])
        ).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found")
        return dict(row)
    finally:
        conn.close()


@app.delete("/api/v1/scans/{scan_id}")
def cancel_scan(scan_id: str, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE scans SET status='cancelled' WHERE id=? AND org_id=? AND status='running'",
            (scan_id, auth["org_id"])
        )
        conn.commit()
        return {"cancelled": True, "scan_id": scan_id}
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────

@app.get("/api/v1/findings")
def list_findings(
    domain: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    auth: dict = Depends(verify_api_key),
):
    conn = get_db()
    try:
        q = "SELECT * FROM findings WHERE org_id=?"
        params: list = [auth["org_id"]]
        if domain:
            q += " AND domain=?"
            params.append(domain)
        if severity:
            q += " AND severity=?"
            params.append(severity.upper())
        if status:
            q += " AND status=?"
            params.append(status)
        q += " ORDER BY risk_score DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(q, params).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE org_id=?"
            + (" AND domain=?" if domain else "")
            + (" AND severity=?" if severity else "")
            + (" AND status=?" if status else ""),
            [auth["org_id"]]
            + ([domain] if domain else [])
            + ([severity.upper()] if severity else [])
            + ([status] if status else [])
        ).fetchone()[0]
        return {"data": [dict(r) for r in rows], "total": total, "has_more": offset + limit < total}
    finally:
        conn.close()


@app.get("/api/v1/findings/{finding_id}")
def get_finding(finding_id: str, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM findings WHERE id=? AND org_id=?", (finding_id, auth["org_id"])
        ).fetchone()
        if not row:
            raise HTTPException(404, "Finding not found")
        return dict(row)
    finally:
        conn.close()


@app.patch("/api/v1/findings/{finding_id}")
def update_finding(finding_id: str, body: FindingStatusUpdate, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        resolved_at = time.time() if body.status == "resolved" else None
        conn.execute(
            "UPDATE findings SET status=?, resolved_at=? WHERE id=? AND org_id=?",
            (body.status, resolved_at, finding_id, auth["org_id"])
        )
        conn.commit()
        return {"updated": True, "status": body.status}
    finally:
        conn.close()


@app.get("/api/v1/findings/stats/summary")
def findings_summary(domain: Optional[str] = None, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        q = "WHERE org_id=?" + (" AND domain=?" if domain else "")
        p = [auth["org_id"]] + ([domain] if domain else [])
        def count(sev):
            return conn.execute(
                f"SELECT COUNT(*) FROM findings {q} AND severity=? AND status!='resolved'", p + [sev]
            ).fetchone()[0]
        return {
            "critical": count("CRITICAL"),
            "high":     count("HIGH"),
            "medium":   count("MEDIUM"),
            "low":      count("LOW"),
            "info":     count("INFO"),
            "kev_matches": conn.execute(
                f"SELECT COUNT(*) FROM findings {q} AND in_kev=1 AND status!='resolved'", p
            ).fetchone()[0],
            "total_open": conn.execute(
                f"SELECT COUNT(*) FROM findings {q} AND status='open'", p
            ).fetchone()[0],
        }
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Assets (from Module 1 JSON reports)
# ─────────────────────────────────────────────

@app.get("/api/v1/assets")
def list_assets(
    domain: Optional[str] = None,
    alive_only: bool = False,
    auth: dict = Depends(verify_api_key),
):
    results = []
    pattern = f"{domain}_*.json" if domain else "*.json"
    for path in sorted(REPORTS_DIR.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue
        for sub in data.get("subdomains", []):
            if alive_only and not sub.get("is_alive"):
                continue
            results.append({
                "subdomain":    sub.get("subdomain"),
                "domain":       data.get("domain"),
                "ip_addresses": sub.get("ip_addresses", []),
                "is_alive":     sub.get("is_alive", False),
                "https_status": sub.get("https_status"),
                "http_status":  sub.get("http_status"),
                "technologies": sub.get("technologies", []),
                "open_ports":   sub.get("open_ports", []),
                "server":       sub.get("server"),
                "title":        sub.get("title"),
                "scanned_at":   data.get("scan_completed"),
            })
        # Only use the most recent report per domain
        if domain:
            break
    return {"data": results, "total": len(results)}

# ─────────────────────────────────────────────
# Reports (Module 4 PDF)
# ─────────────────────────────────────────────

@app.get("/api/v1/reports")
def list_reports(auth: dict = Depends(verify_api_key)):
    pdfs = sorted(PDF_DIR.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {
        "data": [
            {"filename": p.name, "size_bytes": p.stat().st_size,
             "created_at": p.stat().st_mtime}
            for p in pdfs
        ],
        "total": len(pdfs),
    }


@app.post("/api/v1/reports", status_code=202)
async def generate_report(
    body: ReportRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(verify_api_key),
):
    conn = get_db()
    try:
        scan = conn.execute(
            "SELECT * FROM scans WHERE id=? AND org_id=?", (body.scan_id, auth["org_id"])
        ).fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found")
        if not scan["report_path"] or not Path(scan["report_path"]).exists():
            raise HTTPException(400, "Scan report not available yet")
    finally:
        conn.close()

    report_path = scan["report_path"]
    domain = scan["domain"]

    async def _run_report():
        m4_script = MODULE4_DIR / "report_generator.py"
        if not m4_script.exists():
            # Try old name
            m4_script = BASE_DIR / "report_generator.py"
        if not m4_script.exists():
            return  # Module 4 not installed

        PDF_DIR.mkdir(parents=True, exist_ok=True)
        risk_files = sorted(RISK_DIR.glob(f"{domain}_risk_*.json"),
                            key=lambda p: p.stat().st_mtime)

        cmd = [
            sys.executable, str(m4_script),
            "--module1", report_path,
            "--client", body.client_name,
            "--assessor", body.assessor_name,
            "--output-dir", str(PDF_DIR),
            "--confirm",
        ]
        if risk_files:
            cmd += ["--module3", str(risk_files[-1])]

        await asyncio.create_subprocess_exec(*cmd, cwd=str(MODULE4_DIR))

    background_tasks.add_task(_run_report)
    return {"message": "Report generation started", "output_dir": str(PDF_DIR)}


@app.get("/api/v1/reports/download/{filename}")
def download_report(filename: str, auth: dict = Depends(verify_api_key)):
    safe_name = Path(filename).name  # prevent path traversal
    path = PDF_DIR / safe_name
    if not path.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(str(path), media_type="application/pdf", filename=safe_name)

# ─────────────────────────────────────────────
# Notifications
# ─────────────────────────────────────────────

@app.get("/api/v1/notifications")
def list_notifications(unread_only: bool = False, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        q = "SELECT * FROM notifications WHERE org_id=?"
        params = [auth["org_id"]]
        if unread_only:
            q += " AND read=0"
        q += " ORDER BY created_at DESC LIMIT 50"
        rows = conn.execute(q, params).fetchall()
        return {"data": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/api/v1/notifications/mark-read")
def mark_notifications_read(auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        conn.execute("UPDATE notifications SET read=1 WHERE org_id=?", (auth["org_id"],))
        conn.commit()
        return {"updated": True}
    finally:
        conn.close()

# ─────────────────────────────────────────────
# API Keys management
# ─────────────────────────────────────────────

@app.get("/api/v1/api-keys")
def list_api_keys(auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, name, key_prefix, scopes, created_at, last_used FROM api_keys WHERE org_id=?",
            (auth["org_id"],)
        ).fetchall()
        return {"data": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/api/v1/api-keys", status_code=201)
def create_api_key(body: ApiKeyCreate, auth: dict = Depends(verify_api_key)):
    raw = f"sk_live_{uuid.uuid4().hex}"
    prefix = raw[:20] + "…"
    kid = f"key_{uuid.uuid4().hex[:10]}"
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO api_keys (id, org_id, name, key_prefix, key_hash, scopes, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (kid, auth["org_id"], body.name, prefix, hash_key(raw),
              json.dumps(body.scopes), time.time()))
        conn.commit()
        # Return the raw key once — it is never stored and cannot be recovered
        return {"id": kid, "name": body.name, "key": raw,
                "key_prefix": prefix, "scopes": body.scopes,
                "warning": "Save this key now — it will not be shown again."}
    finally:
        conn.close()


@app.delete("/api/v1/api-keys/{key_id}")
def delete_api_key(key_id: str, auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        conn.execute("DELETE FROM api_keys WHERE id=? AND org_id=?", (key_id, auth["org_id"]))
        conn.commit()
        return {"deleted": True}
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Dashboard stats summary (for the overview cards)
# ─────────────────────────────────────────────

@app.get("/api/v1/dashboard/summary")
def dashboard_summary(auth: dict = Depends(verify_api_key)):
    conn = get_db()
    try:
        org_id = auth["org_id"]
        domains = conn.execute(
            "SELECT COUNT(*) FROM domains WHERE org_id=?", (org_id,)
        ).fetchone()[0]
        total_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE org_id=?", (org_id,)
        ).fetchone()[0]
        running_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE org_id=? AND status='running'", (org_id,)
        ).fetchone()[0]
        def fc(sev):
            return conn.execute(
                "SELECT COUNT(*) FROM findings WHERE org_id=? AND severity=? AND status!='resolved'",
                (org_id, sev)
            ).fetchone()[0]
        return {
            "domains":       domains,
            "total_scans":   total_scans,
            "running_scans": running_scans,
            "findings": {
                "critical": fc("CRITICAL"),
                "high":     fc("HIGH"),
                "medium":   fc("MEDIUM"),
                "low":      fc("LOW"),
                "kev":      conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE org_id=? AND in_kev=1 AND status!='resolved'",
                    (org_id,)
                ).fetchone()[0],
            },
        }
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
