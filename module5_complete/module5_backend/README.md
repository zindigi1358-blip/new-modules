# Module 5 — Multi-Tenant SaaS Backend

> **Authorization required.** Always obtain written permission before scanning any domain.

---

## Architecture

```
Browser Dashboard (HTML/CSS/JS)
        │
        ▼  REST API (JSON)
┌─────────────────────────────────┐
│  FastAPI  (main.py, port 8000)  │
│  ─────────────────────────────  │
│  Auth    — Bearer API key       │
│  SQLite  — state + findings DB  │
│  CORS    — for dashboard origin │
└──────────┬──────────────────────┘
           │ asyncio subprocess
    ┌──────┴──────┐
    │  Module 1   │  Asset Discovery
    │  Module 2   │  Monitoring  
    │  Module 2.5 │  Leak Scanner
    │  Module 3   │  Risk + CVE
    │  Module 4   │  PDF Reports
    └─────────────┘
```

---

## Quick Start

### 1. Install dependencies

```bash
cd ~/project/advance/asset-discovery/module5
pip3 install fastapi uvicorn[standard] aiofiles python-multipart pydantic
```

### 2. Start the API server

```bash
python3 main.py
```

Or with make:
```bash
make start
```

The server starts on `http://0.0.0.0:8000`

### 3. Verify it works

```bash
# Health check
curl http://localhost:8000/health

# Dev mode (no real API key needed)
curl -H "Authorization: Bearer dev" http://localhost:8000/api/v1/me
curl -H "Authorization: Bearer dev" http://localhost:8000/api/v1/dashboard/summary
```

### 4. Open Swagger UI
Visit `http://localhost:8000/docs` in your browser — full interactive API docs.

---

## API Endpoints

### Auth
All endpoints require: `Authorization: Bearer sk_live_...`  
In dev mode: `Authorization: Bearer dev`

### Scans
```
POST   /api/v1/scans              Start a new scan
GET    /api/v1/scans              List all scans
GET    /api/v1/scans/{id}         Get scan status + progress
DELETE /api/v1/scans/{id}         Cancel a running scan
```

### Findings
```
GET    /api/v1/findings           List findings (filter by domain/severity/status)
GET    /api/v1/findings/{id}      Get one finding with full details
PATCH  /api/v1/findings/{id}      Update status (open/resolved/accepted/false_positive)
GET    /api/v1/findings/stats/summary   Count by severity
```

### Assets
```
GET    /api/v1/assets             List all discovered assets from Module 1 reports
```

### Reports (Module 4)
```
GET    /api/v1/reports            List generated PDF reports
POST   /api/v1/reports            Trigger PDF generation
GET    /api/v1/reports/download/{filename}   Download a PDF
```

### API Keys
```
GET    /api/v1/api-keys           List keys (prefix only, never the full key)
POST   /api/v1/api-keys           Create a new key (returned ONCE — save it)
DELETE /api/v1/api-keys/{id}      Revoke a key
```

### Notifications
```
GET    /api/v1/notifications      List recent platform alerts
POST   /api/v1/notifications/mark-read   Mark all as read
```

### Domains
```
GET    /api/v1/domains            List monitored domains
POST   /api/v1/domains            Add a domain
DELETE /api/v1/domains/{id}       Remove a domain
```

### Dashboard
```
GET    /api/v1/dashboard/summary  Findings counts + running scans (for overview cards)
GET    /api/v1/me                 Current org + scopes
```

---

## Starting a scan via API

```bash
# Start a full scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer dev" \
  -H "Content-Type: application/json" \
  -d '{"domain": "orgspace.xyz", "scan_type": "full"}'

# Poll progress
curl -H "Authorization: Bearer dev" \
  http://localhost:8000/api/v1/scans/sc_XXXXXXX

# Get findings when done
curl "http://localhost:8000/api/v1/findings?domain=orgspace.xyz&severity=critical" \
  -H "Authorization: Bearer dev"
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_API_SECRET` | `change-me-in-production` | HMAC secret for API key hashing |

**Change the secret in production:**
```bash
export SENTINEL_API_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 main.py
```

---

## File Paths

The backend auto-discovers module paths from its own location:

```
asset-discovery/
├── module1/
│   ├── run.py
│   └── reports/          ← Module 1 JSON reports
├── module2/
├── module2_5/
│   └── module2_5_reports/ ← Leak scan reports
├── module3/
│   └── module3_reports/   ← Risk scoring reports
├── module4/               ← Report generator
│   └── pdf_reports/       ← Generated PDFs
└── module5/               ← This backend
    ├── main.py
    └── module5_state.db   ← SQLite DB (auto-created)
```

---

## Production deployment (systemd)

```ini
# /etc/systemd/system/sentinel-asm.service
[Unit]
Description=Sentinel ASM API
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/project/advance/asset-discovery/module5
Environment="SENTINEL_API_SECRET=your-secret-here"
ExecStart=/usr/bin/python3 main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable sentinel-asm
sudo systemctl start sentinel-asm
sudo systemctl status sentinel-asm
```

---

## Security notes

- API keys are **hashed** with HMAC-SHA256 before storage — the raw key is shown only once on creation
- Set `SENTINEL_API_SECRET` to a random 32-byte secret before going to production
- Remove `"*"` from `ALLOWED_ORIGINS` in production — add only your dashboard's actual URL
- The `Bearer dev` shortcut bypasses auth — disable it in production by removing those 2 lines from `verify_api_key()`
- All user inputs are sanitized (domain names stripped of protocol prefix, filenames validated against path traversal)
