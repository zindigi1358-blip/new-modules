#!/bin/bash
# ─────────────────────────────────────
# Sentinel ASM — Module 5 Backend
# Start script for Ubuntu server
# ─────────────────────────────────────
set -e

echo "Installing dependencies..."
pip3 install fastapi uvicorn[standard] aiofiles python-multipart pydantic

echo "Starting Sentinel ASM API on http://0.0.0.0:8000 ..."
echo "Dashboard API docs: http://localhost:8000/docs"
echo "Health check:       http://localhost:8000/health"
echo ""
echo "Quick test (after start):"
echo "  curl -H 'Authorization: Bearer dev' http://localhost:8000/api/v1/me"
echo ""

python3 main.py
