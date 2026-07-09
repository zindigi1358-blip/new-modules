#!/usr/bin/env python3
"""
Module 3 — Risk Scoring & CVE Matching Engine
================================================
Consumes JSON reports from Module 1 (subdomain discovery) and optionally
Module 2.5 (leak scanner), matches detected technology versions against
the NVD CVE database + CISA KEV catalog, and produces a prioritized,
risk-scored findings report.

Usage:
    python3 run_module3.py --report reports/example.com_latest.json \\
                            --leaks module2_5_reports/example.com_leaks.json \\
                            --nvd-key YOUR_NVD_KEY

Get a free NVD API key (instant): https://nvd.nist.gov/developers/request-an-api-key
"""
import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
import database as db
import tech_parser
import nvd_client
import osv_client
import vulners_client
import kev_client
import risk_engine
import discord_notifier


# ── Console output helpers (no external deps) ────────────────────────────────

RESET, BOLD, RED, YELLOW, GREEN, CYAN, GRAY = (
    "\033[0m", "\033[1m", "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[90m"
)

LEVEL_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN, "INFO": GRAY}


def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════╗
║   MODULE 3 — Risk Scoring & CVE Matching Engine           ║
║   Data sources: NIST NVD + CISA KEV (public, official)    ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def print_finding(finding: dict):
    color = LEVEL_COLOR.get(finding["risk_level"], GRAY)
    print(f"{color}{BOLD}[{finding['risk_level']:<8}]{RESET} "
          f"{finding['subdomain']}  —  {finding['technology']} {finding['version'] or ''}  "
          f"{color}score={finding['risk_score']}{RESET}")
    if finding.get("in_kev"):
        print(f"    {RED}{BOLD}⚠ ACTIVELY EXPLOITED (CISA KEV) — patch immediately{RESET}")
    for cve in finding["matched_cves"][:3]:
        print(f"    {GRAY}└ {cve['cve_id']}  (CVSS {cve['cvss']})  {cve['summary'][:90]}{RESET}")


# ── Input loading ─────────────────────────────────────────────────────────────

def load_module1_report(path: str) -> dict:
    if not os.path.isfile(path):
        print(f"{RED}ERROR: Module 1 report not found at {path}{RESET}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def load_module2_5_findings(path: str) -> list:
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        return data.get("findings", [])
    except Exception as e:
        print(f"{YELLOW}WARNING: Could not load Module 2.5 findings: {e}{RESET}")
        return []


# ── Core scan logic ────────────────────────────────────────────────────────────

def process_subdomain(sub_record: dict, leak_findings: list, scan_id: str, domain: str) -> list:
    """Processes one subdomain: parse tech -> query CVEs -> score -> save. Returns list of findings."""
    if not sub_record.get("is_alive"):
        return []

    subdomain = sub_record.get("subdomain", "unknown")
    technologies = tech_parser.parse_all(sub_record.get("technologies", []))
    exposure_flags = risk_engine.detect_exposure_flags(sub_record, leak_findings)

    findings = []

    # Even with zero parsed technologies, still record pure-exposure findings
    # (e.g. exposed .git with no software version detected)
    tech_iter = technologies if technologies else [{"product": None, "version": None, "raw": None}]

    for tech in tech_iter:
        cve_list = []
        if tech["product"]:
            # Query all 3 sources — each fails gracefully to [] on its own,
            # so a down/misconfigured source never blocks the others.
            nvd_results     = nvd_client.query_nvd(tech["product"], tech["version"])
            osv_results     = osv_client.query_osv(tech["product"], tech["version"])
            vulners_results = vulners_client.query_vulners(tech["product"], tech["version"])

            cve_list = risk_engine.merge_cve_sources(nvd_results, osv_results, vulners_results)
            cve_list, in_kev = kev_client.enrich_with_kev(cve_list)
        else:
            in_kev = False

        if not cve_list and not exposure_flags:
            continue  # nothing to report for this tech entry

        result = risk_engine.compute_finding_score(cve_list, in_kev, exposure_flags, subdomain)

        finding = {
            "scan_id":        scan_id,
            "domain":         domain,
            "subdomain":      subdomain,
            "technology":     tech["product"] or "N/A",
            "version":        tech["version"],
            "matched_cves":   cve_list,
            "in_kev":         in_kev,
            "risk_score":     result["score"],
            "risk_level":     result["level"],
            "exposure_notes": result["breakdown"]["exposure_notes"],
            "breakdown":      result["breakdown"],
        }
        findings.append(finding)

        db.save_finding(
            scan_id, domain, subdomain, finding["technology"], finding["version"],
            cve_list, in_kev, finding["risk_score"], finding["risk_level"],
            finding["exposure_notes"],
        )

    return findings


def run_scan(report_path: str, leaks_path: str, output_dir: str, workers: int = 4) -> dict:
    banner()
    db.init_db()

    report = load_module1_report(report_path)
    domain = report.get("domain", "unknown")
    leak_findings = load_module2_5_findings(leaks_path)
    scan_id = f"{domain}_{uuid.uuid4().hex[:8]}"

    print(f"{CYAN}[*] Domain: {domain}{RESET}")
    print(f"{CYAN}[*] Subdomains in report: {len(report.get('subdomains', []))}{RESET}")
    print(f"{CYAN}[*] Leak findings loaded: {len(leak_findings)}{RESET}")

    print(f"{CYAN}[*] Refreshing CISA KEV catalog...{RESET}")
    kev_count = kev_client.refresh_kev_cache()
    if kev_count == -1:
        print(f"{GREEN}[+] KEV cache already fresh{RESET}")
    elif kev_count > 0:
        print(f"{GREEN}[+] KEV catalog loaded: {kev_count} actively-exploited CVEs tracked{RESET}")
    else:
        print(f"{YELLOW}[!] Could not refresh KEV catalog — continuing without it{RESET}")

    alive_subs = [s for s in report.get("subdomains", []) if s.get("is_alive")]
    print(f"{CYAN}[*] Matching CVEs for {len(alive_subs)} alive subdomains "
          f"(this respects NVD rate limits, may take a while)...{RESET}\n")

    all_findings = []
    # NOTE: kept modest concurrency (workers=4 default) — NVD's rate limiter
    # is a shared resource, so higher parallelism here just means more
    # threads blocking on the SAME limiter, not faster throughput.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(process_subdomain, sub, leak_findings, scan_id, domain): sub
            for sub in alive_subs
        }
        for fut in as_completed(futures):
            try:
                findings = fut.result()
                for f in findings:
                    print_finding(f)
                all_findings.extend(findings)
            except Exception as e:
                sub = futures[fut]
                print(f"{RED}[!] Error processing {sub.get('subdomain')}: {e}{RESET}")

    all_findings.sort(key=lambda x: x["risk_score"], reverse=True)

    # ── Save report ───────────────────────────────────────────────────────────
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_path = os.path.join(output_dir, f"{domain}_risk_report_{int(time.time())}.json")

    summary = {
        "scan_id": scan_id,
        "domain": domain,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_findings": len(all_findings),
        "critical_count": sum(1 for f in all_findings if f["risk_level"] == "CRITICAL"),
        "high_count":     sum(1 for f in all_findings if f["risk_level"] == "HIGH"),
        "medium_count":   sum(1 for f in all_findings if f["risk_level"] == "MEDIUM"),
        "low_count":      sum(1 for f in all_findings if f["risk_level"] == "LOW"),
        "kev_matches":    sum(1 for f in all_findings if f["in_kev"]),
        "findings": all_findings,
    }
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}SCAN SUMMARY{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"  Total findings : {summary['total_findings']}")
    print(f"  {RED}Critical       : {summary['critical_count']}{RESET}")
    print(f"  {RED}High           : {summary['high_count']}{RESET}")
    print(f"  {YELLOW}Medium         : {summary['medium_count']}{RESET}")
    print(f"  {GREEN}Low            : {summary['low_count']}{RESET}")
    print(f"  {RED}{BOLD}Actively Exploited (KEV): {summary['kev_matches']}{RESET}")
    print(f"\n  Report saved: {out_path}")
    print(f"{CYAN}{'='*60}{RESET}\n")

    # ── Notification hook (wire in your Discord/email/webhook logic here) ───
    notify_if_critical(summary)

    return summary


def notify_if_critical(summary: dict):
    """
    Sends Discord alerts to every webhook configured in config.DISCORD_WEBHOOKS
    (up to 5+, all get the same alert). Fires whenever any finding meets or
    exceeds config.DISCORD_ALERT_MIN_LEVEL (default: HIGH).
    """
    if not discord_notifier._active_webhooks():
        return  # nothing configured — silent no-op, not an error
    discord_notifier.send_alert(summary)
    print(f"{GREEN}[+] Discord alert sent to {len(discord_notifier._active_webhooks())} webhook(s){RESET}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Module 3 — Risk Scoring & CVE Matching Engine")
    parser.add_argument("--report",   required=True, help="Path to Module 1 JSON report")
    parser.add_argument("--leaks",    default=None,  help="Path to Module 2.5 leak-scan JSON (optional)")
    parser.add_argument("--nvd-key",     default=os.getenv("NVD_API_KEY", ""),     help="NVD API key (optional, 10x rate limit)")
    parser.add_argument("--vulners-key", default=os.getenv("VULNERS_API_KEY", ""), help="Vulners.com API key (optional)")
    parser.add_argument("--discord-webhook", action="append", default=None,
                        help="Discord webhook URL — repeatable, e.g. --discord-webhook URL1 --discord-webhook URL2 (up to 5+)")
    parser.add_argument("--output-dir", default=config.OUTPUT_DIR, help="Where to save the risk report")
    parser.add_argument("--workers",  type=int, default=4, help="Concurrent subdomain processing threads")
    args = parser.parse_args()

    # These must be set BEFORE any client module function runs — nvd_client/
    # vulners_client read config.NVD_API_KEY / config.VULNERS_API_KEY
    # dynamically (via `import config`, not `from config import X`), so
    # setting them here correctly takes effect for the whole scan.
    if args.nvd_key:
        config.NVD_API_KEY = args.nvd_key
    if args.vulners_key:
        config.VULNERS_API_KEY = args.vulners_key
    if args.discord_webhook:
        config.DISCORD_WEBHOOKS = args.discord_webhook + [w for w in config.DISCORD_WEBHOOKS if w]

    run_scan(args.report, args.leaks, args.output_dir, args.workers)


if __name__ == "__main__":
    main()
