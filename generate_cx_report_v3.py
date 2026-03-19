#!/usr/bin/env python3
"""
Cisco CX AI Network Lifecycle & Security Assessment — v3.0

Three-stage pipeline:
  Stage 1: Data Collection — inventory CSV + Cisco EoX/PSIRT APIs → structured JSON
  Stage 2: AI Analysis    — JSON + system prompt → LLM writes analysis
  Stage 3: Report Assembly — LLM output + data tables → final .md report

APIs used:
  - Cisco EoX API        — Hardware & Software End-of-Life data
  - Cisco PSIRT openVuln — Security advisories by software version (CVEs, CVSS, first-fixed)

Usage:
  export CISCO_API_ID="<id>"
  export CISCO_API_SECRET="<secret>"

  # Default: uses local Ollama (no data leaves your machine)
  python3 generate_cx_report_v3.py --inventory bt.csv --customer "BT Enterprise"
  python3 generate_cx_report_v3.py --inventory bt.csv --customer "BT Enterprise" --llm ollama --model llama3.1:8b
  python3 generate_cx_report_v3.py --inventory bt.csv --customer "BT Enterprise" --llm none  # data-only, no AI

  # Ollama must be running: ollama serve
  # Recommended models: llama3.1:8b, llama3.2, or any model via: ollama pull <model>

Requirements:
  pip install cisco_support requests
"""

import csv
import os
import re
import sys
import time
import json
import argparse
import requests as _requests
from datetime import date, datetime
from collections import Counter, defaultdict
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).parent.resolve()
SW_RECO_FILE = SCRIPT_DIR / "software_recommendation.csv"

RISK_ICON = {
    "PAST EOL": "🔴", "CRITICAL": "🔴", "HIGH": "🟠",
    "MEDIUM": "🟡", "LOW": "🟢", "NO EOL": "⚪", "NONE": "⚪",
    "NON-COMPLIANT": "🔴", "ACCEPTABLE": "🟡", "COMPLIANT": "🟢",
}

# Weights for overall health score
DOMAIN_WEIGHTS = {
    "hw_eol": 0.20,
    "sw_eol": 0.15,
    "security": 0.25,
    "field_notice": 0.10,
    "conformance": 0.20,
    "contract": 0.10,  # placeholder — no data yet
}

# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Cisco CX AI Assessment Report Generator v3.0")
    p.add_argument("--inventory", required=True,
                   help="Path to customer inventory CSV")
    p.add_argument("--customer", default="Valued Customer",
                   help="Customer name for report branding")
    p.add_argument("--output", default=None,
                   help="Output .md file path")
    p.add_argument("--date", default=None,
                   help="Assessment date YYYY-MM-DD (default: today)")
    p.add_argument("--sw-reco", default=str(SW_RECO_FILE),
                   help="Path to software_recommendation.csv")
    p.add_argument("--skip-api", action="store_true",
                   help="Skip Cisco API calls; use only inventory data")
    p.add_argument("--skip-psirt", action="store_true",
                   help="Skip PSIRT openVuln API calls")
    p.add_argument("--llm", default="ollama",
                   choices=["ollama", "none"],
                   help="LLM provider for AI analysis (default: ollama — local, no data leaves machine)")
    p.add_argument("--model", default=None,
                   help="Ollama model name (default: llama3.1:8b). Run 'ollama list' to see available models.")
    p.add_argument("--ollama-url", default="http://localhost:11434",
                   help="Ollama API base URL (default: http://localhost:11434)")
    p.add_argument("--save-json", action="store_true",
                   help="Save intermediate JSON data to disk")
    return p.parse_args()

# ═══════════════════════════════════════════════════════════════════════════
# STAGE 1: DATA COLLECTION
# ═══════════════════════════════════════════════════════════════════════════

def load_inventory(csv_path):
    """Load and cleanse inventory CSV."""
    valid = []
    excluded = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            pid = (row.get("Product ID") or "").strip()
            sw_ver = (row.get("Software Version") or "").strip()
            sw_type = (row.get("Software Type") or "").strip()
            if (not pid or pid.lower() == "null" or
                not sw_ver or sw_ver in ("Not Found", "Missing", "null", "") or
                not sw_type or sw_type in ("Missing", "null", "")):
                excluded.append(row)
            else:
                valid.append(row)
    return valid, excluded


def load_sw_recommendations(csv_path):
    reco = {}
    if not os.path.exists(csv_path):
        print(f"  [WARN] SW recommendation file not found: {csv_path}")
        return reco
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            reco[row["Product ID"]] = {
                "sw_type": row["Software Type"],
                "recommended": row["Recommended Version"],
                "previous": row["Previous Recommended Version"],
            }
    return reco


# ── PID normalization ────────────────────────────────────────────────────

def normalize_pid(pid):
    p = pid.upper()
    if p.startswith("C9500"):  return "C9500"
    if p.startswith(("C9410", "C9407", "C9404")):  return "C9410"
    if p.startswith("C9300"):  return "C9300"
    if p.startswith("C9200"):  return "C9200"
    if p.startswith("ASR"):    return "ASR1000"
    if p.startswith(("C8", "CAT8")):  return "Cat8000"
    if p.startswith(("WS-C3560", "C3560")):  return "C3560"
    if p.startswith("ISR"):    return "ASR1000"
    if p.startswith(("N9K-C9504", "N9K-C9508")):  return "N9K-C9504"
    if p.startswith("N9K-"):   return "N9K-C93180"
    return pid


def platform_family_name(pid):
    p = pid.upper()
    if p.startswith(("C9410", "C9407", "C9404")):  return "Catalyst 9400"
    if p.startswith("C9300"):  return "Catalyst 9300"
    if p.startswith("C9500"):  return "Catalyst 9500"
    if p.startswith("C9200"):  return "Catalyst 9200"
    if p.startswith("C8"):     return "Catalyst 8500"
    if p.startswith(("WS-C3560", "C3560")):  return "Catalyst 3560-CX"
    if p.startswith("ISR"):    return "ISR 4000"
    if p.startswith("ASR"):    return "ASR 1000"
    if p.startswith("N9K-"):   return "Nexus 9000"
    return pid


# ── Cisco EoX API ────────────────────────────────────────────────────────

def query_eox_by_pid(unique_pids, api_id, api_secret):
    """Hardware EoL via EoX API. Returns dict keyed by PID."""
    eol_map = {}
    try:
        from cisco_support import EoX
        eox = EoX(client_id=api_id, client_secret=api_secret)
        pid_list = list(unique_pids)
        for i in range(0, len(pid_list), 20):
            batch = pid_list[i:i + 20]
            print(f"    [HW-EoX] Batch {i // 20 + 1}: {', '.join(batch[:5])}{'…' if len(batch) > 5 else ''}")
            try:
                resp = eox.get_by_product_ids(batch)
                for rec in resp.get("EOXRecord", []):
                    pid_key = rec.get("EOLProductID", "")
                    ldos = rec.get("LastDateOfSupport", {}).get("value", "")
                    eos = rec.get("EndOfSaleDate", {}).get("value", "")
                    if not pid_key or (not ldos and not eos):
                        continue
                    eol_map[pid_key] = {
                        "pid": pid_key,
                        "description": rec.get("ProductIDDescription", ""),
                        "bulletin": rec.get("ProductBulletinNumber", ""),
                        "announced": rec.get("EOXExternalAnnouncementDate", {}).get("value", ""),
                        "end_of_sale": eos,
                        "end_of_sw_maint": rec.get("EndOfSWMaintenanceReleases", {}).get("value", ""),
                        "end_of_sec_vuln": rec.get("EndOfSecurityVulSupportDate", {}).get("value", ""),
                        "last_date_of_support": ldos,
                        "migration_pid": rec.get("EOXMigrationDetails", {}).get("MigrationProductId", ""),
                        "migration_info": rec.get("EOXMigrationDetails", {}).get("MigrationInformation", ""),
                        "migration_strategy": rec.get("EOXMigrationDetails", {}).get("MigrationStrategy", ""),
                    }
            except Exception as e:
                print(f"    [HW-EoX] API error: {e}")
            if i + 20 < len(pid_list):
                time.sleep(1)
    except ImportError:
        print("    [HW-EoX] cisco_support not installed — pip install cisco_support")
    except Exception as e:
        print(f"    [HW-EoX] Init error: {e}")
    return eol_map


def query_eox_by_sw(unique_sw_versions, api_id, api_secret):
    """Software EoL via EoX API. Returns dict keyed by SW version string.

    The API returns many EOXRecords per version query (one per software PID).
    We query ONE version at a time to avoid cross-contamination, and pick
    the record with the latest LastDateOfSupport (most relevant/recent EoL).
    """
    sw_eol_map = {}
    try:
        from cisco_support import EoX
        eox = EoX(client_id=api_id, client_secret=api_secret)
        ver_list = list(unique_sw_versions)
        for idx, ver in enumerate(ver_list):
            print(f"    [SW-EoX] {idx + 1}/{len(ver_list)}: {ver}")
            try:
                resp = eox.get_by_software_release_strings([ver])
                best = None
                best_ldos = ""
                for rec in resp.get("EOXRecord", []):
                    ldos = rec.get("LastDateOfSupport", {}).get("value", "")
                    eos = rec.get("EndOfSaleDate", {}).get("value", "")
                    if not ldos and not eos:
                        continue
                    # Pick the record with the latest LDoS (most relevant)
                    if not best or ldos > best_ldos:
                        best = rec
                        best_ldos = ldos
                if best:
                    sw_eol_map[ver] = {
                        "version": ver,
                        "bulletin": best.get("ProductBulletinNumber", ""),
                        "end_of_sale": best.get("EndOfSaleDate", {}).get("value", ""),
                        "end_of_sw_maint": best.get("EndOfSWMaintenanceReleases", {}).get("value", ""),
                        "end_of_sec_vuln": best.get("EndOfSecurityVulSupportDate", {}).get("value", ""),
                        "last_date_of_support": best_ldos,
                        "migration_strategy": best.get("EOXMigrationDetails", {}).get("MigrationStrategy", ""),
                        "total_affected_pids": resp.get("PaginationResponseRecord", {}).get("TotalRecords", 0),
                    }
            except Exception as e:
                print(f"    [SW-EoX] API error for {ver}: {e}")
            if idx + 1 < len(ver_list):
                time.sleep(0.5)
    except ImportError:
        print("    [SW-EoX] cisco_support not installed")
    except Exception as e:
        print(f"    [SW-EoX] Init error: {e}")
    return sw_eol_map


# ── Cisco PSIRT openVuln API ──────────────────────────────────────────────

PSIRT_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
PSIRT_API_BASE = "https://apix.cisco.com/security/advisories/v2"

# Map our SW type names to PSIRT OSType values
SW_TYPE_TO_OSTYPE = {
    "IOS-XE": "iosxe",
    "IOS": "ios",
    "NX-OS": "nxos",
}


def _get_psirt_token(api_id, api_secret):
    """Acquire OAuth2 bearer token for PSIRT API."""
    resp = _requests.post(
        PSIRT_TOKEN_URL,
        data={
            "client_id": api_id,
            "client_secret": api_secret,
            "grant_type": "client_credentials",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _is_remote_unauth(summary):
    """Check if advisory summary indicates remote + unauthenticated attack."""
    s = (summary or "").lower()
    remote = "remote" in s
    unauth = any(w in s for w in (
        "unauthenticated", "without authentication",
        "no authentication", "not authenticated",
    ))
    return remote and unauth


def query_psirt_by_sw(sw_versions_by_type, api_id, api_secret,
                      max_age_years=2):
    """Query PSIRT openVuln API for advisories per SW version.

    Filters applied:
      1. Only advisories published within *max_age_years* (default 2)
      2. Only Critical and High severity (SIR)
      3. Only remote + unauthenticated (based on advisory summary text)

    Args:
        sw_versions_by_type: dict  e.g. {"IOS-XE": ["17.9.5", "16.12.4"]}
        api_id, api_secret: Cisco API credentials
        max_age_years: advisory recency window

    Returns:
        dict keyed by "sw_type|version" → {
            "total": N,
            "by_severity": {"Critical": N, "High": N},
            "top_advisories": [top 5 by CVSS — remote + unauthenticated only],
        }
    """
    psirt_map = {}
    cutoff = date.today().replace(year=date.today().year - max_age_years)
    cutoff_str = cutoff.isoformat()  # e.g. "2024-03-18"
    try:
        token = _get_psirt_token(api_id, api_secret)
    except Exception as e:
        print(f"    [PSIRT] Token error: {e}")
        return psirt_map

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    query_count = sum(len(v) for v in sw_versions_by_type.values())
    idx = 0
    for sw_type, versions in sw_versions_by_type.items():
        os_type = SW_TYPE_TO_OSTYPE.get(sw_type)
        if not os_type:
            continue
        for ver in versions:
            idx += 1
            print(f"    [PSIRT] {idx}/{query_count}: {sw_type} {ver}")
            try:
                resp = _requests.get(
                    f"{PSIRT_API_BASE}/OSType/{os_type}",
                    params={"version": ver},
                    headers=headers,
                    timeout=30,
                )
                if resp.status_code == 406:  # no advisories
                    psirt_map[f"{sw_type}|{ver}"] = {
                        "total": 0, "by_severity": {}, "top_advisories": [],
                    }
                    continue
                resp.raise_for_status()
                data = resp.json()
                raw_advisories = data.get("advisories", [])

                # Filter chain:
                #  1. Published within last N years
                #  2. Critical or High severity only
                #  3. Remote + unauthenticated only
                advisories = []
                for adv in raw_advisories:
                    pub = (adv.get("firstPublished") or "")[:10]
                    if pub < cutoff_str:
                        continue
                    sir = adv.get("sir", "")
                    if sir not in ("Critical", "High"):
                        continue
                    if not _is_remote_unauth(adv.get("summary", "")):
                        continue
                    advisories.append(adv)

                by_severity = {}
                for adv in advisories:
                    sir = adv.get("sir", "Unknown")
                    by_severity[sir] = by_severity.get(sir, 0) + 1

                # Sort by CVSS descending, keep top 5
                advisories.sort(
                    key=lambda a: float(a.get("cvssBaseScore") or "0"),
                    reverse=True,
                )
                top = []
                for adv in advisories[:5]:
                    first_fixed = adv.get("firstFixed", [])
                    top.append({
                        "advisoryId": adv.get("advisoryId", ""),
                        "title": adv.get("advisoryTitle", ""),
                        "sir": adv.get("sir", ""),
                        "cvssBaseScore": adv.get("cvssBaseScore", ""),
                        "cves": adv.get("cves", []),
                        "firstFixed": first_fixed[:5] if first_fixed else [],
                        "firstPublished": adv.get("firstPublished", ""),
                    })

                psirt_map[f"{sw_type}|{ver}"] = {
                    "total": len(advisories),
                    "by_severity": by_severity,
                    "top_advisories": top,
                }
            except Exception as e:
                print(f"    [PSIRT] Error for {sw_type} {ver}: {e}")

            if idx < query_count:
                time.sleep(0.5)

    return psirt_map


# ── Risk classification ──────────────────────────────────────────────────

def classify_hw_risk(ldos_str, assess_date):
    if not ldos_str:
        return "NO EOL", 99999
    try:
        ldos = datetime.strptime(ldos_str, "%Y-%m-%d").date()
    except ValueError:
        return "NO EOL", 99999
    days = (ldos - assess_date).days
    if days < 0:     return "PAST EOL", days
    if days < 180:   return "CRITICAL", days
    if days < 365:   return "HIGH", days
    if days < 730:   return "MEDIUM", days
    return "LOW", days


def classify_sw_eol_risk(ldos_str, assess_date):
    """Same thresholds as HW but for SW end-of-life."""
    return classify_hw_risk(ldos_str, assess_date)


def classify_psirt(count):
    c = int(count) if count else 0
    if c >= 9: return "CRITICAL"
    if c >= 6: return "HIGH"
    if c >= 4: return "MEDIUM"
    if c >= 1: return "LOW"
    return "NONE"


def classify_fn(count):
    c = int(count) if count else 0
    if c >= 5: return "HIGH"
    if c >= 3: return "MEDIUM"
    if c >= 1: return "LOW"
    return "NONE"


def sw_train_status(sw_type, version):
    if sw_type == "IOS-XE" and version.startswith("16."):
        return "CRITICAL", "End-of-Life Train (IOS-XE 16.x)"
    if sw_type == "IOS-XE" and version.startswith("17.6."):
        return "HIGH", "Older Maintenance Train"
    if sw_type == "IOS-XE" and version.startswith("17.9."):
        return "MEDIUM", "Active but behind recommended 17.12.x"
    if sw_type == "IOS-XE" and version.startswith("17.12."):
        return "LOW", "Current Recommended Train"
    if sw_type == "IOS" and version.startswith("15."):
        return "HIGH", "Legacy IOS (limited maintenance)"
    if sw_type == "NX-OS" and version.startswith("9."):
        return "HIGH", "Legacy NX-OS Train (behind 10.x)"
    if sw_type == "NX-OS" and version.startswith("10.3"):
        return "MEDIUM", "Active (behind recommended 10.4)"
    if sw_type == "NX-OS" and version.startswith("10.4"):
        return "LOW", "Current Recommended Train"
    if sw_type == "IOS-XE":
        return "LOW", "Active"
    return "MEDIUM", "Review Required"


# ── Build structured JSON ────────────────────────────────────────────────

def build_assessment_json(devices, excluded, hw_eol_map, sw_eol_map, psirt_map,
                          sw_reco, customer, assess_date):
    """Build the structured JSON that feeds into the LLM."""

    total = len(devices)
    pid_counter = Counter()
    family_counter = Counter()
    sw_type_counter = Counter()
    sw_ver_counter = Counter()
    site_counter = Counter()

    for d in devices:
        pid = d["Product ID"]
        pid_counter[pid] += 1
        family_counter[platform_family_name(pid)] += 1
        sw_type_counter[d["Software Type"]] += 1
        sw_ver_counter[f'{d["Software Type"]}|{d["Software Version"]}'] += 1
        name = d.get("Device Name", "")
        site = name.split("-")[0] if "-" in name else name
        site_counter[site] += 1

    # ── HW EoL analysis ─────────────────────────────────────────────────
    hw_eol_items = []
    hw_risk_dist = Counter()
    for pid, eol in hw_eol_map.items():
        cnt = pid_counter.get(pid, 0)
        if cnt == 0:
            continue
        risk, days = classify_hw_risk(eol["last_date_of_support"], assess_date)
        hw_risk_dist[risk] += cnt
        hw_eol_items.append({
            **eol, "risk": risk, "days_remaining": days, "device_count": cnt
        })
    hw_eol_items.sort(key=lambda x: (-{"PAST EOL": 5, "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["risk"], 0), -x["device_count"]))

    no_eol_pids = [{"pid": pid, "family": platform_family_name(pid), "count": cnt}
                   for pid, cnt in pid_counter.items() if pid not in hw_eol_map]
    no_eol_pids.sort(key=lambda x: -x["count"])

    hw_affected = sum(e["device_count"] for e in hw_eol_items)
    hw_no_eol = sum(e["count"] for e in no_eol_pids)

    # HW domain score: 100 if all no-eol, 0 if all past-eol
    hw_score = ((hw_no_eol + hw_risk_dist.get("LOW", 0)) / total * 100) if total else 100

    # ── SW EoL analysis ──────────────────────────────────────────────────
    # Build a lookup: sw_type → recommended version from sw_reco
    sw_type_to_reco = {}
    for fam, rec in sw_reco.items():
        st = rec["sw_type"]
        if st not in sw_type_to_reco:
            sw_type_to_reco[st] = rec["recommended"]

    sw_eol_items = []
    sw_risk_dist = Counter()
    for ver_key, cnt in sw_ver_counter.most_common():
        sw_type, version = ver_key.split("|", 1)
        train_risk, train_status = sw_train_status(sw_type, version)
        reco_ver = sw_type_to_reco.get(sw_type, "N/A")

        # Check if API returned actual SW EoL data
        api_eol = sw_eol_map.get(version, {})
        if api_eol:
            api_risk, api_days = classify_sw_eol_risk(api_eol.get("last_date_of_support"), assess_date)
            # Use the worse of train-based vs API-based risk
            risk_order = {"PAST EOL": 5, "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NO EOL": 0}
            if risk_order.get(api_risk, 0) > risk_order.get(train_risk, 0):
                effective_risk = api_risk
            else:
                effective_risk = train_risk
            sw_eol_items.append({
                "sw_type": sw_type, "version": version, "device_count": cnt,
                "train_risk": train_risk, "train_status": train_status,
                "api_eol_bulletin": api_eol.get("bulletin", ""),
                "api_eol_ldos": api_eol.get("last_date_of_support", ""),
                "api_eol_sec_vuln_end": api_eol.get("end_of_sec_vuln", ""),
                "api_migration_strategy": api_eol.get("migration_strategy", ""),
                "recommended_version": reco_ver,
                "effective_risk": effective_risk,
                "days_remaining": api_days if api_eol else None,
            })
            sw_risk_dist[effective_risk] += cnt
        else:
            sw_eol_items.append({
                "sw_type": sw_type, "version": version, "device_count": cnt,
                "train_risk": train_risk, "train_status": train_status,
                "api_eol_bulletin": None, "api_eol_ldos": None,
                "api_eol_sec_vuln_end": None, "api_migration_strategy": None,
                "recommended_version": reco_ver,
                "effective_risk": train_risk,
                "days_remaining": None,
            })
            sw_risk_dist[train_risk] += cnt

    sw_eol_items.sort(key=lambda x: (-{"PAST EOL": 5, "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["effective_risk"], 0), -x["device_count"]))

    sw_score = ((sw_risk_dist.get("LOW", 0)) / total * 100) if total else 100

    # ── Security analysis ────────────────────────────────────────────────
    sec_risk_dist = Counter()
    sec_top_devices = []
    total_psirt = 0
    for d in devices:
        psirt = int(d.get("PSIRT Vulnerable Alerts", 0) or 0)
        fn = int(d.get("FN Vulnerable Alerts", 0) or 0)
        hw_eox = int(d.get("Hardware EoX Alerts", 0) or 0)
        cbp = int(d.get("CBP Alerts", 0) or 0)
        sw_al = int(d.get("Software Alerts", 0) or 0)
        total_psirt += psirt
        risk = classify_psirt(psirt)
        # Compound: legacy train + high PSIRT → escalate
        ver = d.get("Software Version", "")
        if (ver.startswith("16.") or ver.startswith("9.3")) and psirt >= 6:
            risk = "CRITICAL"
        sec_risk_dist[risk] += 1
        sec_top_devices.append({
            "device": d["Device Name"], "pid": d["Product ID"],
            "sw": f'{d["Software Type"]} {d["Software Version"]}',
            "psirt": psirt, "fn": fn, "hw_eox": hw_eox, "cbp": cbp, "sw_alerts": sw_al,
            "risk": risk,
        })
    sec_top_devices.sort(key=lambda x: (-x["psirt"], -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}.get(x["risk"], 0)))

    sec_score = ((sec_risk_dist.get("NONE", 0) + sec_risk_dist.get("LOW", 0)) / total * 100) if total else 100

    # ── PSIRT advisory analysis (from openVuln API) ──────────────────────
    # Build a lookup: version → recommended golden version from sw_reco
    psirt_by_version = []
    total_api_advisories = 0
    total_critical_high = 0
    for ver_key, cnt in sw_ver_counter.most_common():
        sw_type, version = ver_key.split("|", 1)
        key = f"{sw_type}|{version}"

        # Check if this version is past EoVSS
        api_eol = sw_eol_map.get(version, {})
        eovss_date_str = api_eol.get("end_of_sec_vuln", "") or ""
        past_eovss = False
        if eovss_date_str:
            try:
                eovss_date = datetime.strptime(eovss_date_str, "%Y-%m-%d").date()
                past_eovss = eovss_date < assess_date
            except ValueError:
                pass

        reco_ver = sw_type_to_reco.get(sw_type, "N/A")

        if past_eovss:
            # Version is past EoVSS — don't list individual advisories,
            # just recommend upgrading to the golden version
            psirt_by_version.append({
                "sw_type": sw_type, "version": version, "device_count": cnt,
                "past_eovss": True,
                "eovss_date": eovss_date_str,
                "recommended_version": reco_ver,
                "total_advisories": 0,
                "by_severity": {},
                "top_advisories": [],
            })
            continue

        pdata = psirt_map.get(key)
        if pdata:
            total_api_advisories += pdata["total"]
            crit = pdata["by_severity"].get("Critical", 0)
            high = pdata["by_severity"].get("High", 0)
            total_critical_high += crit + high
            psirt_by_version.append({
                "sw_type": sw_type, "version": version, "device_count": cnt,
                "past_eovss": False,
                "total_advisories": pdata["total"],
                "by_severity": pdata["by_severity"],
                "top_advisories": pdata["top_advisories"],
            })
    # Sort: past-EoVSS first, then by total advisories descending
    psirt_by_version.sort(key=lambda x: (0 if x.get("past_eovss") else 1, -x["total_advisories"]))

    # ── Field notice analysis ────────────────────────────────────────────
    fn_risk_dist = Counter()
    fn_top_devices = []
    for d in devices:
        fn_count = int(d.get("FN Vulnerable Alerts", 0) or 0)
        risk = classify_fn(fn_count)
        fn_risk_dist[risk] += 1
        if fn_count > 0:
            fn_top_devices.append({
                "device": d["Device Name"], "pid": d["Product ID"],
                "sw": f'{d["Software Type"]} {d["Software Version"]}',
                "fn_alerts": fn_count, "risk": risk,
            })
    fn_top_devices.sort(key=lambda x: -x["fn_alerts"])
    fn_score = ((fn_risk_dist.get("NONE", 0) + fn_risk_dist.get("LOW", 0)) / total * 100) if total else 100

    # ── Software conformance ─────────────────────────────────────────────
    conf_dist = Counter()
    conf_family = defaultdict(lambda: {"compliant": 0, "acceptable": 0, "non_compliant": 0, "total": 0, "versions": Counter()})
    for d in devices:
        family = normalize_pid(d["Product ID"])
        ver = d["Software Version"]
        rec = sw_reco.get(family)
        if rec:
            if ver == rec["recommended"]:
                status = "COMPLIANT"
            elif ver == rec["previous"]:
                status = "ACCEPTABLE"
            else:
                status = "NON-COMPLIANT"
        else:
            status = "NON-COMPLIANT"
        conf_dist[status] += 1
        s = conf_family[family]
        s["total"] += 1
        s["versions"][ver] += 1
        s[status.lower().replace("-", "_")] += 1

    conf_score = ((conf_dist.get("COMPLIANT", 0) + conf_dist.get("ACCEPTABLE", 0) * 0.5) / total * 100) if total else 100

    # Contract coverage placeholder (no data available)
    contract_score = 50  # neutral assumption

    # ── Overall health score ─────────────────────────────────────────────
    health_score = round(
        hw_score * DOMAIN_WEIGHTS["hw_eol"] +
        sw_score * DOMAIN_WEIGHTS["sw_eol"] +
        sec_score * DOMAIN_WEIGHTS["security"] +
        fn_score * DOMAIN_WEIGHTS["field_notice"] +
        conf_score * DOMAIN_WEIGHTS["conformance"] +
        contract_score * DOMAIN_WEIGHTS["contract"],
        1
    )
    if health_score >= 80:   health_grade = "Healthy"
    elif health_score >= 60: health_grade = "Moderate Risk"
    elif health_score >= 40: health_grade = "Elevated Risk"
    else:                    health_grade = "Critical Risk"

    # ── Assemble JSON ────────────────────────────────────────────────────
    data = {
        "meta": {
            "customer": customer,
            "assessment_date": assess_date.strftime("%Y-%m-%d"),
            "total_devices_analyzed": total,
            "total_devices_excluded": len(excluded),
            "unique_pids": len(pid_counter),
            "unique_sw_versions": len(sw_ver_counter),
            "sites": len(site_counter),
        },
        "fleet_composition": {
            "by_platform_family": [{"family": f, "count": c, "pct": round(c / total * 100, 1)}
                                   for f, c in family_counter.most_common()],
            "by_product_id": [{"pid": p, "family": platform_family_name(p), "count": c}
                              for p, c in pid_counter.most_common()],
            "by_sw_type": [{"sw_type": s, "count": c} for s, c in sw_type_counter.most_common()],
            "by_sw_version": [{"sw_type": k.split("|")[0], "version": k.split("|")[1], "count": c}
                              for k, c in sw_ver_counter.most_common()],
            "top_sites": [{"site": s, "count": c} for s, c in site_counter.most_common(20)],
        },
        "hw_eol": {
            "domain_score": round(hw_score, 1),
            "pids_with_eol": len(hw_eol_items),
            "devices_affected": hw_affected,
            "risk_distribution": dict(hw_risk_dist),
            "eol_details": hw_eol_items[:20],  # top 20 for LLM context
            "no_eol_pids": no_eol_pids,
        },
        "sw_eol": {
            "domain_score": round(sw_score, 1),
            "risk_distribution": dict(sw_risk_dist),
            "eol_details": sw_eol_items,
        },
        "security": {
            "domain_score": round(sec_score, 1),
            "total_psirt_alerts": total_psirt,
            "avg_psirt_per_device": round(total_psirt / total, 1) if total else 0,
            "risk_distribution": dict(sec_risk_dist),
            "top_20_devices": sec_top_devices[:20],
        },
        "psirt_advisories": {
            "total_advisories_from_api": total_api_advisories,
            "total_critical_high": total_critical_high,
            "by_version": psirt_by_version,
        },
        "field_notices": {
            "domain_score": round(fn_score, 1),
            "risk_distribution": dict(fn_risk_dist),
            "top_20_devices": fn_top_devices[:20],
        },
        "conformance": {
            "domain_score": round(conf_score, 1),
            "distribution": dict(conf_dist),
            "by_family": {
                fam: {
                    "compliant": s["compliant"], "acceptable": s["acceptable"],
                    "non_compliant": s["non_compliant"], "total": s["total"],
                    "recommended": sw_reco.get(fam, {}).get("recommended", "N/A"),
                    "previous": sw_reco.get(fam, {}).get("previous", "N/A"),
                    "running_versions": dict(s["versions"]),
                }
                for fam, s in sorted(conf_family.items())
            },
        },
        "overall_health": {
            "score": health_score,
            "grade": health_grade,
            "domain_scores": {
                "hw_eol": round(hw_score, 1),
                "sw_eol": round(sw_score, 1),
                "security": round(sec_score, 1),
                "field_notice": round(fn_score, 1),
                "conformance": round(conf_score, 1),
                "contract": contract_score,
            },
        },
    }
    return data

# ═══════════════════════════════════════════════════════════════════════════
# STAGE 2: LLM ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a senior Cisco CX Architect performing an AI-driven network lifecycle and security assessment. You will receive structured JSON data containing:
- Fleet composition (devices by platform, software, site)
- Hardware End-of-Life data from Cisco EoX API (real dates, bulletin numbers)
- Software End-of-Life data from Cisco EoX API (real dates, bulletin numbers)
- PSIRT advisory data from Cisco openVuln API (real CVEs, CVSS scores, advisory IDs, first-fixed versions per software version)
- Security vulnerability exposure (PSIRT alert counts per device from inventory)
- Field Notice exposure (FN alert counts per device)
- Software conformance audit (running vs recommended versions)
- Overall health score

Your job is to write the ANALYSIS sections of the assessment report. You must:

1. **Executive Summary** — 3-4 paragraphs written for a CIO/VP audience. Cover the overall health posture, the most critical risks, and the top recommended actions. Reference specific numbers from the data. Do NOT be generic — tie every statement to actual data points.

2. **Hardware EoL Analysis** — For the top 3 HW risks, write specific analysis: what's the business impact of each, what's the migration path, what's the urgency. Reference the Cisco bulletin numbers and actual dates.

3. **Software EoL Analysis** — Analyze the SW EoL posture. If Cisco has announced EoL for running versions (bulletin data provided), call it out explicitly. Explain what "End of Security Vulnerability Support" means for the customer. Call out the migration strategy from Cisco.

4. **Security Posture Analysis** — This section now has REAL advisory data from Cisco PSIRT openVuln API. Analyze the actual CVE exposure per software version. Reference specific advisory IDs, CVSS scores, and first-fixed versions. Identify which software versions have the most Critical/High advisories. Explain the remediation path using the first-fixed versions provided.

5. **Software Conformance Analysis** — Analyze the gap between running and recommended. For each platform family, explain what they're running vs what they should be running. Prioritize the upgrade recommendations.

6. **Cross-Domain Risk Correlation** — This is where AI adds value. Identify software versions that appear in MULTIPLE risk categories simultaneously (e.g., SW EoL announced + high PSIRT advisory count + non-compliant). Correlate the PSIRT advisory data with EoL dates — versions past security vulnerability support end date with open Critical advisories are the highest risk.

7. **Remediation Roadmap** — Write a specific 30/60/90-day action plan. Each action must reference specific PIDs, software versions, device counts, and target states. Use the first-fixed versions from PSIRT data to recommend specific upgrade targets.

RULES:
- Every claim must reference actual numbers from the JSON data
- Never fabricate Cisco bulletin numbers, dates, or CVE IDs
- You MAY reference advisory IDs and CVEs from the psirt_advisories data — these are real
  Cisco PSIRT advisories, filtered to Critical/High severity, remote + unauthenticated only, last 2 years.
  Versions past End-of-Vulnerability-Security-Support (EoVSS) have no individual advisories listed —
  for those, recommend upgrading to the golden version shown in the data.
- If data is missing (e.g., no contract coverage data), say so explicitly
- Write for both executive and engineering audiences — clear language, specific technical details
- Use Markdown formatting with headers, bold, bullet points
- Do NOT output tables — the data tables will be assembled separately from the raw data
- Do NOT repeat the raw data — analyze it, correlate it, draw conclusions"""


def _trim_json_for_llm(data_json):
    """Create a trimmed copy of the assessment JSON for LLM context.

    The full JSON can be 100KB+ with PSIRT advisory details. The LLM only needs
    summaries and top items — the full data goes into the report tables directly.
    """
    import copy
    trimmed = copy.deepcopy(data_json)

    # Trim PSIRT: keep per-version summary but limit top_advisories to top 5
    psirt = trimmed.get("psirt_advisories", {})
    for pv in psirt.get("by_version", []):
        top = pv.get("top_advisories", [])
        # Keep only top 5 advisories per version, slim them down
        pv["top_advisories"] = [
            {
                "advisoryId": a["advisoryId"],
                "sir": a["sir"],
                "cvssBaseScore": a["cvssBaseScore"],
                "cves": a.get("cves", [])[:2],
                "firstFixed": a.get("firstFixed", [])[:2],
            }
            for a in top[:5]
        ]

    # Trim security top_20_devices to top 10
    sec = trimmed.get("security", {})
    sec["top_20_devices"] = sec.get("top_20_devices", [])[:10]

    # Trim field notices top_20_devices to top 10
    fn = trimmed.get("field_notices", {})
    fn["top_20_devices"] = fn.get("top_20_devices", [])[:10]

    # Trim fleet composition details
    fleet = trimmed.get("fleet_composition", {})
    fleet.pop("top_sites", None)

    return trimmed


def call_ollama(data_json, model, base_url):
    """Call local Ollama API. All data stays on your machine."""
    model = model or "llama3.1:8b"
    url = f"{base_url}/api/chat"

    # Trim JSON to fit within LLM context window
    llm_data = _trim_json_for_llm(data_json)

    user_content = (
        f"Here is the structured assessment data for {llm_data['meta']['customer']}. "
        f"Analyze it and write the assessment report sections.\n\n"
        f"```json\n{json.dumps(llm_data, indent=2)}\n```"
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_ctx": 32768,
        },
    }

    resp = _requests.post(url, json=payload, timeout=600)
    resp.raise_for_status()
    content = resp.json()["message"]["content"]

    # Strip markdown code fences some models wrap their output in
    content = re.sub(r"^```(?:markdown)?\s*\n", "", content)
    content = re.sub(r"\n```\s*$", "", content)
    # Strip <think>...</think> blocks from reasoning models (e.g., DeepSeek R1)
    content = re.sub(r"<think>.*?</think>\s*", "", content, flags=re.DOTALL)

    return content


def run_llm_analysis(data_json, provider, model, ollama_url="http://localhost:11434"):
    """Dispatch to the appropriate LLM provider."""
    if provider == "ollama":
        return call_ollama(data_json, model, ollama_url)
    return None

# ═══════════════════════════════════════════════════════════════════════════
# STAGE 3: REPORT ASSEMBLY
# ═══════════════════════════════════════════════════════════════════════════

def assemble_report(data, ai_analysis, assess_date, output_path):
    """Combine AI analysis with structured data tables into final .md report."""
    lines = []
    w = lines.append

    customer = data["meta"]["customer"]
    total = data["meta"]["total_devices_analyzed"]
    excluded = data["meta"]["total_devices_excluded"]
    health = data["overall_health"]

    # ── Cover ────────────────────────────────────────────────────────────
    w("# Cisco CX AI Network Lifecycle & Security Assessment Report")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| **Customer** | {customer} |")
    w(f"| **Assessment Date** | {assess_date.strftime('%B %d, %Y')} |")
    w(f"| **Report Version** | 3.0 |")
    w(f"| **Generated By** | Cisco CX AI Assessment Engine |")
    w(f"| **Total Devices Analyzed** | {total} |")
    w(f"| **Devices Excluded** | {excluded} |")
    w(f"| **Overall Health Score** | **{health['score']}/100** — {health['grade']} |")
    w("")
    w("---")
    w("")

    # ── Domain Score Summary ─────────────────────────────────────────────
    def score_icon(s):
        if s >= 80: return "🟢"
        if s >= 60: return "🟡"
        if s >= 40: return "🟠"
        return "🔴"

    w("### Domain Health Scores")
    w("")
    w("| Domain | Score | Grade |")
    w("|--------|-------|-------|")
    for domain, label in [("hw_eol", "Hardware End-of-Life"), ("sw_eol", "Software End-of-Life"),
                          ("security", "Security Vulnerabilities"), ("field_notice", "Field Notices"),
                          ("conformance", "Software Conformance"), ("contract", "Contract Coverage")]:
        s = health["domain_scores"][domain]
        w(f"| {label} | {score_icon(s)} **{s}**/100 | {'Healthy' if s >= 80 else 'Moderate' if s >= 60 else 'Elevated' if s >= 40 else 'Critical'} |")
    w("")
    w("---")
    w("")

    # ── AI Analysis ──────────────────────────────────────────────────────
    if ai_analysis:
        w("## AI-Driven Analysis")
        w("")
        w(ai_analysis)
        w("")
        w("---")
        w("")

    # ═════════════════════════════════════════════════════════════════════
    # DATA TABLES (structured, always present regardless of LLM)
    # ═════════════════════════════════════════════════════════════════════

    # ── Fleet composition tables ─────────────────────────────────────────
    w("## Fleet Analytics")
    w("")
    w("### Devices by Platform Family")
    w("")
    w("| Platform Family | Count | % |")
    w("|----------------|-------|---|")
    for f in data["fleet_composition"]["by_platform_family"]:
        w(f'| {f["family"]} | {f["count"]} | {f["pct"]}% |')
    w("")

    w("### Devices by Product ID")
    w("")
    w("| Product ID | Platform Family | Count |")
    w("|-----------|----------------|-------|")
    for p in data["fleet_composition"]["by_product_id"]:
        w(f'| {p["pid"]} | {p["family"]} | {p["count"]} |')
    w("")

    w("### Devices by Software Version")
    w("")
    w("| Software Type | Version | Count |")
    w("|--------------|---------|-------|")
    for v in data["fleet_composition"]["by_sw_version"]:
        w(f'| {v["sw_type"]} | {v["version"]} | {v["count"]} |')
    w("")

    # ── HW EoL table ────────────────────────────────────────────────────
    w("## Hardware End-of-Life Data")
    w("")
    hw = data["hw_eol"]
    if hw["eol_details"]:
        w(f'> **{hw["pids_with_eol"]}** PIDs with active EoL bulletins affecting **{hw["devices_affected"]}** devices.')
        w("")
        w("| Product ID | Description | Bulletin | End-of-Sale | LDoS | Days Left | Risk | Migration PID | Devices |")
        w("|-----------|------------|---------|-------------|------|----------|------|--------------|---------|")
        for e in hw["eol_details"]:
            icon = RISK_ICON.get(e["risk"], "")
            days = str(e["days_remaining"]) if e["days_remaining"] != 99999 else "N/A"
            desc = e.get("description", "")[:50]
            w(f'| {e["pid"]} | {desc} | {e["bulletin"]} | {e["end_of_sale"]} | {e["last_date_of_support"]} | {days} | {icon} **{e["risk"]}** | {e["migration_pid"]} | {e["device_count"]} |')
        w("")

    if hw["no_eol_pids"]:
        w("### PIDs with No EoL Announcement")
        w("")
        w("| Product ID | Platform Family | Count |")
        w("|-----------|----------------|-------|")
        for e in hw["no_eol_pids"]:
            w(f'| {e["pid"]} | {e["family"]} | {e["count"]} |')
        w("")

    # ── SW EoL table ────────────────────────────────────────────────────
    w("## Software End-of-Life Data")
    w("")
    sw = data["sw_eol"]
    w("| SW Type | Version | Count | Train Status | EoL Bulletin | LDoS | Sec Vuln End | Recommended Upgrade | Risk |")
    w("|--------|---------|-------|-------------|-------------|------|------------|-----------|------|")
    for e in sw["eol_details"]:
        icon = RISK_ICON.get(e["effective_risk"], "")
        bulletin = e["api_eol_bulletin"] or "—"
        ldos = e["api_eol_ldos"] or "—"
        sec_end = e["api_eol_sec_vuln_end"] or "—"
        reco_ver = e.get("recommended_version", "N/A")
        if reco_ver and reco_ver != "N/A":
            migration = f"Upgrade to {e['sw_type']} {reco_ver}"
        else:
            migration = "—"
        w(f'| {e["sw_type"]} | {e["version"]} | {e["device_count"]} | {e["train_status"]} | {bulletin} | {ldos} | {sec_end} | {migration} | {icon} **{e["effective_risk"]}** |')
    w("")

    # ── Security table ──────────────────────────────────────────────────
    w("## Security Vulnerability Data")
    w("")
    sec = data["security"]
    w(f'> Total PSIRT alerts across fleet: **{sec["total_psirt_alerts"]}** | Average per device: **{sec["avg_psirt_per_device"]}**')
    w("")
    w("### Risk Distribution")
    w("")
    w("| Risk Level | Devices | % |")
    w("|-----------|---------|---|")
    for rl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        cnt = sec["risk_distribution"].get(rl, 0)
        pct = round(cnt / total * 100, 1) if total else 0
        w(f'| {RISK_ICON.get(rl, "")} **{rl}** | {cnt} | {pct}% |')
    w("")

    w("### Top 20 Highest Risk Devices")
    w("")
    w("| Device | Product ID | Software | PSIRT | FN | HW EoX | CBP | Risk |")
    w("|--------|-----------|----------|-------|----|----|-----|------|")
    for e in sec["top_20_devices"]:
        icon = RISK_ICON.get(e["risk"], "")
        w(f'| {e["device"]} | {e["pid"]} | {e["sw"]} | {e["psirt"]} | {e["fn"]} | {e["hw_eox"]} | {e["cbp"]} | {icon} **{e["risk"]}** |')
    w("")

    # ── PSIRT Advisory tables (from openVuln API) ───────────────────────
    psirt_data = data.get("psirt_advisories", {})
    psirt_versions = psirt_data.get("by_version", [])
    if psirt_versions:
        w("## PSIRT Advisory Data (Cisco openVuln API)")
        w("")
        total_api = psirt_data.get("total_advisories_from_api", 0)
        total_ch = psirt_data.get("total_critical_high", 0)
        w(f"> **{total_api}** Critical/High remote-exploitable advisories across all software versions")
        w("")

        # Summary table: advisories per SW version
        w("### Advisories by Software Version")
        w("")
        w("> Filters: Critical/High severity only · Remote + unauthenticated exploits · Published within last 2 years")
        w("> Versions past End-of-Vulnerability-Security-Support (EoVSS) are flagged for upgrade.")
        w("")
        w("| SW Type | Version | Devices | Total Advisories | Critical | High | Medium | Low | Note |")
        w("|--------|---------|---------|-----------------|----------|------|--------|-----|------|")
        for pv in psirt_versions:
            if pv.get("past_eovss"):
                reco = pv.get('recommended_version', 'N/A')
                eovss = pv.get('eovss_date', '—')
                w(f'| {pv["sw_type"]} | {pv["version"]} | {pv["device_count"]} '
                  f'| — | — | — | — | — '
                  f'| ⚠️ Past EoVSS ({eovss}) — upgrade to {pv["sw_type"]} {reco} |')
            else:
                sev = pv["by_severity"]
                w(f'| {pv["sw_type"]} | {pv["version"]} | {pv["device_count"]} '
                  f'| {pv["total_advisories"]} '
                  f'| {sev.get("Critical", 0)} '
                  f'| {sev.get("High", 0)} '
                  f'| {sev.get("Medium", 0)} '
                  f'| {sev.get("Low", 0)} | |')
        w("")

        # Top advisories detail table (collect across all versions, deduplicate)
        # Skip past-EoVSS versions (they have no individual advisories)
        seen_ids = set()
        all_top = []
        for pv in psirt_versions:
            if pv.get("past_eovss"):
                continue
            for adv in pv.get("top_advisories", []):
                aid = adv["advisoryId"]
                if aid not in seen_ids:
                    seen_ids.add(aid)
                    all_top.append({**adv, "_sw": f'{pv["sw_type"]} {pv["version"]}'})
        # Sort by CVSS descending
        all_top.sort(key=lambda a: float(a.get("cvssBaseScore") or "0"), reverse=True)
        if all_top:
            w("### Top Security Advisories — Remote Unauthenticated (by CVSS Score)")
            w("")
            w("| SIR | CVSS | Advisory ID | Title | CVEs | First Fixed | Affects |")
            w("|-----|------|-------------|-------|------|-------------|---------|")
            for adv in all_top[:15]:
                sir_icon = RISK_ICON.get(adv["sir"].upper(), "")
                cves = ", ".join(adv.get("cves", [])[:3])
                if len(adv.get("cves", [])) > 3:
                    cves += "…"
                ff = ", ".join(adv.get("firstFixed", [])[:3]) or "N/A"
                title = adv.get("title", "")[:60]
                w(f'| {sir_icon} **{adv["sir"]}** | {adv["cvssBaseScore"]} '
                  f'| {adv["advisoryId"]} | {title} '
                  f'| {cves} | {ff} | {adv["_sw"]} |')
            w("")

    # ── Field Notice table ──────────────────────────────────────────────
    w("## Field Notice Data")
    w("")
    fn = data["field_notices"]
    w("| Risk Level | Devices |")
    w("|-----------|---------|")
    for rl in ["HIGH", "MEDIUM", "LOW", "NONE"]:
        w(f'| {RISK_ICON.get(rl, "")} **{rl}** | {fn["risk_distribution"].get(rl, 0)} |')
    w("")

    if fn["top_20_devices"]:
        w("### Devices with Active Field Notices")
        w("")
        w("| Device | Product ID | Software | FN Alerts | Risk |")
        w("|--------|-----------|----------|----------|------|")
        for e in fn["top_20_devices"][:20]:
            icon = RISK_ICON.get(e["risk"], "")
            w(f'| {e["device"]} | {e["pid"]} | {e["sw"]} | {e["fn_alerts"]} | {icon} **{e["risk"]}** |')
        w("")

    # ── Conformance table ───────────────────────────────────────────────
    w("## Software Conformance Data")
    w("")
    conf = data["conformance"]
    w("| Status | Count | % |")
    w("|--------|-------|---|")
    for status in ["COMPLIANT", "ACCEPTABLE", "NON-COMPLIANT"]:
        cnt = conf["distribution"].get(status, 0)
        pct = round(cnt / total * 100, 1) if total else 0
        w(f'| {RISK_ICON.get(status, "")} **{status}** | {cnt} | {pct}% |')
    w("")

    w("### Conformance by Platform Family")
    w("")
    w("| Family | Running Versions | Recommended | Previous | Compliant | Acceptable | Non-Compliant | Total |")
    w("|--------|-----------------|-------------|----------|----------|-----------|--------------|-------|")
    for fam, s in sorted(conf["by_family"].items()):
        vers = ", ".join(f"{v}({c})" for v, c in sorted(s["running_versions"].items(), key=lambda x: -x[1])[:3])
        w(f'| {fam} | {vers} | {s["recommended"]} | {s["previous"]} | {s["compliant"]} | {s["acceptable"]} | {s["non_compliant"]} | {s["total"]} |')
    w("")

    # ── Footer ──────────────────────────────────────────────────────────
    w("---")
    w("")
    w(f"*Report generated by Cisco CX AI Assessment Engine v3.0 — {assess_date.strftime('%B %d, %Y')}*")
    w("")
    w("*Data Sources: Cisco EoX API (HW & SW), Cisco PSIRT openVuln API, Cisco Architect Software Recommendations, CSPC/BCI Inventory Telemetry*")
    if ai_analysis:
        w("")
        w("*AI analysis powered by local LLM (Ollama). All customer data processed on-premises — no data sent to external cloud services.*")

    report_text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    return report_text

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    args = parse_args()
    assess_date = datetime.strptime(args.date, "%Y-%m-%d").date() if args.date else date.today()

    if args.output:
        output_path = args.output
    else:
        safe = args.customer.replace(" ", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"{safe}_CX_Assessment_{timestamp}.md"

    json_path = output_path.replace(".md", "_data.json")

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   Cisco CX AI Assessment Engine v3.0                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Customer:  {args.customer:<48}║")
    print(f"║  Inventory: {args.inventory:<48}║")
    print(f"║  LLM:       {args.llm:<48}║")
    print(f"║  Date:      {assess_date.strftime('%Y-%m-%d'):<48}║")
    print(f"║  Output:    {output_path:<48}║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    # ── Stage 1: Data Collection ─────────────────────────────────────────
    print("━━━ STAGE 1: DATA COLLECTION ━━━")
    print()

    print("  [1/4] Loading inventory...")
    devices, excluded = load_inventory(args.inventory)
    print(f"    ✅ {len(devices)} valid devices, {len(excluded)} excluded")

    print("  [2/4] Loading software recommendations...")
    sw_reco = load_sw_recommendations(args.sw_reco)
    print(f"    ✅ {len(sw_reco)} platform baselines")

    hw_eol_map = {}
    sw_eol_map = {}
    psirt_map = {}
    api_id = os.getenv("CISCO_API_ID")
    api_secret = os.getenv("CISCO_API_SECRET")

    if args.skip_api:
        print("  [3/5] Skipping Cisco APIs (--skip-api)")
    elif not api_id or not api_secret:
        print("  [3/5] ⚠️  CISCO_API_ID / CISCO_API_SECRET not set — skipping APIs")
    else:
        unique_pids = sorted(set(d["Product ID"] for d in devices))
        unique_sw_versions = sorted(set(d["Software Version"] for d in devices))

        print(f"  [3/5] Querying Cisco EoX APIs...")
        print(f"    → Hardware EoL ({len(unique_pids)} unique PIDs)...")
        hw_eol_map = query_eox_by_pid(unique_pids, api_id, api_secret)
        print(f"    ✅ {len(hw_eol_map)} PIDs with EoL bulletins")

        print(f"    → Software EoL ({len(unique_sw_versions)} unique versions)...")
        sw_eol_map = query_eox_by_sw(unique_sw_versions, api_id, api_secret)
        print(f"    ✅ {len(sw_eol_map)} versions with EoL bulletins")

    if args.skip_api or args.skip_psirt:
        if not args.skip_api:
            print("  [4/5] Skipping PSIRT API (--skip-psirt)")
    elif api_id and api_secret:
        # Build sw_versions_by_type for PSIRT query
        sw_versions_by_type = defaultdict(set)
        for d in devices:
            sw_type = d["Software Type"]
            ver = d["Software Version"]
            if sw_type in SW_TYPE_TO_OSTYPE:
                sw_versions_by_type[sw_type].add(ver)
        sw_versions_by_type = {k: sorted(v) for k, v in sw_versions_by_type.items()}
        query_count = sum(len(v) for v in sw_versions_by_type.values())

        print(f"  [4/5] Querying Cisco PSIRT openVuln API ({query_count} versions)...")
        psirt_map = query_psirt_by_sw(sw_versions_by_type, api_id, api_secret)
        total_adv = sum(p["total"] for p in psirt_map.values())
        print(f"    ✅ {len(psirt_map)} versions queried, {total_adv} total advisories")

    print("  [5/5] Building assessment data structure...")
    data = build_assessment_json(devices, excluded, hw_eol_map, sw_eol_map,
                                 psirt_map, sw_reco, args.customer, assess_date)
    print(f"    ✅ Overall Health Score: {data['overall_health']['score']}/100 ({data['overall_health']['grade']})")

    if args.save_json:
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"    📄 JSON saved: {json_path}")

    print()

    # ── Stage 2: AI Analysis ─────────────────────────────────────────────
    print("━━━ STAGE 2: AI ANALYSIS ━━━")
    print()

    ai_analysis = None
    if args.llm == "none":
        print("  Skipping LLM analysis (--llm none)")
        print("  Report will contain data tables only, no AI-written analysis.")
    elif args.llm == "ollama":
        # Verify Ollama is reachable
        try:
            _requests.get(f"{args.ollama_url}/api/tags", timeout=5)
        except Exception:
            print(f"  ❌ Ollama not reachable at {args.ollama_url}")
            print(f"  Start it with: ollama serve")
            print(f"  Falling back to data-only report.")
            args.llm = "none"

        if args.llm != "none":
            model_name = args.model or "llama3.1:8b"
            print(f"  🔒 LOCAL LLM — No customer data leaves this machine")
            print(f"  Sending assessment data to Ollama ({model_name})...")
            try:
                ai_analysis = run_llm_analysis(data, args.llm, args.model, args.ollama_url)
                word_count = len(ai_analysis.split()) if ai_analysis else 0
                print(f"    ✅ AI analysis received ({word_count} words)")
            except Exception as e:
                print(f"    ❌ Ollama error: {e}")
                print("    Falling back to data-only report.")

    print()

    # ── Stage 3: Report Assembly ─────────────────────────────────────────
    print("━━━ STAGE 3: REPORT ASSEMBLY ━━━")
    print()

    assemble_report(data, ai_analysis, assess_date, output_path)
    line_count = sum(1 for _ in open(output_path))
    print(f"  ✅ Report written: {output_path} ({line_count} lines)")

    if ai_analysis:
        print(f"  🤖 Includes AI-driven analysis from {args.llm}")
    else:
        print(f"  📊 Data-only report (no AI analysis)")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
