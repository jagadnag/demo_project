#!/usr/bin/env python3
"""
Cisco CX AI Network Lifecycle & Security Assessment Report Generator v2.0

Scalable, engineer-ready tool that:
  1. Reads any customer inventory CSV (CSPC / BCI Portal export)
  2. Queries Cisco EoX API for live hardware end-of-life data
  3. Cross-references software conformance against recommended baselines
  4. Generates a professional Markdown report with full analysis

Usage:
  export CISCO_API_ID="<your_id>"
  export CISCO_API_SECRET="<your_secret>"
  python3 generate_cx_report.py --inventory bt.csv --customer "BT Enterprise"

Requirements:
  pip install cisco_support requests tabulate
"""

import csv
import os
import sys
import time
import json
import argparse
from datetime import date, datetime
from collections import Counter, defaultdict

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

SW_RECO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "software_recommendation.csv")

RISK_ICON = {
    "PAST EOL": "🔴", "CRITICAL": "🔴", "HIGH": "🟠",
    "MEDIUM": "🟡", "LOW": "🟢", "NO EOL": "⚪", "NONE": "⚪",
    "NON-COMPLIANT": "🔴", "ACCEPTABLE": "🟡", "COMPLIANT": "🟢",
}

# ═══════════════════════════════════════════════════════════════════════════
# CLI ARGUMENTS
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Cisco CX AI Assessment Report Generator v2.0")
    p.add_argument("--inventory", required=True,
                   help="Path to customer inventory CSV (CSPC/BCI export)")
    p.add_argument("--customer", default="Valued Customer",
                   help="Customer name for report branding")
    p.add_argument("--output", default=None,
                   help="Output .md file path (default: <customer>_CX_Report.md)")
    p.add_argument("--date", default=None,
                   help="Assessment date YYYY-MM-DD (default: today)")
    p.add_argument("--sw-reco", default=SW_RECO_FILE,
                   help="Path to software_recommendation.csv")
    p.add_argument("--skip-api", action="store_true",
                   help="Skip live API calls; use only inventory data")
    return p.parse_args()

# ═══════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════

def load_inventory(csv_path):
    """Load and cleanse inventory. Exclude null PIDs and missing SW versions."""
    all_rows = []
    excluded = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pid = (row.get("Product ID") or "").strip()
            sw_ver = (row.get("Software Version") or "").strip()
            sw_type = (row.get("Software Type") or "").strip()
            if (not pid or pid.lower() == "null" or
                not sw_ver or sw_ver in ("Not Found", "Missing", "null", "") or
                not sw_type or sw_type in ("Missing", "null", "")):
                excluded.append(row)
            else:
                all_rows.append(row)
    return all_rows, excluded


def load_sw_recommendations(csv_path):
    """Load software recommendation baselines."""
    reco = {}
    if not os.path.exists(csv_path):
        print(f"[WARN] Software recommendation file not found: {csv_path}")
        return reco
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            reco[row["Product ID"]] = {
                "sw_type": row["Software Type"],
                "recommended": row["Recommended Version"],
                "previous": row["Previous Recommended Version"],
            }
    return reco

# ═══════════════════════════════════════════════════════════════════════════
# PID NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def normalize_pid(pid):
    """Map a specific PID to its platform family for SW recommendation matching."""
    pid_upper = pid.upper()
    if pid_upper.startswith("C9500"):
        return "C9500"
    if pid_upper.startswith("C9410") or pid_upper.startswith("C9407") or pid_upper.startswith("C9404"):
        return "C9410"
    if pid_upper.startswith("C9300"):
        return "C9300"
    if pid_upper.startswith("C9200"):
        return "C9200"
    if pid_upper.startswith("ASR"):
        return "ASR1000"
    if pid_upper.startswith("C8") or pid_upper.startswith("CAT8"):
        return "Cat8000"
    if pid_upper.startswith("WS-C3560") or pid_upper.startswith("C3560"):
        return "C3560"
    if pid_upper.startswith("ISR"):
        return "ASR1000"  # same IOS-XE recommended release
    if pid_upper.startswith("N9K-C9504") or pid_upper.startswith("N9K-C9508"):
        return "N9K-C9504"
    if pid_upper.startswith("N9K-"):
        return "N9K-C93180"
    return pid


def platform_family_name(pid):
    """Human-friendly platform family name."""
    p = pid.upper()
    if p.startswith("C9410") or p.startswith("C9407") or p.startswith("C9404"):
        return "Catalyst 9400"
    if p.startswith("C9300"):
        return "Catalyst 9300"
    if p.startswith("C9500"):
        return "Catalyst 9500"
    if p.startswith("C9200"):
        return "Catalyst 9200"
    if p.startswith("C8"):
        return "Catalyst 8500"
    if p.startswith("WS-C3560") or p.startswith("C3560"):
        return "Catalyst 3560-CX"
    if p.startswith("ISR"):
        return "ISR 4000"
    if p.startswith("ASR"):
        return "ASR 1000"
    if p.startswith("N9K-"):
        return "Nexus 9000"
    return pid

# ═══════════════════════════════════════════════════════════════════════════
# CISCO SUPPORT API CALLS
# ═══════════════════════════════════════════════════════════════════════════

def query_eox_api(unique_pids, api_id, api_secret):
    """Query Cisco EoX API for hardware EoL data. Returns dict keyed by PID."""
    eol_map = {}
    try:
        from cisco_support import EoX
        eox = EoX(client_id=api_id, client_secret=api_secret)
        # Batch in groups of 20 (API limit)
        pid_list = list(unique_pids)
        for i in range(0, len(pid_list), 20):
            batch = pid_list[i:i+20]
            print(f"  [EoX] Querying batch {i//20+1}: {', '.join(batch[:5])}{'...' if len(batch)>5 else ''}")
            try:
                resp = eox.get_by_product_ids(batch)
                records = resp.get("EOXRecord", [])
                for rec in records:
                    pid_key = rec.get("EOLProductID", "")
                    if not pid_key:
                        continue
                    # Skip empty records (API returns placeholder for unknown PIDs)
                    ldos = rec.get("LastDateOfSupport", {}).get("value", "")
                    eos = rec.get("EndOfSaleDate", {}).get("value", "")
                    if not ldos and not eos:
                        continue
                    eol_map[pid_key] = {
                        "pid": pid_key,
                        "description": rec.get("ProductIDDescription", ""),
                        "bulletin": rec.get("ProductBulletinNumber", ""),
                        "announced": rec.get("EOXExternalAnnouncementDate", {}).get("value", ""),
                        "end_of_sale": eos,
                        "end_of_sw_maint": rec.get("EndOfSWMaintenanceReleases", {}).get("value", ""),
                        "end_of_sec_vuln": rec.get("EndOfSecurityVulSupportDate", {}).get("value", ""),
                        "end_of_svc_renewal": rec.get("EndOfServiceContractRenewal", {}).get("value", ""),
                        "last_date_of_support": ldos,
                        "migration_pid": rec.get("EOXMigrationDetails", {}).get("MigrationProductId", ""),
                        "migration_info": rec.get("EOXMigrationDetails", {}).get("MigrationInformation", ""),
                    }
            except Exception as e:
                print(f"  [EoX] API error for batch: {e}")
            if i + 20 < len(pid_list):
                time.sleep(1)  # rate limit courtesy
    except ImportError:
        print("  [EoX] cisco_support not installed. pip install cisco_support")
    except Exception as e:
        print(f"  [EoX] API initialization error: {e}")
    return eol_map


# ═══════════════════════════════════════════════════════════════════════════
# RISK CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════

def classify_hw_eol_risk(ldos_str, assess_date):
    """Classify hardware EoL risk by days to Last Date of Support."""
    if not ldos_str:
        return "NO EOL", 99999
    try:
        ldos = datetime.strptime(ldos_str, "%Y-%m-%d").date()
    except ValueError:
        return "NO EOL", 99999
    days = (ldos - assess_date).days
    if days < 0:
        return "PAST EOL", days
    if days < 180:
        return "CRITICAL", days
    if days < 365:
        return "HIGH", days
    if days < 730:
        return "MEDIUM", days
    return "LOW", days


def classify_psirt_risk(psirt_count):
    p = int(psirt_count) if psirt_count else 0
    if p >= 9:   return "CRITICAL"
    if p >= 6:   return "HIGH"
    if p >= 4:   return "MEDIUM"
    if p >= 1:   return "LOW"
    return "NONE"


def classify_fn_risk(fn_count):
    f = int(fn_count) if fn_count else 0
    if f >= 5:   return "HIGH"
    if f >= 3:   return "MEDIUM"
    if f >= 1:   return "LOW"
    return "NONE"


def sw_train_risk(sw_type, version):
    """Flag legacy software trains regardless of EoL announcement."""
    if sw_type == "IOS-XE" and version.startswith("16."):
        return "CRITICAL", "End-of-Life Train (IOS-XE 16.x)"
    if sw_type == "IOS-XE" and version.startswith("17.6."):
        return "HIGH", "Older Maintenance Train"
    if sw_type == "IOS-XE" and version.startswith("17.9."):
        return "MEDIUM", "Active Maintenance (behind recommended 17.12.x)"
    if sw_type == "IOS-XE" and version.startswith("17.12."):
        return "LOW", "Current Recommended Train"
    if sw_type == "IOS" and version.startswith("15."):
        return "HIGH", "Legacy IOS Train (limited maintenance)"
    if sw_type == "NX-OS" and version.startswith("9."):
        return "HIGH", "Legacy NX-OS Train (behind 10.x)"
    if sw_type == "NX-OS" and version.startswith("10.3"):
        return "MEDIUM", "Active (behind recommended 10.4)"
    if sw_type == "NX-OS" and version.startswith("10.4"):
        return "LOW", "Current Recommended Train"
    if sw_type == "IOS-XE":
        return "LOW", "Active"
    return "MEDIUM", "Review Required"

# ═══════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def generate_report(devices, excluded, eol_map, sw_reco,
                    customer, assess_date, output_path):
    """Generate the full Markdown report."""
    lines = []
    w = lines.append  # shorthand

    total_valid = len(devices)
    total_excluded = len(excluded)

    # ── Counters ─────────────────────────────────────────────────────────
    pid_counter = Counter()
    family_counter = Counter()
    sw_type_counter = Counter()
    sw_ver_counter = Counter()
    device_type_counter = Counter()
    image_counter = Counter()
    site_counter = Counter()

    for d in devices:
        pid = d["Product ID"]
        pid_counter[pid] += 1
        family_counter[platform_family_name(pid)] += 1
        sw_type_counter[d["Software Type"]] += 1
        sw_ver_counter[f'{d["Software Type"]} {d["Software Version"]}'] += 1
        device_type_counter[d.get("Type", "Unknown")] += 1
        image_counter[d.get("Image Name", "Unknown")] += 1
        # Extract site from device name (first token before first -)
        name = d.get("Device Name", "")
        site = name.split("-")[0] if "-" in name else name
        site_counter[site] += 1

    # ═════════════════════════════════════════════════════════════════════
    # COVER
    # ═════════════════════════════════════════════════════════════════════
    w(f"# Cisco CX AI Network Lifecycle & Security Assessment Report")
    w("")
    w(f"| | |")
    w(f"|---|---|")
    w(f"| **Customer** | {customer} |")
    w(f"| **Assessment Date** | {assess_date.strftime('%B %d, %Y')} |")
    w(f"| **Report Version** | 2.0 |")
    w(f"| **Generated By** | Cisco CX AI Assessment Engine |")
    w(f"| **Total Devices Analyzed** | {total_valid} |")
    w(f"| **Devices Excluded (unreachable/missing data)** | {total_excluded} |")
    w("")
    w("---")
    w("")

    # ═════════════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ═════════════════════════════════════════════════════════════════════
    w("## 1. Executive Summary")
    w("")
    w(f"This report presents a comprehensive AI-driven assessment of **{customer}**'s ")
    w(f"Cisco network infrastructure comprising **{total_valid}** managed devices ")
    w(f"across **{len(site_counter)}** sites. The assessment was conducted on ")
    w(f"**{assess_date.strftime('%B %d, %Y')}** and covers seven risk domains: ")
    w("Hardware End-of-Life, Software End-of-Life, Security Vulnerabilities, ")
    w("Field Notices, Software Conformance, and Overall Health.")
    w("")
    if total_excluded > 0:
        w(f"> **Note:** {total_excluded} devices were excluded from analysis due to ")
        w(f"> missing Product ID or unreachable status (Software Version = \"Not Found\").")
        w("")

    # ── Fleet composition summary ────────────────────────────────────────
    w("### Fleet Composition")
    w("")
    w("| Platform Family | Device Count | % of Fleet |")
    w("|----------------|-------------|-----------|")
    for fam, cnt in family_counter.most_common():
        pct = f"{cnt/total_valid*100:.1f}%"
        w(f"| {fam} | {cnt} | {pct} |")
    w("")

    # ── Compute domain risks for summary ─────────────────────────────────
    # HW EoL
    hw_past = 0; hw_crit = 0; hw_high = 0; hw_eol_devices = 0
    for pid, eol in eol_map.items():
        cnt = pid_counter.get(pid, 0)
        if cnt == 0:
            continue
        risk, _ = classify_hw_eol_risk(eol["last_date_of_support"], assess_date)
        if risk == "PAST EOL":
            hw_past += cnt
        elif risk == "CRITICAL":
            hw_crit += cnt
        elif risk == "HIGH":
            hw_high += cnt
        if risk in ("PAST EOL", "CRITICAL", "HIGH", "MEDIUM"):
            hw_eol_devices += cnt

    hw_risk_level = "🟢 LOW"
    if hw_past > 0:
        hw_risk_level = "🔴 CRITICAL"
    elif hw_crit > 0:
        hw_risk_level = "🔴 CRITICAL"
    elif hw_high > 0:
        hw_risk_level = "🟠 HIGH"
    elif hw_eol_devices > 0:
        hw_risk_level = "🟡 MEDIUM"

    # SW EoL / Train
    sw_crit = 0; sw_high = 0
    for ver_key, cnt in sw_ver_counter.items():
        parts = ver_key.split(" ", 1)
        if len(parts) < 2:
            continue
        risk, _ = sw_train_risk(parts[0], parts[1])
        if risk == "CRITICAL":
            sw_crit += cnt
        elif risk == "HIGH":
            sw_high += cnt

    sw_risk_level = "🟢 LOW"
    if sw_crit > 0:
        sw_risk_level = "🔴 CRITICAL"
    elif sw_high > 0:
        sw_risk_level = "🟠 HIGH"

    # Security
    sec_crit = 0; sec_high = 0; total_psirt = 0
    for d in devices:
        p = int(d.get("PSIRT Vulnerable Alerts", 0) or 0)
        total_psirt += p
        r = classify_psirt_risk(p)
        if r == "CRITICAL":
            sec_crit += 1
        elif r == "HIGH":
            sec_high += 1

    sec_risk_level = "🟢 LOW"
    if sec_crit > 0:
        sec_risk_level = "🔴 CRITICAL"
    elif sec_high > 0:
        sec_risk_level = "🟠 HIGH"

    # FN
    fn_high = sum(1 for d in devices if classify_fn_risk(d.get("FN Vulnerable Alerts", 0)) in ("HIGH",))
    fn_risk_level = "🟠 HIGH" if fn_high > 0 else "🟡 MEDIUM" if any(
        classify_fn_risk(d.get("FN Vulnerable Alerts", 0)) == "MEDIUM" for d in devices) else "🟢 LOW"

    # Conformance
    compliant = 0; acceptable = 0; non_compliant = 0
    for d in devices:
        family = normalize_pid(d["Product ID"])
        rec = sw_reco.get(family)
        if rec:
            ver = d["Software Version"]
            if ver == rec["recommended"]:
                compliant += 1
            elif ver == rec["previous"]:
                acceptable += 1
            else:
                non_compliant += 1
        else:
            non_compliant += 1

    conf_pct = compliant / total_valid * 100 if total_valid else 0
    conf_risk = "🟢 LOW" if conf_pct >= 80 else "🟡 MEDIUM" if conf_pct >= 50 else "🟠 HIGH" if conf_pct >= 20 else "🔴 CRITICAL"

    w("### Overall Risk Posture")
    w("")
    w("| Domain | Risk Level | Summary |")
    w("|--------|-----------|---------|")
    w(f"| Hardware End-of-Life | {hw_risk_level} | {hw_past} past EOL, {hw_crit} critical, {hw_high} high-risk devices |")
    w(f"| Software End-of-Life | {sw_risk_level} | {sw_crit} devices on dead trains, {sw_high} on legacy trains |")
    w(f"| Security Vulnerabilities | {sec_risk_level} | {sec_crit} critical, {sec_high} high-risk devices; {total_psirt} total PSIRT alerts |")
    w(f"| Field Notices | {fn_risk_level} | {fn_high} devices with HIGH field notice exposure |")
    w(f"| Software Conformance | {conf_risk} | {conf_pct:.1f}% compliant — {non_compliant} devices non-compliant |")
    w("")

    # ═════════════════════════════════════════════════════════════════════
    # 2. FLEET ANALYTICS
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 2. Fleet Analytics & Inventory Breakdown")
    w("")

    # 2a. By Product ID
    w("### 2.1 Devices by Product ID")
    w("")
    w("| Product ID | Platform Family | Device Count | % of Fleet |")
    w("|-----------|----------------|-------------|-----------|")
    for pid, cnt in pid_counter.most_common():
        pct = f"{cnt/total_valid*100:.1f}%"
        w(f"| {pid} | {platform_family_name(pid)} | {cnt} | {pct} |")
    w("")

    # 2b. By Software Type
    w("### 2.2 Devices by Software Type")
    w("")
    w("| Software Type | Device Count | % of Fleet |")
    w("|--------------|-------------|-----------|")
    for swt, cnt in sw_type_counter.most_common():
        pct = f"{cnt/total_valid*100:.1f}%"
        w(f"| {swt} | {cnt} | {pct} |")
    w("")

    # 2c. By Software Version
    w("### 2.3 Devices by Software Version")
    w("")
    w("| Software Type | Version | Device Count | % of Fleet |")
    w("|--------------|---------|-------------|-----------|")
    for ver_key, cnt in sw_ver_counter.most_common():
        parts = ver_key.split(" ", 1)
        sw_t = parts[0]
        ver = parts[1] if len(parts) > 1 else ""
        pct = f"{cnt/total_valid*100:.1f}%"
        w(f"| {sw_t} | {ver} | {cnt} | {pct} |")
    w("")

    # 2d. By Device Type
    w("### 2.4 Devices by Device Type (Chassis)")
    w("")
    w("| Device Type | Device Count | % of Fleet |")
    w("|-----------|-------------|-----------|")
    for dt, cnt in device_type_counter.most_common():
        pct = f"{cnt/total_valid*100:.1f}%"
        w(f"| {dt} | {cnt} | {pct} |")
    w("")

    # 2e. By Image Name
    w("### 2.5 Devices by Software Image")
    w("")
    w("| Image Name | Device Count | % of Fleet |")
    w("|-----------|-------------|-----------|")
    for img, cnt in image_counter.most_common():
        pct = f"{cnt/total_valid*100:.1f}%"
        w(f"| {img} | {cnt} | {pct} |")
    w("")

    # 2f. By Site
    w("### 2.6 Devices by Site (Top 20)")
    w("")
    w("| Site Prefix | Device Count |")
    w("|-----------|-------------|")
    for site, cnt in site_counter.most_common(20):
        w(f"| {site} | {cnt} |")
    w("")

    # ═════════════════════════════════════════════════════════════════════
    # 3. HARDWARE EOL ASSESSMENT
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 3. Hardware End-of-Life (EoL) Assessment")
    w("")

    hw_entries = []
    for pid, eol in eol_map.items():
        cnt = pid_counter.get(pid, 0)
        if cnt == 0:
            continue
        risk, days = classify_hw_eol_risk(eol["last_date_of_support"], assess_date)
        score = cnt * (5 if risk == "PAST EOL" else 4 if risk == "CRITICAL" else 3 if risk == "HIGH" else 2 if risk == "MEDIUM" else 1)
        hw_entries.append({**eol, "risk": risk, "days": days, "count": cnt, "score": score})

    # PIDs with NO EoL
    no_eol_pids = []
    for pid, cnt in pid_counter.items():
        if pid not in eol_map:
            no_eol_pids.append({"pid": pid, "count": cnt})

    hw_entries.sort(key=lambda x: (-x["score"], -x["count"]))

    if hw_entries:
        w("### PIDs with Active EoL Bulletins")
        w("")
        w(f"> **{len(hw_entries)}** Product IDs have active Cisco EoL bulletins affecting **{sum(e['count'] for e in hw_entries)}** devices.")
        w("")
        w("| Product ID | Description | Bulletin | End-of-Sale | Last Date of Support | Days Left | Risk | Migration PID | Devices |")
        w("|-----------|------------|---------|-------------|---------------------|----------|------|--------------|---------|")
        for e in hw_entries:
            icon = RISK_ICON.get(e["risk"], "")
            days_str = str(e["days"]) if e["days"] != 99999 else "N/A"
            desc = e.get("description", "")[:50]
            w(f'| {e["pid"]} | {desc} | {e["bulletin"]} | {e["end_of_sale"]} | {e["last_date_of_support"]} | {days_str} | {icon} **{e["risk"]}** | {e["migration_pid"]} | {e["count"]} |')
        w("")

    if no_eol_pids:
        no_eol_pids.sort(key=lambda x: -x["count"])
        w("### PIDs with No EoL Announcement")
        w("")
        w(f"> **{len(no_eol_pids)}** Product IDs have **no Cisco EoL announcement** — these products are fully supported.")
        w("")
        w("| Product ID | Platform Family | Device Count |")
        w("|-----------|----------------|-------------|")
        for e in no_eol_pids:
            w(f'| {e["pid"]} | {platform_family_name(e["pid"])} | {e["count"]} |')
        w("")

    # Top 3 HW Risks
    hw_with_eol = [e for e in hw_entries if e["risk"] not in ("LOW", "NO EOL")]
    if hw_with_eol:
        w("### 🏆 Top 3 Hardware EoL Risks")
        w("")
        for i, e in enumerate(hw_with_eol[:3], 1):
            icon = RISK_ICON.get(e["risk"], "")
            w(f"**{i}. {icon} {e['pid']}** — {e['risk']} ({e['count']} devices)")
            w(f"   - **Bulletin:** {e['bulletin']} | **Last Date of Support:** {e['last_date_of_support']}")
            if e["days"] < 0:
                w(f"   - **Status:** Support ended {abs(e['days'])} days ago. Immediate replacement required.")
            else:
                w(f"   - **Status:** {e['days']} days remaining until end of support.")
            if e["migration_pid"]:
                w(f"   - **Recommendation:** Migrate to **{e['migration_pid']}** — {e.get('migration_info', '')}")
            else:
                w(f"   - **Recommendation:** Contact Cisco account team for replacement options.")
            w(f"   - **Business Impact:** Loss of TAC support, security patches, and bug fixes after Last Date of Support.")
            w("")

    # ═════════════════════════════════════════════════════════════════════
    # 4. SOFTWARE EOL ASSESSMENT
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 4. Software End-of-Life & Train Assessment")
    w("")

    sw_entries = []
    for ver_key, cnt in sw_ver_counter.most_common():
        parts = ver_key.split(" ", 1)
        if len(parts) < 2:
            continue
        swt, ver = parts[0], parts[1]
        risk, status = sw_train_risk(swt, ver)
        score = cnt * (4 if risk == "CRITICAL" else 3 if risk == "HIGH" else 2 if risk == "MEDIUM" else 1)
        sw_entries.append({"sw_type": swt, "version": ver, "count": cnt,
                           "status": status, "risk": risk, "score": score})

    sw_entries.sort(key=lambda x: (-x["score"], -x["count"]))

    w("| Software Type | Version | Device Count | Train Status | Risk Level |")
    w("|--------------|---------|-------------|-------------|-----------|")
    for e in sw_entries:
        icon = RISK_ICON.get(e["risk"], "")
        w(f'| {e["sw_type"]} | {e["version"]} | {e["count"]} | {e["status"]} | {icon} **{e["risk"]}** |')
    w("")

    sw_high = [e for e in sw_entries if e["risk"] in ("CRITICAL", "HIGH")]
    if sw_high:
        w("### 🏆 Top 3 Software EoL Risks")
        w("")
        for i, e in enumerate(sw_high[:3], 1):
            icon = RISK_ICON.get(e["risk"], "")
            w(f"**{i}. {icon} {e['sw_type']} {e['version']}** — {e['risk']} ({e['count']} devices)")
            w(f"   - **Train Status:** {e['status']}")
            if e["risk"] == "CRITICAL":
                w(f"   - **Recommendation:** URGENT — Upgrade immediately. This software train is end-of-life with no new security patches available.")
            elif "NX-OS" in e["sw_type"]:
                w(f"   - **Recommendation:** Upgrade to NX-OS 10.4(7) recommended release.")
            elif "IOS" == e["sw_type"]:
                w(f"   - **Recommendation:** Plan hardware refresh to Catalyst 9200CX with IOS-XE. IOS 15.2 is in limited maintenance.")
            else:
                w(f"   - **Recommendation:** Upgrade to current recommended release (17.12.6 for IOS-XE platforms).")
            w(f"   - **Business Impact:** Reduced security patch availability and accumulating vulnerability exposure.")
            w("")

    # ═════════════════════════════════════════════════════════════════════
    # 5. SECURITY VULNERABILITY ASSESSMENT
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 5. Security Vulnerability Assessment")
    w("")

    sec_entries = []
    for d in devices:
        psirt = int(d.get("PSIRT Vulnerable Alerts", 0) or 0)
        fn = int(d.get("FN Vulnerable Alerts", 0) or 0)
        hw_eox = int(d.get("Hardware EoX Alerts", 0) or 0)
        sw_al = int(d.get("Software Alerts", 0) or 0)
        cbp = int(d.get("CBP Alerts", 0) or 0)
        risk = classify_psirt_risk(psirt)
        # Compound: legacy train + high PSIRT → escalate
        sw_ver = d.get("Software Version", "")
        sw_type = d.get("Software Type", "")
        if sw_ver.startswith("16.") and psirt >= 6:
            risk = "CRITICAL"
        elif sw_ver.startswith("9.3") and psirt >= 6:
            risk = "CRITICAL"
        score = psirt * (4 if risk == "CRITICAL" else 3 if risk == "HIGH" else 2 if risk == "MEDIUM" else 1)
        sec_entries.append({
            "device": d["Device Name"], "pid": d["Product ID"],
            "sw_ver": sw_ver, "sw_type": sw_type,
            "psirt": psirt, "fn": fn, "hw_eox": hw_eox,
            "sw_alerts": sw_al, "cbp": cbp,
            "risk": risk, "score": score,
        })
    sec_entries.sort(key=lambda x: (-x["score"], -x["psirt"]))

    # Risk distribution
    sec_dist = Counter(e["risk"] for e in sec_entries)
    w("### Vulnerability Risk Distribution")
    w("")
    w("| Risk Level | Device Count | % of Fleet |")
    w("|-----------|-------------|-----------|")
    for rl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        cnt = sec_dist.get(rl, 0)
        pct = f"{cnt/total_valid*100:.1f}%" if total_valid else "0%"
        icon = RISK_ICON.get(rl, "")
        w(f"| {icon} **{rl}** | {cnt} | {pct} |")
    w("")

    # Top 20 table
    w("### Highest Vulnerability Devices (Top 20)")
    w("")
    w("| Device Name | Product ID | Software Version | PSIRT Alerts | FN Alerts | HW EoX | CBP | Risk |")
    w("|------------|-----------|-----------------|-------------|----------|--------|-----|------|")
    for e in sec_entries[:20]:
        icon = RISK_ICON.get(e["risk"], "")
        w(f'| {e["device"]} | {e["pid"]} | {e["sw_type"]} {e["sw_ver"]} | {e["psirt"]} | {e["fn"]} | {e["hw_eox"]} | {e["cbp"]} | {icon} **{e["risk"]}** |')
    w("")

    # Top 3 security risks
    sec_top = sec_entries[:3]
    if sec_top:
        w("### 🏆 Top 3 Security Vulnerability Risks")
        w("")
        for i, e in enumerate(sec_top, 1):
            icon = RISK_ICON.get(e["risk"], "")
            w(f"**{i}. {icon} {e['device']}** ({e['pid']}) — {e['risk']}")
            w(f"   - **Software:** {e['sw_type']} {e['sw_ver']} | **PSIRT Alerts:** {e['psirt']} | **FN Alerts:** {e['fn']}")
            if e["sw_ver"].startswith("16."):
                w(f"   - **Recommendation:** URGENT — Running end-of-life IOS-XE 16.x with {e['psirt']} PSIRT advisories. Upgrade to 17.12.6 and migrate hardware.")
            elif e["sw_ver"].startswith("9.3"):
                w(f"   - **Recommendation:** Upgrade NX-OS from 9.3 to recommended 10.4(7) to resolve known PSIRT advisories.")
            else:
                w(f"   - **Recommendation:** Upgrade to Cisco recommended software release to remediate known vulnerabilities.")
            w(f"   - **Business Impact:** Active security vulnerabilities expose the network to potential exploitation and compliance violations.")
            w("")

    # ═════════════════════════════════════════════════════════════════════
    # 6. FIELD NOTICE ASSESSMENT
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 6. Field Notice Assessment")
    w("")

    fn_entries = [e for e in sec_entries if e["fn"] > 0]
    fn_entries.sort(key=lambda x: (-x["fn"],))

    fn_dist = Counter(classify_fn_risk(e["fn"]) for e in sec_entries)
    w("### Field Notice Risk Distribution")
    w("")
    w("| Risk Level | Device Count |")
    w("|-----------|-------------|")
    for rl in ["HIGH", "MEDIUM", "LOW", "NONE"]:
        icon = RISK_ICON.get(rl, "")
        w(f"| {icon} **{rl}** | {fn_dist.get(rl, 0)} |")
    w("")

    if fn_entries:
        w("### Devices with Active Field Notices (Top 20)")
        w("")
        w("| Device Name | Product ID | Software Version | FN Alerts | Risk |")
        w("|------------|-----------|-----------------|----------|------|")
        for e in fn_entries[:20]:
            fn_r = classify_fn_risk(e["fn"])
            icon = RISK_ICON.get(fn_r, "")
            w(f'| {e["device"]} | {e["pid"]} | {e["sw_type"]} {e["sw_ver"]} | {e["fn"]} | {icon} **{fn_r}** |')
        w("")

    # ═════════════════════════════════════════════════════════════════════
    # 7. SOFTWARE CONFORMANCE AUDIT
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 7. Software Conformance Audit")
    w("")

    # Compute per device
    conf_details = []
    conf_family_summary = defaultdict(lambda: {"compliant": 0, "acceptable": 0, "non_compliant": 0, "total": 0, "versions": Counter()})
    for d in devices:
        pid = d["Product ID"]
        family = normalize_pid(pid)
        ver = d["Software Version"]
        rec = sw_reco.get(family)
        if rec:
            if ver == rec["recommended"]:
                st = "COMPLIANT"
            elif ver == rec["previous"]:
                st = "ACCEPTABLE"
            else:
                st = "NON-COMPLIANT"
            reco_ver = rec["recommended"]
            prev_ver = rec["previous"]
        else:
            st = "NON-COMPLIANT"
            reco_ver = "N/A"
            prev_ver = "N/A"

        conf_details.append({"device": d["Device Name"], "pid": pid, "family": family,
                             "version": ver, "recommended": reco_ver,
                             "prev_recommended": prev_ver, "status": st})
        s = conf_family_summary[family]
        s["total"] += 1
        s["versions"][ver] += 1
        if st == "COMPLIANT":
            s["compliant"] += 1
        elif st == "ACCEPTABLE":
            s["acceptable"] += 1
        else:
            s["non_compliant"] += 1

    c_total = len(conf_details)
    c_comp = sum(1 for c in conf_details if c["status"] == "COMPLIANT")
    c_acc = sum(1 for c in conf_details if c["status"] == "ACCEPTABLE")
    c_nc = sum(1 for c in conf_details if c["status"] == "NON-COMPLIANT")

    w("### Fleet-Wide Conformance Score")
    w("")
    w("| Status | Count | Percentage |")
    w("|--------|-------|-----------|")
    w(f"| 🟢 **COMPLIANT** (on recommended) | {c_comp} | {c_comp/c_total*100:.1f}% |")
    w(f"| 🟡 **ACCEPTABLE** (on previous recommended) | {c_acc} | {c_acc/c_total*100:.1f}% |")
    w(f"| 🔴 **NON-COMPLIANT** (neither) | {c_nc} | {c_nc/c_total*100:.1f}% |")
    w(f"| **TOTAL** | {c_total} | 100% |")
    w("")

    w("### Conformance by Platform Family")
    w("")
    w("| Platform Family | Running Version(s) | Recommended | Prev Recommended | Compliant | Acceptable | Non-Compliant | Total |")
    w("|----------------|-------------------|-------------|-----------------|----------|-----------|--------------|-------|")
    for family in sorted(conf_family_summary.keys()):
        s = conf_family_summary[family]
        rec = sw_reco.get(family, {})
        reco_v = rec.get("recommended", "N/A")
        prev_v = rec.get("previous", "N/A")
        versions = ", ".join(f"{v}({c})" for v, c in s["versions"].most_common(3))
        w(f'| {family} | {versions} | {reco_v} | {prev_v} | {s["compliant"]} | {s["acceptable"]} | {s["non_compliant"]} | {s["total"]} |')
    w("")

    # Top 3 non-compliance risks
    nc_ranking = []
    for family, s in conf_family_summary.items():
        if s["non_compliant"] > 0:
            nc_ranking.append({"family": family, "nc": s["non_compliant"], "total": s["total"],
                               "pct": s["non_compliant"] / s["total"] * 100,
                               "versions": s["versions"],
                               "recommended": sw_reco.get(family, {}).get("recommended", "N/A")})
    nc_ranking.sort(key=lambda x: (-x["nc"], -x["pct"]))

    if nc_ranking:
        w("### 🏆 Top 3 Software Non-Compliance Risks")
        w("")
        for i, e in enumerate(nc_ranking[:3], 1):
            versions_str = ", ".join(f"{v} ({c} devices)" for v, c in e["versions"].most_common())
            w(f"**{i}. 🔴 {e['family']}** — {e['nc']}/{e['total']} devices NON-COMPLIANT ({e['pct']:.0f}%)")
            w(f"   - **Running Versions:** {versions_str}")
            w(f"   - **Cisco Recommended:** {e['recommended']}")
            w(f"   - **Recommendation:** Schedule phased upgrade to {e['recommended']} across all {e['family']} devices.")
            w(f"   - **Business Impact:** Non-compliant software misses critical bug fixes, security patches, and feature enhancements.")
            w("")

    # ═════════════════════════════════════════════════════════════════════
    # 8. CONSOLIDATED RISK MATRIX
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 8. Consolidated Risk Matrix")
    w("")
    w("| Domain | Overall Risk | Top Risk Item | Devices Affected | Recommended Action | Priority |")
    w("|--------|-------------|--------------|-----------------|-------------------|---------|")

    if hw_with_eol:
        ht = hw_with_eol[0]
        w(f'| **Hardware EoL** | {RISK_ICON[ht["risk"]]} **{ht["risk"]}** | {ht["pid"]} (LDoS: {ht["last_date_of_support"]}) | {ht["count"]} | Migrate to {ht["migration_pid"] or "next-gen platform"} | 🔴 P1 |')
    else:
        w(f'| **Hardware EoL** | 🟢 **LOW** | No critical EoL items | — | Continue lifecycle monitoring | 🟢 P4 |')

    if sw_high:
        st = sw_high[0]
        w(f'| **Software EoL** | {RISK_ICON[st["risk"]]} **{st["risk"]}** | {st["sw_type"]} {st["version"]} | {st["count"]} | Upgrade to recommended release | 🔴 P1 |')

    if sec_top:
        s0 = sec_top[0]
        w(f'| **Security PSIRT** | {RISK_ICON[s0["risk"]]} **{s0["risk"]}** | {s0["device"]} ({s0["psirt"]} PSIRTs) | Top-20 affected | Upgrade software to patch advisories | 🔴 P1 |')

    if nc_ranking:
        n0 = nc_ranking[0]
        nr = "CRITICAL" if n0["pct"] > 80 else "HIGH" if n0["pct"] > 50 else "MEDIUM"
        w(f'| **SW Conformance** | {RISK_ICON[nr]} **{nr}** | {n0["family"]} ({n0["nc"]} non-compliant) | {n0["total"]} total | Upgrade to {n0["recommended"]} | 🟠 P2 |')
    w("")

    # ═════════════════════════════════════════════════════════════════════
    # 9. REMEDIATION ROADMAP
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 9. Remediation Roadmap")
    w("")

    # Build prioritized actions from all domains
    actions_30 = []  # critical
    actions_60 = []  # high
    actions_90 = []  # medium

    for e in sw_entries:
        if e["risk"] == "CRITICAL":
            actions_30.append(f"**Upgrade {e['sw_type']} {e['version']} devices** ({e['count']} devices) — End-of-life software train. Upgrade to current recommended release immediately.")
    for e in hw_entries:
        if e["risk"] == "PAST EOL":
            actions_30.append(f"**Replace {e['pid']}** ({e['count']} devices) — Past end-of-life (support ended {abs(e['days'])} days ago). {'Migrate to ' + e['migration_pid'] if e['migration_pid'] else 'Engage Cisco for replacement options'}.")
        elif e["risk"] == "CRITICAL":
            actions_30.append(f"**Plan {e['pid']} replacement** ({e['count']} devices) — {e['days']} days to end of support. {'Migrate to ' + e['migration_pid'] if e['migration_pid'] else 'Engage Cisco'}.")

    for e in sw_entries:
        if e["risk"] == "HIGH":
            actions_60.append(f"**Upgrade {e['sw_type']} {e['version']} devices** ({e['count']} devices) — {e['status']}. Upgrade to recommended release.")
    for e in hw_entries:
        if e["risk"] == "HIGH":
            actions_60.append(f"**Plan {e['pid']} migration** ({e['count']} devices) — {e['days']} days to LDoS. {'Target: ' + e['migration_pid'] if e['migration_pid'] else 'Contact Cisco'}.")

    for nc in nc_ranking[:3]:
        actions_90.append(f"**Fleet-wide {nc['family']} upgrade** ({nc['nc']} devices) — Upgrade to {nc['recommended']} for full conformance.")

    w("### 🔴 30-Day Actions (Critical)")
    w("")
    for i, a in enumerate(actions_30, 1):
        w(f"{i}. {a}")
    if not actions_30:
        w("No critical 30-day actions identified.")
    w("")

    w("### 🟠 60-Day Actions (High)")
    w("")
    for i, a in enumerate(actions_60, 1):
        w(f"{i}. {a}")
    if not actions_60:
        w("No high-priority 60-day actions identified.")
    w("")

    w("### 🟡 90-Day Actions (Medium)")
    w("")
    for i, a in enumerate(actions_90, 1):
        w(f"{i}. {a}")
    if not actions_90:
        w("No medium-priority 90-day actions identified.")
    w("")

    # ═════════════════════════════════════════════════════════════════════
    # 10. FULL DEVICE INVENTORY
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w("## 10. Full Device Inventory")
    w("")
    w(f"> **{total_valid}** devices with valid data. {total_excluded} devices excluded (missing PID or unreachable).")
    w("")
    w("| # | Device Name | Hostname | IP Address | Product ID | Software Type | Software Version | Type | PSIRT | FN | HW EoX | CBP | SW Alerts |")
    w("|---|------------|---------|-----------|-----------|--------------|-----------------|------|-------|----|----|-----|----------|")
    for idx, d in enumerate(devices, 1):
        w(f'| {idx} | {d["Device Name"]} | {d.get("Hostname","")} | {d.get("IP Address","")} | {d["Product ID"]} | {d["Software Type"]} | {d["Software Version"]} | {d.get("Type","")} | {d.get("PSIRT Vulnerable Alerts",0)} | {d.get("FN Vulnerable Alerts",0)} | {d.get("Hardware EoX Alerts",0)} | {d.get("CBP Alerts",0)} | {d.get("Software Alerts",0)} |')
    w("")

    # ═════════════════════════════════════════════════════════════════════
    # FOOTER
    # ═════════════════════════════════════════════════════════════════════
    w("---")
    w("")
    w(f"*Report generated by Cisco CX AI Assessment Engine v2.0 — {assess_date.strftime('%B %d, %Y')}*")
    w("")
    w("*Data Sources: Cisco EoX Support API, Cisco Architect Software Recommendations (software_recommendation.csv), CSPC/BCI Inventory Telemetry*")

    # Write file
    report_text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return report_text

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    args = parse_args()

    # Assessment date
    if args.date:
        assess_date = datetime.strptime(args.date, "%Y-%m-%d").date()
    else:
        assess_date = date.today()

    # Output path
    if args.output:
        output_path = args.output
    else:
        safe_name = args.customer.replace(" ", "_").replace("/", "_")
        output_path = f"{safe_name}_CX_Assessment_Report.md"

    print(f"╔══════════════════════════════════════════════════════════════╗")
    print(f"║   Cisco CX AI Assessment Report Generator v2.0             ║")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Customer:    {args.customer:<46}║")
    print(f"║  Inventory:   {args.inventory:<46}║")
    print(f"║  Date:        {assess_date.strftime('%Y-%m-%d'):<46}║")
    print(f"║  Output:      {output_path:<46}║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print()

    # 1. Load inventory
    print("[1/5] Loading customer inventory...")
    devices, excluded = load_inventory(args.inventory)
    print(f"  ✅ {len(devices)} valid devices loaded, {len(excluded)} excluded")

    # 2. Load software recommendations
    print("[2/5] Loading software recommendations...")
    sw_reco = load_sw_recommendations(args.sw_reco)
    print(f"  ✅ {len(sw_reco)} platform baselines loaded")

    # 3. Query APIs
    eol_map = {}
    api_id = os.getenv("CISCO_API_ID")
    api_secret = os.getenv("CISCO_API_SECRET")

    if args.skip_api:
        print("[3/5] Skipping API calls (--skip-api)")
    elif not api_id or not api_secret:
        print("[3/5] ⚠️  CISCO_API_ID / CISCO_API_SECRET not set — skipping API calls")
        print("  Set environment variables to enable live Cisco EoX data.")
    else:
        unique_pids = sorted(set(d["Product ID"] for d in devices))
        print(f"[3/5] Querying Cisco EoX API for {len(unique_pids)} unique PIDs...")

        eol_map = query_eox_api(unique_pids, api_id, api_secret)
        print(f"  ✅ {len(eol_map)} PIDs with active EoL bulletins")

    # 4. Generate report
    print(f"[4/5] Generating assessment report...")
    generate_report(devices, excluded, eol_map, sw_reco,
                    args.customer, assess_date, output_path)
    print(f"  ✅ Report written to: {output_path}")

    # 5. Summary
    line_count = sum(1 for _ in open(output_path))
    print(f"[5/5] Done!")
    print(f"  📄 {output_path} ({line_count} lines)")
    print()


if __name__ == "__main__":
    main()
