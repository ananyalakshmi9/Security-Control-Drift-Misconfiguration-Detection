#!/usr/bin/env python3
"""
=============================================================================
alert_system.py  –  Prioritised Alert Engine
Security Control Drift Detection System
Societe Generale Enterprise Security Hackathon
=============================================================================

Reads drift_analysis_results.csv + drift_explanations.json
Produces:
  alerts.json          – machine-readable alert queue (sorted by priority)
  alert_queue.txt      – human-readable SOC alert console output
  alert_summary.md     – markdown alert digest for CISO / management

Alert priority levels:
  P1 – CRITICAL + Drifted + Off-hours          → Page on-call NOW
  P2 – CRITICAL + Drifted / Under_Review       → Escalate within 15 min
  P3 – HIGH + Drifted + Regression             → Resolve within 1 hour
  P4 – HIGH + Drifted                          → Resolve within 1 hour
  P5 – HIGH + Under_Review / Mitigated         → Follow up within 4 hours
  P6 – MEDIUM + Drifted                        → Schedule review
  P7 – Any + Compliance Impact Mapped          → Compliance notification
  P8 – BENIGN / resolved                       → Log only
=============================================================================
"""

import csv
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Optional

BASE_DIR       = Path(__file__).parent.parent
RESULTS_CSV    = BASE_DIR / "output" / "drift_analysis_results.csv"
EXPL_JSON      = BASE_DIR / "output" / "drift_explanations.json"
OUT_JSON       = BASE_DIR / "output" / "alerts.json"
OUT_TXT        = BASE_DIR / "output" / "alert_queue.txt"
OUT_MD         = BASE_DIR / "docs" / "alert_summary.md"

# SLA minutes per priority
SLA = {
    "P1": 15,
    "P2": 60,
    "P3": 60,
    "P4": 60,
    "P5": 240,
    "P6": 1440,
    "P7": 480,
    "P8": None,    # log only
}

ESCALATION = {
    "P1": "CISO, SOC Lead, DPO, On-Call Engineer",
    "P2": "CISO, SOC Lead",
    "P3": "SOC Lead, Control Owner",
    "P4": "SOC Lead, Control Owner",
    "P5": "Control Owner",
    "P6": "Control Owner, Risk Team",
    "P7": "Compliance Officer",
    "P8": "Auto-logged",
}

CHANNEL = {
    "P1": "PagerDuty P1 + SMS + Email",
    "P2": "PagerDuty P2 + Email",
    "P3": "Slack #soc-alerts + Email",
    "P4": "Slack #soc-alerts",
    "P5": "Slack #soc-low-priority",
    "P6": "ITSM Ticket (auto-created)",
    "P7": "Email to Compliance DL",
    "P8": "SIEM Log only",
}

ACTION = {
    "P1": "Isolate or disable the affected system immediately. Page CISO.",
    "P2": "Begin emergency remediation. Notify CISO within 15 minutes.",
    "P3": "Assign remediation ticket. Resolve within 1 hour.",
    "P4": "Create ITSM ticket. Resolve within 1 hour.",
    "P5": "Create ITSM ticket. Follow up within 4 hours.",
    "P6": "Schedule review in next maintenance window.",
    "P7": "File compliance incident report. Notify DPO if GDPR-relevant.",
    "P8": "No action required. Logged for audit trail.",
}


# ── Priority Scoring ─────────────────────────────────────────────────────────

def assign_priority(r: dict, exp: Optional[dict]) -> str:
    """
    Determine P1-P8 priority from classification, status, flags, and compliance.
    """
    cls      = r.get("classification", "")
    status   = r.get("status", "").strip().lower()
    off_h    = str(r.get("is_off_hours", "")).strip().lower() == "true"
    regr     = str(r.get("is_regression", "")).strip().lower() == "true"
    score    = int(r.get("risk_score", 0))
    comp     = bool(r.get("compliance_impact", "").strip())
    has_comp = bool(exp and exp.get("compliance_violations"))

    if cls == "CRITICAL_DRIFT":
        if off_h and status == "drifted":
            return "P1"
        if status in ("drifted", "under_review"):
            return "P2"
        return "P3"  # Critical but mitigated/compliant

    if cls == "HIGH_DRIFT":
        if regr and status == "drifted":
            return "P3"
        if status == "drifted":
            return "P4"
        if status in ("under_review", "mitigated"):
            return "P5"
        return "P6"

    if cls == "MEDIUM_DRIFT":
        if has_comp and status == "drifted":
            return "P7"
        return "P6"

    # BENIGN
    return "P8"


def priority_sort_key(p: str) -> int:
    """Lower number = higher priority."""
    return {"P1":1,"P2":2,"P3":3,"P4":4,"P5":5,"P6":6,"P7":7,"P8":8}.get(p, 9)


# ── Alert Builder ─────────────────────────────────────────────────────────────

def build_alert(r: dict, exp: Optional[dict], priority: str) -> dict:
    generated = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    sla_min    = SLA[priority]
    sla_str    = f"{sla_min} minutes" if sla_min else "No SLA — log only"

    score = int(r.get("risk_score", 0))

    alert = {
        "alert_id":         f"ALT-{r['drift_event_id'].replace('DRF','').lstrip('0') or '0'}",
        "drift_event_id":   r["drift_event_id"],
        "priority":         priority,
        "sla":              sla_str,
        "escalation_path":  ESCALATION[priority],
        "notification_channel": CHANNEL[priority],
        "required_action":  ACTION[priority],
        "generated_at":     generated,
        # Event details
        "control_name":     r.get("control_name",""),
        "control_type":     r.get("control_type",""),
        "classification":   r.get("classification",""),
        "risk_score":       score,
        "severity":         r.get("severity",""),
        "change_type":      r.get("change_type",""),
        "status":           r.get("status",""),
        "change_date":      r.get("change_date",""),
        "is_off_hours":     r.get("is_off_hours",""),
        "is_regression":    r.get("is_regression",""),
        "operator_name":    r.get("operator_name",""),
        "operator_email":   r.get("operator_email",""),
        "approver_name":    r.get("approver_name",""),
        "compliance_impact":r.get("compliance_impact",""),
        # Enrichment from explanations
        "plain_english":       exp.get("plain_english","N/A") if exp else "See drift_analysis_results.csv",
        "compliance_violations": exp.get("compliance_violations",[]) if exp else [],
        "remediation_steps":   exp.get("remediation","See remediation_playbook.md") if exp else "See remediation_playbook.md",
        "business_impact":     exp.get("business_impact","") if exp else "",
    }
    return alert


# ── Console Alert Formatter ───────────────────────────────────────────────────

SEVERITY_COLOUR = {
    "P1": "🔴🔴", "P2": "🔴", "P3": "🟠",
    "P4": "🟠", "P5": "🟡", "P6": "🟡",
    "P7": "🔵", "P8": "⚪",
}

def format_alert_console(a: dict, idx: int) -> str:
    icon  = SEVERITY_COLOUR.get(a["priority"],"⚪")
    lines = [
        f"{'═'*72}",
        f" {icon}  [{a['priority']}] ALERT #{idx:04d} — {a['alert_id']}  |  Risk Score: {a['risk_score']}",
        f"{'─'*72}",
        f"  Drift Event    : {a['drift_event_id']}",
        f"  Control        : {a['control_name']} ({a['control_type']})",
        f"  Classification : {a['classification']}",
        f"  Severity       : {a['severity']}  |  Change: {a['change_type']}  |  Status: {a['status']}",
        f"  Date           : {a['change_date']}  |  Off-hours: {a['is_off_hours']}  |  Regression: {a['is_regression']}",
        f"  Operator       : {a['operator_name']} <{a['operator_email']}>",
        f"  Approver       : {a['approver_name']}",
        f"  SLA            : {a['sla']}",
        f"  Notify         : {a['escalation_path']}",
        f"  Channel        : {a['notification_channel']}",
        f"  ACTION REQUIRED: {a['required_action']}",
    ]

    if a.get("compliance_violations"):
        lines.append(f"  Compliance     : {', '.join(a['compliance_violations'])}")

    if a.get("plain_english") and a["plain_english"] != "N/A":
        desc = a["plain_english"][:220] + ("..." if len(a["plain_english"]) > 220 else "")
        lines.append(f"  Description    : {desc}")

    if a.get("remediation_steps") and "See" not in a["remediation_steps"]:
        steps = a["remediation_steps"][:200] + ("..." if len(a["remediation_steps"]) > 200 else "")
        lines.append(f"  Remediation    : {steps}")

    return "\n".join(lines)


# ── Markdown Digest ───────────────────────────────────────────────────────────

def write_md_summary(alerts: list, path: Path, stats: dict):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# 🚨 Security Alert Digest — SOC Priority Queue\n\n",
        f"> **Generated:** {now}  \n",
        f"> **Total Alerts:** {len(alerts)}  \n",
        f"> **Dataset:** {stats['total_events']:,} drift events · Apr 2025 – Apr 2026\n\n",
        "---\n\n",
        "## Alert Priority Summary\n\n",
        "| Priority | Level | Count | SLA | Escalation |\n",
        "|----------|-------|-------|-----|------------|\n",
    ]

    priority_counts = Counter(a["priority"] for a in alerts)
    p_labels = {
        "P1":"CRITICAL — Page Now","P2":"CRITICAL — 15 min","P3":"HIGH — Off-hours + Regression",
        "P4":"HIGH — Active Drift","P5":"HIGH — In-Progress","P6":"MEDIUM — Schedule Review",
        "P7":"MEDIUM — Compliance","P8":"BENIGN — Log Only",
    }
    for p in ["P1","P2","P3","P4","P5","P6","P7","P8"]:
        cnt = priority_counts.get(p, 0)
        if cnt > 0:
            lines.append(f"| **{p}** | {p_labels[p]} | **{cnt}** | {SLA[p] or 'N/A'} min | {ESCALATION[p][:40]}... |\n")

    lines.append("\n---\n\n")

    # P1 and P2 in detail
    for p_level in ["P1","P2","P3"]:
        p_alerts = [a for a in alerts if a["priority"] == p_level]
        if not p_alerts: continue
        lines.append(f"## {p_level} Alerts — {p_labels[p_level]} ({len(p_alerts)} events)\n\n")
        for a in p_alerts[:15]:   # cap at 15 per priority
            lines.append(f"### `{a['alert_id']}` — {a['control_name']} ({a['control_type']})\n\n")
            lines.append(f"| Field | Value |\n|-------|-------|\n")
            lines.append(f"| Risk Score | **{a['risk_score']}** |\n")
            lines.append(f"| Severity | {a['severity']} |\n")
            lines.append(f"| Change | {a['change_type']} |\n")
            lines.append(f"| Status | {a['status']} |\n")
            lines.append(f"| Date | {a['change_date']} |\n")
            lines.append(f"| Off-Hours | {a['is_off_hours']} |\n")
            lines.append(f"| Regression | {a['is_regression']} |\n")
            lines.append(f"| Operator | {a['operator_name']} |\n")
            lines.append(f"| SLA | {a['sla']} |\n")
            if a.get("compliance_violations"):
                lines.append(f"| Compliance | {', '.join(a['compliance_violations'])} |\n")
            lines.append(f"\n**Required Action:** {a['required_action']}\n\n")
            if a.get("plain_english") and a["plain_english"] != "N/A":
                lines.append(f"**Summary:** {a['plain_english'][:300]}...\n\n")
            if a.get("remediation_steps") and "See" not in a["remediation_steps"]:
                lines.append(f"**Remediation:** {a['remediation_steps'][:250]}...\n\n")
            lines.append("---\n\n")

    # Operator risk table
    lines.append("## Top 10 Operators by Alert Volume\n\n")
    op_counts = Counter(a["operator_name"] for a in alerts if a["priority"] in ("P1","P2","P3","P4"))
    lines.append("| Rank | Operator | P1-P4 Alerts |\n|------|----------|--------------|\n")
    for i, (op, cnt) in enumerate(op_counts.most_common(10), 1):
        lines.append(f"| {i} | {op} | **{cnt}** |\n")

    lines.append("\n---\n\n")
    lines.append("## Compliance Impact Summary\n\n")
    all_stds = Counter()
    for a in alerts:
        for s in a.get("compliance_violations", []):
            all_stds[s] += 1
    lines.append("| Standard | Affected Alerts |\n|----------|-----------------|\n")
    for std, cnt in all_stds.most_common(10):
        lines.append(f"| `{std}` | {cnt} |\n")

    lines.append("\n---\n\n")
    lines.append("*Alert digest auto-generated by alert_system.py  •  Societe Generale Enterprise Security*\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(lines))
    print(f"[INFO] Alert digest written: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*72)
    print("  ALERT SYSTEM  –  Prioritised SOC Alert Engine")
    print("="*72 + "\n")

    # Load results
    if not RESULTS_CSV.exists():
        print(f"[ERROR] {RESULTS_CSV} not found. Run drift_detector.py first.")
        sys.exit(1)

    results = []
    with open(RESULTS_CSV, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            results.append(row)
    print(f"[INFO] Loaded {len(results)} classified events.")

    # Load explanations
    explanations = {}
    if EXPL_JSON.exists():
        with open(EXPL_JSON, encoding="utf-8") as f:
            for exp in json.load(f):
                explanations[exp["drift_id"]] = exp
    print(f"[INFO] Loaded {len(explanations)} explanations.")

    # Build and prioritise alerts
    alerts = []
    for r in results:
        exp      = explanations.get(r["drift_event_id"])
        priority = assign_priority(r, exp)
        alert    = build_alert(r, exp, priority)
        alerts.append(alert)

    # Sort by priority then risk score descending
    alerts.sort(key=lambda a: (priority_sort_key(a["priority"]), -a["risk_score"]))

    # Print priority distribution
    p_counts = Counter(a["priority"] for a in alerts)
    print("\n  PRIORITY DISTRIBUTION")
    print("  " + "-"*50)
    for p in ["P1","P2","P3","P4","P5","P6","P7","P8"]:
        cnt = p_counts.get(p, 0)
        if cnt > 0:
            bar = "█" * min(cnt // 2, 40)
            print(f"  {p}  {cnt:>4} alerts  {bar}")

    # Save JSON
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, default=str)
    print(f"\n[INFO] alerts.json written: {OUT_JSON}  ({len(alerts)} alerts)")

    # Save console output
    console_lines = [
        "="*72,
        "  SOC ALERT QUEUE  –  PRIORITISED BY RISK LEVEL",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Total: {len(alerts)} alerts",
        "="*72,
        "",
    ]
    p1p2 = [a for a in alerts if a["priority"] in ("P1","P2")]
    p3p4 = [a for a in alerts if a["priority"] in ("P3","P4")]
    p5p6 = [a for a in alerts if a["priority"] in ("P5","P6")]

    console_lines.append(f"\n{'─'*72}")
    console_lines.append(f"  ‼️  IMMEDIATE ACTION REQUIRED — {len(p1p2)} P1/P2 Alerts")
    console_lines.append(f"{'─'*72}\n")
    for i, a in enumerate(p1p2, 1):
        console_lines.append(format_alert_console(a, i))
        console_lines.append("")

    console_lines.append(f"\n{'─'*72}")
    console_lines.append(f"  ⚠️   HIGH PRIORITY — {len(p3p4)} P3/P4 Alerts (resolve within 1 hour)")
    console_lines.append(f"{'─'*72}\n")
    for i, a in enumerate(p3p4[:20], 1):  # show top 20
        console_lines.append(format_alert_console(a, i))
        console_lines.append("")
    if len(p3p4) > 20:
        console_lines.append(f"  ... and {len(p3p4)-20} more P3/P4 alerts. See alerts.json for full list.")

    console_lines.append(f"\n{'─'*72}")
    console_lines.append(f"  📋  STANDARD QUEUE — {len(p5p6)} P5/P6 Alerts (schedule review)")
    console_lines.append(f"{'─'*72}")
    console_lines.append(f"  {len(p5p6)} P5-P6 alerts not shown. See alerts.json.")

    with open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(console_lines))
    print(f"[INFO] Console queue written: {OUT_TXT}")

    # Stats for markdown digest
    stats = {"total_events": len(results)}
    write_md_summary(alerts, OUT_MD, stats)

    # Final summary
    actionable = sum(1 for a in alerts if a["priority"] in ("P1","P2","P3","P4"))
    print(f"\n{'='*72}")
    print(f"  ALERT GENERATION COMPLETE")
    print(f"  Total alerts       : {len(alerts)}")
    print(f"  P1 (Page Now)      : {p_counts.get('P1',0)}")
    print(f"  P2 (15 min SLA)    : {p_counts.get('P2',0)}")
    print(f"  P3/P4 (1 hr SLA)   : {p_counts.get('P3',0) + p_counts.get('P4',0)}")
    print(f"  P5/P6 (standard)   : {p_counts.get('P5',0) + p_counts.get('P6',0)}")
    print(f"  P7 (compliance)    : {p_counts.get('P7',0)}")
    print(f"  P8 (log only)      : {p_counts.get('P8',0)}")
    print(f"  Actionable (P1-P4) : {actionable}")
    print(f"\n  Output files:")
    print(f"    alerts.json         ({OUT_JSON.stat().st_size:,} bytes)")
    print(f"    alert_queue.txt     ({OUT_TXT.stat().st_size:,} bytes)")
    print(f"    alert_summary.md    ({OUT_MD.stat().st_size:,} bytes)")
    print(f"{'='*72}\n")


if __name__ == "__main__":
    main()
