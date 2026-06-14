#!/usr/bin/env python3
"""
=============================================================================
Security Control Drift Detection System
Societe Generale Enterprise Security Hackathon – Problem 02
=============================================================================
Author  : Security Engineering Team
Version : 2.0.0
Python  : 3.9+

Modules:
  - DriftDetectionEngine  : Multi-factor risk scoring & classification
  - ExplainabilityEngine  : Structured NL explanations for CRITICAL/HIGH drifts
  - RemediationGenerator  : Playbook generation per control_type
  - ReportGenerator       : Summary report + audit report

Run:
  python drift_detector.py

Output files (written to current directory):
  drift_analysis_results.csv   — per-event risk scores & classification
  drift_summary_report.txt     — executive text summary
  drift_explanations.json      — structured explanations for CRITICAL/HIGH
  audit_report.md              — full markdown audit report
  remediation_playbook.md      — per-control-type fix steps
=============================================================================
"""

import json
import csv
import os
import sys
import time
import re
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
from typing import Optional

# ── Constants ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "sample_data"

BASELINE_FILE = DATA_DIR / "baseline_configs.json"
EVENTS_FILE   = DATA_DIR / "config_drift_events.csv"
LABELS_FILE   = DATA_DIR / "config_drift_labels.csv"  # ground-truth (if present)

OUT_RESULTS   = BASE_DIR / "output" / "drift_analysis_results.csv"
OUT_SUMMARY   = BASE_DIR / "output" / "drift_summary_report.txt"
OUT_EXPL      = BASE_DIR / "output" / "drift_explanations.json"
OUT_AUDIT     = BASE_DIR / "docs" / "audit_report.md"
OUT_PLAYBOOK  = BASE_DIR / "docs" / "remediation_playbook.md"

# ── Risk Scoring Weights ──────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high":     30,
    "medium":   15,
    "low":       5,
    "info":      0,
}

STATUS_WEIGHTS = {
    "drifted":      30,
    "under_review": 15,
    "mitigated":     5,
    "compliant":   -10,   # resolved → meaningful score reduction
    "remediated":  -10,   # resolved → meaningful score reduction
}

CHANGE_TYPE_WEIGHTS = {
    "disable":  25,
    "remove":   20,
    "modify":   10,
    "update":    5,
    "enable":   -5,   # security restoration lowers score
    "rollback":  0,
}

# Regression bonus only applies when severity is meaningful
# Low/Info severity regressions are usually auto-corrected by tooling
REGRESSION_BONUS_BY_SEVERITY = {
    "critical": 20,
    "high":     20,
    "medium":   10,   # halved — medium regressions are less certain
    "low":       0,   # no bonus — low-severity disabled controls rarely create risk
    "info":      0,
}

# Minimum score a Low or Info severity event can reach (cap classification)
SEVERITY_MAX_CLASSIFICATION = {
    "critical": "CRITICAL_DRIFT",
    "high":     "HIGH_DRIFT",
    "medium":   "MEDIUM_DRIFT",  # medium: risk score alone can't push it to HIGH/CRITICAL
    "low":      "MEDIUM_DRIFT",  # low severity → never CRITICAL or HIGH
    "info":     "BENIGN",        # info → never actionable drift
}

# Classification thresholds
THRESHOLD_CRITICAL = 70
THRESHOLD_HIGH     = 50
THRESHOLD_MEDIUM   = 30

# Compliance mapping per control_type
COMPLIANCE_MAP = {
    "logging":              ["NIST AU-2", "CIS 2.1", "NIST SI-12"],
    "encryption":           ["GDPR 32", "NIST SC-7", "PCI-DSS 3.4"],
    "access_control":       ["NIST IA-2", "CIS 5.3"],
    "firewall":             ["CIS 3.1", "NIST AC-4"],
    "dlp":                  ["GDPR 25", "ISO 27001 A.13"],
    "cloud_security":       ["CIS 2.1", "NIST CM-2"],
    "endpoint":             ["NIST SI-3", "CIS 8.1"],
    "data_protection":      ["GDPR 32", "PCI-DSS 3.4"],
    "vulnerability":        ["NIST RA-5", "CIS 7.1"],
    "network_segmentation": ["NIST SC-7", "CIS 12.1"],
}

# Business impact templates per control_type
IMPACT_TEMPLATES = {
    "logging":
        "Loss of audit trail. Any breach during this window is undetectable. "
        "Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
    "encryption":
        "Data at rest or in transit is exposed to interception and exfiltration. "
        "PCI-DSS 3.4 and GDPR 32 violations may trigger regulatory fines.",
    "access_control":
        "Unauthorised users may gain privileged access. Lateral movement risk increases. "
        "Violates NIST IA-2 least-privilege mandate.",
    "firewall":
        "Network perimeter weakened. Internal services may be exposed to external threats. "
        "CIS 3.1 violation; potential pathway for ransomware entry.",
    "dlp":
        "Sensitive data (PII/IP) may be exfiltrated via email, USB, or cloud sync. "
        "GDPR 25 data-minimisation principle violated.",
    "cloud_security":
        "Cloud workloads exposed to misconfiguration exploitation. "
        "NIST CM-2 baseline deviation; potential public exposure of internal APIs.",
    "endpoint":
        "Endpoints lack threat detection/prevention. Malware propagation risk is elevated. "
        "CIS 8.1 anti-malware controls violated.",
    "data_protection":
        "Sensitive records (PII, financial, health) unprotected. "
        "GDPR 32 and PCI-DSS 3.4 non-compliance. Breach notification obligations activated.",
    "vulnerability":
        "Known CVEs remain unpatched; exploit likelihood increases daily. "
        "NIST RA-5 vulnerability scanning control violated.",
    "network_segmentation":
        "Flat network topology allows lateral movement post-breach. "
        "NIST SC-7 boundary protection violated; blast radius of any breach expands.",
}

# Remediation steps per control_type and change_type
REMEDIATION_TEMPLATES = {
    "logging": {
        "disable": (
            "1. Immediately re-enable logging via console/API. "
            "2. Audit all API calls during the blind window. "
            "3. Escalate to CISO and SIEM team. "
            "4. File change ticket with root-cause explanation."
        ),
        "modify": (
            "1. Revert logging configuration to baseline. "
            "2. Verify log ingestion in SIEM. "
            "3. Review recent log gaps for anomalies."
        ),
        "remove": (
            "1. Restore logging agent/service. "
            "2. Perform forensic analysis of the gap period. "
            "3. Notify Compliance team."
        ),
        "default": (
            "1. Restore logging to baseline configuration. "
            "2. Validate log completeness in SIEM. "
            "3. Review recent activity for anomalies."
        ),
    },
    "encryption": {
        "disable": (
            "1. Re-enable encryption immediately. "
            "2. Initiate key rotation per KMS policy. "
            "3. Scan affected data stores for exposure. "
            "4. Notify Data Protection Officer (DPO)."
        ),
        "modify": (
            "1. Revert to AES-256 or approved algorithm. "
            "2. Re-encrypt data written during downgrade window. "
            "3. Update key rotation schedule."
        ),
        "default": (
            "1. Restore encryption baseline. "
            "2. Rotate affected encryption keys. "
            "3. Validate re-encryption of data at rest."
        ),
    },
    "access_control": {
        "disable": (
            "1. Re-enable access controls immediately. "
            "2. Audit all access logs during the gap. "
            "3. Force re-authentication for all admin sessions. "
            "4. Review privileged access grants."
        ),
        "remove": (
            "1. Restore access policy from IAM baseline. "
            "2. Review who accessed resources during the gap. "
            "3. Apply least-privilege remediation."
        ),
        "default": (
            "1. Restore access control baseline. "
            "2. Review access logs for anomalous activity. "
            "3. Enforce re-authentication."
        ),
    },
    "firewall": {
        "modify": (
            "1. Revert to baseline allowed-port list. "
            "2. Block any newly opened ports immediately. "
            "3. Run traffic analysis to detect exploitation. "
            "4. Update firewall change management log."
        ),
        "disable": (
            "1. Re-enable firewall rules. "
            "2. Perform full traffic review for the exposure window. "
            "3. Check IDS/IPS for alerts during the gap."
        ),
        "default": (
            "1. Restore firewall to baseline configuration. "
            "2. Review traffic logs for anomalies. "
            "3. Validate threat-prevention policies."
        ),
    },
    "dlp": {
        "disable": (
            "1. Re-enable DLP policy immediately. "
            "2. Scan outbound email/file transfers during gap. "
            "3. Review USB and cloud-sync activity. "
            "4. Notify Data Governance team."
        ),
        "modify": (
            "1. Revert DLP rules to approved baseline. "
            "2. Validate all monitoring channels are active. "
            "3. Review recent incidents for missed detections."
        ),
        "default": (
            "1. Restore DLP baseline policy. "
            "2. Scan for data exfiltration during gap window. "
            "3. Notify Compliance."
        ),
    },
    "cloud_security": {
        "disable": (
            "1. Re-enable cloud security controls via AWS/Azure/GCP console. "
            "2. Review CloudTrail/Activity Log for unauthorized access. "
            "3. Run cloud security posture assessment."
        ),
        "modify": (
            "1. Revert cloud policy to IaC-defined baseline. "
            "2. Trigger Terraform plan to detect drift. "
            "3. Validate policy enforcement across all regions."
        ),
        "default": (
            "1. Restore cloud security baseline. "
            "2. Run cloud posture scan (CSPM tool). "
            "3. Review misconfigurations in all accounts."
        ),
    },
    "endpoint": {
        "disable": (
            "1. Re-enable endpoint protection agent. "
            "2. Run full AV/EDR scan on affected endpoints. "
            "3. Review endpoint logs for indicators of compromise."
        ),
        "remove": (
            "1. Reinstall endpoint protection agent. "
            "2. Quarantine affected endpoints. "
            "3. Initiate incident response if IOCs found."
        ),
        "default": (
            "1. Restore endpoint security baseline. "
            "2. Force agent update on all managed endpoints. "
            "3. Validate EDR telemetry."
        ),
    },
    "data_protection": {
        "disable": (
            "1. Re-enable data protection controls. "
            "2. Identify affected data assets and assess exposure. "
            "3. Notify DPO; assess GDPR breach notification obligation."
        ),
        "remove": (
            "1. Restore data protection policy. "
            "2. Perform data inventory audit. "
            "3. Escalate to Legal/Compliance."
        ),
        "default": (
            "1. Restore data protection baseline. "
            "2. Audit data handling during exposure window. "
            "3. Review retention and access policies."
        ),
    },
    "vulnerability": {
        "disable": (
            "1. Re-enable vulnerability scanning immediately. "
            "2. Schedule emergency scan for affected systems. "
            "3. Review unscanned assets for known CVEs."
        ),
        "default": (
            "1. Restore vulnerability management baseline. "
            "2. Run immediate scan on affected scope. "
            "3. Prioritise critical CVEs for patching."
        ),
    },
    "network_segmentation": {
        "modify": (
            "1. Revert network segmentation rules. "
            "2. Verify VLAN/subnet isolation is intact. "
            "3. Review east-west traffic logs for anomalies."
        ),
        "disable": (
            "1. Re-enable segmentation controls immediately. "
            "2. Check for lateral movement indicators. "
            "3. Rebuild firewall zone policies if needed."
        ),
        "default": (
            "1. Restore network segmentation baseline. "
            "2. Validate micro-segmentation policies. "
            "3. Review inter-VLAN routing tables."
        ),
    },
}


# ── Utility Functions ─────────────────────────────────────────────────────────

def normalise(s: str) -> str:
    """Lowercase + strip for safe dict lookups."""
    return str(s).strip().lower()


def is_regression(baseline_val: str, current_val: str) -> bool:
    """
    Returns True if baseline was 'True/enabled' and current is 'False/disabled'.
    Handles: 'True', 'enabled=True', 'true', '1', etc.
    """
    true_pat  = re.compile(r'\b(true|enabled|yes|1)\b', re.I)
    false_pat = re.compile(r'\b(false|disabled|no|0)\b', re.I)
    return bool(true_pat.search(str(baseline_val))) and bool(false_pat.search(str(current_val)))


def is_off_hours(dt: datetime) -> bool:
    """Returns True if change happened between 00:00–06:59 (suspicious window)."""
    return 0 <= dt.hour <= 6


def parse_datetime(dt_str: str) -> Optional[datetime]:
    """Parse datetime strings tolerantly."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(dt_str).strip(), fmt)
        except ValueError:
            continue
    return None


def get_remediation(control_type: str, change_type: str) -> str:
    """Return remediation steps for a given control_type and change_type."""
    ct   = normalise(control_type)
    chg  = normalise(change_type)
    plan = REMEDIATION_TEMPLATES.get(ct, {})
    return plan.get(chg, plan.get("default",
        "Review the configuration against the approved baseline and revert unauthorised changes immediately."))


def get_compliance(control_type: str, compliance_impact: str = "") -> list:
    """Return compliance standards for a control_type, enriched from CSV compliance_impact."""
    ct   = normalise(control_type)
    base = list(COMPLIANCE_MAP.get(ct, ["NIST CM-2"]))
    ci   = str(compliance_impact).strip().upper()
    additions = {
        "NIST": ["NIST CM-3"],
        "GDPR": ["GDPR Article 32"],
        "PCI":  ["PCI-DSS 12.10"],
        "CIS":  ["CIS Benchmark v8"],
        "ISO":  ["ISO 27001 A.12"],
    }
    for prefix, extras in additions.items():
        if ci.startswith(prefix):
            for extra in extras:
                if extra not in base:
                    base.append(extra)
    return base


def generate_plain_english(row: dict, score: int, classification: str) -> str:
    """Generate a human-readable one-paragraph explanation of the drift event."""
    control   = row.get("control_name", "Unknown Control")
    ctrl_type = row.get("control_type", "")
    change    = row.get("change_type", "").capitalize()
    status    = row.get("status", "").replace("_", " ")
    reason    = row.get("change_reason", "unspecified reason")
    dt_obj    = row.get("_datetime")
    dt_str    = dt_obj.strftime("%I:%M %p on %Y-%m-%d") if dt_obj else "unknown time"

    off_phrase = " during off-hours (00:00–07:00, suspicious window)" if row.get("_off_hours") else ""
    reg_phrase = ", reverting a security control from enabled to disabled (regression)" if row.get("_regression") else ""
    impact     = IMPACT_TEMPLATES.get(normalise(ctrl_type), "Security posture degraded.")

    return (
        f"{change} performed on {control} ({ctrl_type}) at {dt_str}{off_phrase}{reg_phrase}. "
        f"Change reason stated: '{reason}'. Current remediation status: {status}. "
        f"Risk score: {score} → classified as {classification.replace('_', ' ')}. "
        f"Business impact: {impact}"
    )


# ── Core Detection Engine ─────────────────────────────────────────────────────

class DriftDetectionEngine:
    """
    Loads drift events, applies multi-factor risk scoring,
    and classifies each event into CRITICAL/HIGH/MEDIUM/BENIGN.
    """

    def __init__(self, baseline_file: Path, events_file: Path):
        self.baselines = self._load_baselines(baseline_file)
        self.events    = []
        self.results   = []
        self._load_events(events_file)

    def _load_baselines(self, path: Path) -> dict:
        """Load NDJSON baseline file into a dict keyed by control_name."""
        baselines = {}
        if not path.exists():
            print(f"[WARN] Baseline file not found: {path}")
            return baselines
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    baselines[obj.get("control_name", "")] = obj
                except json.JSONDecodeError as e:
                    print(f"[WARN] Failed to parse baseline line: {e}")
        print(f"[INFO] Loaded {len(baselines)} baseline configurations.")
        return baselines

    def _load_events(self, path: Path):
        """Load CSV drift events into self.events with pre-computed flags."""
        if not path.exists():
            print(f"[ERROR] Events file not found: {path}")
            sys.exit(1)
        with open(path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row["_datetime"]   = parse_datetime(row.get("change_date", ""))
                row["_off_hours"]  = is_off_hours(row["_datetime"]) if row["_datetime"] else False
                row["_regression"] = is_regression(
                    row.get("baseline_value", ""),
                    row.get("current_value", "")
                )
                self.events.append(row)
        print(f"[INFO] Loaded {len(self.events)} drift events.")

    def compute_risk_score(self, row: dict) -> tuple:
        """
        Apply 6-factor risk scoring. Returns (total_score, breakdown_dict).

        Scoring factors:
          1. severity weight
          2. status weight (Compliant/Remediated get a small penalty)
          3. change_type risk weight
          4. regression bonus (severity-gated: 0 for Low/Info)
          5. off-hours flag (+10 if 00:00–06:59)
          6. compliance_impact present (+10)

        False-positive guards:
          - Regression bonus is 0 for Low/Info severity (auto-corrected by tooling)
          - Compliant/Remediated status subtracts 5 (already resolved)
          - classify() caps Low→MEDIUM_DRIFT, Info→BENIGN regardless of score
        """
        sev = normalise(row.get("severity", ""))

        breakdown = {}
        breakdown["severity"]    = SEVERITY_WEIGHTS.get(sev, 0)
        breakdown["status"]      = STATUS_WEIGHTS.get(normalise(row.get("status", "")), 0)
        breakdown["change_type"] = CHANGE_TYPE_WEIGHTS.get(normalise(row.get("change_type", "")), 0)

        # Severity-gated regression bonus (key FP reduction)
        breakdown["regression"] = (
            REGRESSION_BONUS_BY_SEVERITY.get(sev, 0)
            if row.get("_regression") else 0
        )

        breakdown["off_hours"]         = 10 if row.get("_off_hours") else 0
        breakdown["compliance_impact"] = 10 if str(row.get("compliance_impact", "")).strip() else 0

        total = max(0, sum(breakdown.values()))
        return total, breakdown

    def classify(self, score: int, severity: str = "") -> str:
        """
        Map numeric risk score to drift classification label.
        Applies severity cap to prevent Low/Info events from being CRITICAL/HIGH.
        """
        # Raw score-based classification
        if score >= THRESHOLD_CRITICAL:
            raw_cls = "CRITICAL_DRIFT"
        elif score >= THRESHOLD_HIGH:
            raw_cls = "HIGH_DRIFT"
        elif score >= THRESHOLD_MEDIUM:
            raw_cls = "MEDIUM_DRIFT"
        else:
            raw_cls = "BENIGN"

        # Apply severity ceiling
        sev = normalise(severity)
        max_cls = SEVERITY_MAX_CLASSIFICATION.get(sev, "CRITICAL_DRIFT")

        # Ordering for ceiling comparison
        order = ["BENIGN", "MEDIUM_DRIFT", "HIGH_DRIFT", "CRITICAL_DRIFT"]
        raw_idx = order.index(raw_cls) if raw_cls in order else 0
        max_idx = order.index(max_cls) if max_cls in order else 3

        return order[min(raw_idx, max_idx)]

    def process_all(self) -> list:
        """Process all events; return list of enriched result dicts."""
        results = []
        for row in self.events:
            score, breakdown = self.compute_risk_score(row)
            classification   = self.classify(score, row.get("severity", ""))
            dt_obj           = row.get("_datetime")

            result = {
                "drift_event_id":    row.get("drift_event_id", ""),
                "control_name":      row.get("control_name", ""),
                "control_type":      row.get("control_type", ""),
                "severity":          row.get("severity", ""),
                "change_type":       row.get("change_type", ""),
                "status":            row.get("status", ""),
                "baseline_value":    row.get("baseline_value", ""),
                "current_value":     row.get("current_value", ""),
                "change_date":       row.get("change_date", ""),
                "change_hour":       dt_obj.hour if dt_obj else -1,
                "operator_name":     row.get("operator_name", ""),
                "operator_email":    row.get("operator_email", ""),
                "approver_name":     row.get("approver_name", ""),
                "approver_email":    row.get("approver_email", ""),
                "change_reason":     row.get("change_reason", ""),
                "compliance_impact": row.get("compliance_impact", ""),
                "is_regression":     row.get("_regression", False),
                "is_off_hours":      row.get("_off_hours", False),
                "risk_score":        score,
                "score_breakdown":   json.dumps(breakdown),
                "classification":    classification,
            }
            results.append(result)

        self.results = results
        print(f"[INFO] Scored and classified {len(results)} events.")
        return results


# ── Explainability Engine ─────────────────────────────────────────────────────

class ExplainabilityEngine:
    """
    Generates structured JSON explanations for CRITICAL and HIGH drift events.
    Each explanation includes plain-English narrative, compliance violations,
    business impact, and remediation steps.
    """

    def __init__(self, results: list):
        self.results = results

    def generate_explanations(self) -> list:
        """Return list of explanation dicts for CRITICAL_DRIFT and HIGH_DRIFT events."""
        explanations = []
        for r in self.results:
            if r["classification"] not in ("CRITICAL_DRIFT", "HIGH_DRIFT"):
                continue

            ctrl_type   = r.get("control_type", "")
            change_type = r.get("change_type", "")

            # Reconstruct flags for plain-english generation
            dt_obj = parse_datetime(r.get("change_date", ""))
            fake_row = dict(r)
            fake_row["_datetime"]   = dt_obj
            fake_row["_off_hours"]  = r.get("is_off_hours", False)
            fake_row["_regression"] = r.get("is_regression", False)

            explanation = {
                "drift_id":              r["drift_event_id"],
                "risk_score":            r["risk_score"],
                "classification":        r["classification"],
                "control_name":          r["control_name"],
                "control_type":          ctrl_type,
                "severity":              r["severity"],
                "change_type":           change_type,
                "change_date":           r["change_date"],
                "is_off_hours":          r["is_off_hours"],
                "is_regression":         r["is_regression"],
                "plain_english":         generate_plain_english(fake_row, r["risk_score"], r["classification"]),
                "compliance_violations": get_compliance(ctrl_type, r.get("compliance_impact", "")),
                "business_impact":       IMPACT_TEMPLATES.get(normalise(ctrl_type), "Security posture degraded."),
                "remediation":           get_remediation(ctrl_type, change_type),
                "operator":              f"{r['operator_name']} <{r['operator_email']}>",
                "approver":              f"{r['approver_name']} <{r['approver_email']}>",
            }
            explanations.append(explanation)

        print(f"[INFO] Generated {len(explanations)} structured explanations.")
        return explanations


# ── Report Generator ──────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Generates:
    - Plain-text executive summary (drift_summary_report.txt)
    - Full markdown audit report (audit_report.md)
    """

    def __init__(self, results: list, explanations: list):
        self.results      = results
        self.explanations = explanations
        self._compute_stats()

    def _compute_stats(self):
        self.total    = len(self.results)
        self.critical = sum(1 for r in self.results if r["classification"] == "CRITICAL_DRIFT")
        self.high     = sum(1 for r in self.results if r["classification"] == "HIGH_DRIFT")
        self.medium   = sum(1 for r in self.results if r["classification"] == "MEDIUM_DRIFT")
        self.benign   = sum(1 for r in self.results if r["classification"] == "BENIGN")

        self.compliance_counts  = defaultdict(int)
        self.compliance_controls = defaultdict(set)
        for exp in self.explanations:
            for std in exp.get("compliance_violations", []):
                self.compliance_counts[std] += 1
                self.compliance_controls[std].add(exp["control_name"])

        self.operator_scores = defaultdict(int)
        for r in self.results:
            self.operator_scores[r["operator_email"]] += r["risk_score"]

        self.ctrl_type_counts = Counter(r["control_type"] for r in self.results)
        self.off_hours_count  = sum(1 for r in self.results if r["is_off_hours"])
        self.regression_count = sum(1 for r in self.results if r["is_regression"])

    def write_summary_report(self, path: Path):
        """Write plain-text executive summary."""
        top3 = sorted(self.results, key=lambda x: x["risk_score"], reverse=True)[:3]
        lines = [
            "=" * 70,
            " SECURITY CONTROL DRIFT DETECTION – EXECUTIVE SUMMARY REPORT",
            "=" * 70,
            f" Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f" Data period  : Apr 2025 – Apr 2026",
            f" Total events : {self.total:,}",
            "",
            "── CLASSIFICATION BREAKDOWN ──────────────────────────────────────",
            f"  CRITICAL_DRIFT  : {self.critical:>5}  ({self.critical/self.total*100:.1f}%)",
            f"  HIGH_DRIFT      : {self.high:>5}  ({self.high/self.total*100:.1f}%)",
            f"  MEDIUM_DRIFT    : {self.medium:>5}  ({self.medium/self.total*100:.1f}%)",
            f"  BENIGN          : {self.benign:>5}  ({self.benign/self.total*100:.1f}%)",
            "",
            "── TOP 3 HIGHEST-RISK EVENTS ─────────────────────────────────────",
        ]
        for i, r in enumerate(top3, 1):
            lines.append(
                f"  {i}. [{r['drift_event_id']}] {r['control_name']} ({r['control_type']})"
                f" | Score: {r['risk_score']} | {r['severity']} | {r['change_type']}"
                f" | {r['change_date']}"
            )
        lines += [
            "",
            "── RISK SIGNALS ──────────────────────────────────────────────────",
            f"  Off-hours changes  : {self.off_hours_count}  ({self.off_hours_count/self.total*100:.1f}%)",
            f"  Regression changes : {self.regression_count}  ({self.regression_count/self.total*100:.1f}%)",
            "",
            "── TOP 5 CONTROL TYPES BY VOLUME ─────────────────────────────────",
        ]
        for ct, cnt in self.ctrl_type_counts.most_common(5):
            lines.append(f"  {ct:<28} {cnt:>4} events")
        lines += [
            "",
            "── TOP 10 COMPLIANCE VIOLATIONS ──────────────────────────────────",
        ]
        for std, cnt in sorted(self.compliance_counts.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {std:<32} {cnt:>4} violations")
        lines += [
            "",
            "── TOP 5 RISKIEST OPERATORS ──────────────────────────────────────",
        ]
        for email, score in sorted(self.operator_scores.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"  {email:<45}  Total risk: {score:,}")
        lines += [
            "",
            "── RECOMMENDED IMMEDIATE ACTIONS ────────────────────────────────",
            "  1. Review all CRITICAL_DRIFT events immediately.",
            "  2. Escalate off-hours changes to CISO for investigation.",
            "  3. Audit all regressions (enabled->disabled) for malicious intent.",
            "  4. File compliance incident reports for GDPR/NIST violations.",
            "  5. Enforce change-management approval gates for high-criticality controls.",
            "",
            "=" * 70,
            "  See: drift_analysis_results.csv  — full event-level analysis",
            "  See: drift_explanations.json     — CRITICAL/HIGH structured explanations",
            "  See: remediation_playbook.md     — per-control-type fix procedures",
            "=" * 70,
        ]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[INFO] Summary report written: {path}")

    def write_audit_report(self, path: Path):
        """Write full markdown audit report."""
        top20    = sorted(self.explanations, key=lambda x: x["risk_score"], reverse=True)[:20]
        top_ops  = sorted(self.operator_scores.items(), key=lambda x: -x[1])[:10]
        op_evts  = Counter(r["operator_email"] for r in self.results)

        lines = []
        # Header
        lines.append("# Security Control Drift – Full Audit Report\n\n")
        lines.append(f"> **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        lines.append(f"> **Data Period:** April 2025 – April 2026  \n")
        lines.append(f"> **Events Analysed:** {self.total:,}\n\n---\n\n")

        # 1. Executive Summary
        lines.append("## 1. Executive Summary\n\n")
        lines.append(
            f"Analysis of **{self.total:,}** security configuration drift events across 10 control types "
            f"identified **{self.critical} CRITICAL** and **{self.high} HIGH** risk deviations. "
            f"**{self.off_hours_count}** changes occurred during off-hours (00:00–07:00). "
            f"**{self.regression_count}** events represent security regressions "
            f"(controls explicitly disabled after being enabled).\n\n"
        )
        lines.append("### Top 3 Critical Findings\n\n")
        for i, exp in enumerate(top20[:3], 1):
            lines.append(
                f"**{i}. [{exp['drift_id']}]** `{exp['control_name']}` ({exp['control_type']}) "
                f"– Risk Score: **{exp['risk_score']}** | {exp['severity']} | {exp['change_date']}\n\n"
                f"> {exp['plain_english'][:250]}...\n\n"
            )
        lines.append("---\n\n")

        # 2. Methodology
        lines.append("## 2. Methodology – Risk Scoring\n\n")
        lines.append("| Factor | Weight | Notes |\n|--------|--------|-------|\n")
        lines.append("| Severity | Critical=40, High=30, Medium=15, Low=5, Info=0 | From event severity field |\n")
        lines.append("| Status | Drifted=30, Under_Review=15, Mitigated=5, Compliant/Remediated=0 | Unresolved scores higher |\n")
        lines.append("| Change Type | Disable=25, Remove=20, Modify=10, Update=5, Enable=-5, Rollback=0 | Destructive changes score higher |\n")
        lines.append("| Regression | +20 | Baseline enabled → current disabled |\n")
        lines.append("| Off-Hours | +10 | Change between 00:00–06:59 |\n")
        lines.append("| Compliance Impact Present | +10 | Non-empty compliance_impact field |\n\n")
        lines.append("**Thresholds:** CRITICAL ≥ 70 · HIGH 50–69 · MEDIUM 30–49 · BENIGN < 30\n\n---\n\n")

        # 3. Top 20 Drifts
        lines.append("## 3. Top 20 Detected Drifts\n\n")
        for i, exp in enumerate(top20, 1):
            lines.append(f"### {i}. `{exp['drift_id']}` | Score: {exp['risk_score']} | {exp['classification']}\n\n")
            lines.append("```json\n")
            lines.append(json.dumps(exp, indent=2, default=str))
            lines.append("\n```\n\n")
        lines.append("---\n\n")

        # 4. Compliance Matrix
        lines.append("## 4. Compliance Impact Matrix\n\n")
        lines.append("| Standard | Violations | Affected Controls | Risk Level |\n")
        lines.append("|----------|-----------|-------------------|------------|\n")
        for std, cnt in sorted(self.compliance_counts.items(), key=lambda x: -x[1]):
            ctrls = ", ".join(sorted(self.compliance_controls[std])[:4])
            if len(self.compliance_controls[std]) > 4:
                ctrls += f" +{len(self.compliance_controls[std])-4} more"
            risk = "CRITICAL" if cnt > 50 else ("HIGH" if cnt > 20 else "MEDIUM")
            lines.append(f"| {std} | {cnt} | {ctrls} | {risk} |\n")
        lines.append("\n---\n\n")

        # 5. Operator Risk Ranking
        lines.append("## 5. Operator Risk Ranking\n\n")
        lines.append("| Rank | Email | Total Risk Score | Event Count |\n")
        lines.append("|------|-------|-----------------|-------------|\n")
        for i, (email, score) in enumerate(top_ops, 1):
            lines.append(f"| {i} | {email} | {score:,} | {op_evts[email]} |\n")
        lines.append("\n---\n\n")

        # 6. Remediation Priority Queue
        lines.append("## 6. Remediation Priority Queue\n\n")
        lines.append("| Priority | Drift ID | Control | Type | Score | Est. Fix Time | First Step |\n")
        lines.append("|----------|----------|---------|------|-------|--------------|------------|\n")
        for i, exp in enumerate(top20, 1):
            fix_time = "15–30 min" if exp["classification"] == "CRITICAL_DRIFT" else "30–60 min"
            first_step = exp["remediation"].split(".")[0] + "."
            lines.append(
                f"| P{i} | {exp['drift_id']} | {exp['control_name']} | {exp['control_type']} "
                f"| {exp['risk_score']} | {fix_time} | {first_step} |\n"
            )
        lines.append("\n---\n\n")

        # 7. Gaps & Limitations
        lines.append("## 7. Gaps & Limitations\n\n")
        limitations = [
            "**No real-time baseline pull**: Static baselines only. Live API integration would improve accuracy.",
            "**Binary value comparison**: The regex-based regression detection handles simple enabled/disabled patterns. "
            "Numerical config values (timeouts, port lists) require additional parsers.",
            "**No change-intent NLP**: Change reason strings are not semantically analysed. "
            "An NLP model could further reduce false positives by 10–15%.",
            "**Ground truth dependency**: Without `config_drift_labels.csv`, precision/recall cannot be computed automatically.",
            "**Operator context**: Operators are flagged by aggregate risk score, not intent. "
            "Legitimate senior admins making emergency fixes may appear in high-risk rankings.",
        ]
        for lim in limitations:
            lines.append(f"- {lim}\n")

        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(lines))
        print(f"[INFO] Audit report written: {path}")


# ── Remediation Playbook ──────────────────────────────────────────────────────

def write_remediation_playbook(path: Path):
    """Write the full remediation playbook markdown."""
    content = r"""# Security Control Drift – Remediation Playbook

> **Version:** 2.0 | **Owner:** Security Engineering | **Review Cycle:** Quarterly

---

## Table of Contents
1. [Logging Controls](#1-logging-controls)
2. [Encryption Controls](#2-encryption-controls)
3. [Access Controls](#3-access-controls)
4. [DLP Controls](#4-data-loss-prevention)
5. [Firewall Rules](#5-firewall-rules)
6. [MFA & Authentication](#6-mfa--authentication)
7. [Cloud Security](#7-cloud-security)
8. [Endpoint Protection](#8-endpoint-protection)
9. [Vulnerability Management](#9-vulnerability-management)
10. [Network Segmentation](#10-network-segmentation)
11. [Data Protection](#11-data-protection)
12. [Escalation Matrix](#12-escalation-matrix)

---

## 1. Logging Controls

### Logging Disabled
**Severity:** CRITICAL | **SLA:** 15 minutes

**Immediate Response:**
```bash
# AWS CloudTrail
aws cloudtrail start-logging --name <trail-name>
aws cloudtrail get-trail-status --name <trail-name>

# Azure Monitor
az monitor diagnostic-settings create --name "SecurityLogs" \
  --resource <resource-id> --logs '[{"category":"AuditLogs","enabled":true}]'
```

**Audit Blind Window Recovery:**
1. Identify exact gap timestamps
2. Query SIEM for adjacent system events during gap
3. Review VPC Flow Logs / NSG Flow Logs as fallback
4. Document gap; notify Compliance
5. Check for privileged operations during gap

**Compliance Filings:** NIST AU-2 deviation report, GDPR Article 32 assessment

---

### Log File Validation Disabled
**Severity:** HIGH | **SLA:** 1 hour
```bash
aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation
aws cloudtrail validate-logs --trail-arn <arn> --start-time <gap-start>
```

---

## 2. Encryption Controls

### Encryption Disabled
**Severity:** CRITICAL | **SLA:** 30 minutes

```bash
# AWS RDS – snapshot then restore with encryption
aws rds create-db-snapshot --db-instance-identifier <db> --db-snapshot-identifier pre-remed
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier <new-db> \
  --db-snapshot-identifier pre-remed \
  --storage-encrypted

# AWS S3 – enforce default encryption
aws s3api put-bucket-encryption --bucket <bucket> \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'

# Key rotation
aws kms rotate-key-on-demand --key-id <key-id>
```

**Steps:**
1. Identify all data written during exposure window
2. Classify: PII, financial, health — escalate to DPO if PII found
3. Assess GDPR Article 33 breach notification (72-hour clock)

### Encryption Algorithm Downgraded (AES-256 → AES-128)
**Severity:** HIGH | **SLA:** 2 hours
1. Re-encrypt with AES-256 immediately
2. Update crypto policy to reject weaker algorithms
3. Root-cause: if performance issue, find alternative (hardware acceleration)

---

## 3. Access Controls

### Access Control Removed/Disabled
**Severity:** CRITICAL | **SLA:** 15 minutes

```bash
# AWS IAM – restore policy
aws iam put-role-policy --role-name <role> \
  --policy-name SecurityBaseline \
  --policy-document file://baseline_policy.json

# Azure RBAC
az role assignment create --assignee <principal> \
  --role "Security Reader" --scope /subscriptions/<sub-id>

# Review access during gap
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<operator> \
  --start-time <gap-start> --end-time <gap-end>
```

**Least-Privilege Review:**
1. Run IAM Access Analyzer
2. Remove permissions not used in last 90 days
3. Force re-authentication for all sessions during gap

---

## 4. Data Loss Prevention

### DLP Policy Disabled
**Severity:** HIGH | **SLA:** 30 minutes

```powershell
# Microsoft Purview DLP
Set-DlpCompliancePolicy -Identity "Baseline-DLP-Policy" -Enabled $true
Get-DlpCompliancePolicy -Identity "Baseline-DLP-Policy" | Select Name,Mode,Enabled

# Review email DLP violations during gap
Get-MailDetailDlpPolicyReport -StartDate <gap-start> -EndDate <gap-end>
```

**Steps:**
1. Re-enable all DLP channels (email, file, USB, cloud sync)
2. Scan file transfers from endpoints during gap
3. Review cloud sync logs for large uploads (OneDrive, Dropbox)
4. Check USB activity on affected endpoints
5. Notify Data Governance and Legal

---

## 5. Firewall Rules

### Firewall Rule Modified (New Ports Opened)
**Severity:** HIGH–CRITICAL | **SLA:** 30 minutes

```bash
# AWS Security Group – remove unauthorized ingress
aws ec2 revoke-security-group-ingress \
  --group-id <sg-id> \
  --protocol tcp \
  --port <unauthorized-port> \
  --cidr 0.0.0.0/0

# Palo Alto – revert commit
set deviceconfig system panorama-server <panorama-ip>
request plugins update

# Check for exploitation via VPC flow logs
aws logs filter-log-events \
  --log-group-name /aws/vpc/flowlogs \
  --filter-pattern "[version, account, intf, srcaddr, dstaddr, srcport, dstport=<port>, proto=6, ...]"
```

### Deny Rule Deleted
**Severity:** CRITICAL | **SLA:** 15 minutes
1. Restore deny rule from IaC baseline immediately
2. Review all traffic that traversed the gap
3. Threat intelligence lookup on source IPs

---

## 6. MFA & Authentication

### MFA Disabled for Admin Accounts
**Severity:** CRITICAL | **SLA:** Immediate

```powershell
# Azure AD – re-enforce MFA
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <policy-id> `
  -GrantControls @{Operator="AND"; BuiltInControls=@("mfa")}

# Revoke admin sessions
Revoke-MgUserSignInSession -UserId <admin-upn>
```

**Admin Session Audit:**
1. List all admin sign-ins during MFA gap
2. Verify IP ranges / managed devices
3. Check for impossible travel events
4. Force password reset for all admin accounts that authenticated without MFA
5. Set grace period = 0 days (no exceptions without CISO sign-off)

---

## 7. Cloud Security

### Cloud Security Policy Disabled
**Severity:** HIGH | **SLA:** 1 hour

```bash
# AWS Security Hub
aws securityhub enable-security-hub --enable-default-standards

# AWS Config
aws configservice put-config-rule --config-rule file://baseline_config_rule.json

# Azure Defender
az security pricing create --name VirtualMachines --tier standard

# GCP SCC
gcloud scc settings update --organization=<org-id> --enable-asset-discovery
```

**Post-Remediation:**
1. Run CSPM scan immediately
2. Review all config changes during gap
3. Check for new public-facing resources
4. Validate IAM policies across all cloud accounts

---

## 8. Endpoint Protection

### Endpoint Protection Agent Removed
**Severity:** CRITICAL | **SLA:** 30 minutes

```powershell
# CrowdStrike Falcon reinstall
.\WindowsSensor.exe /install /quiet CID=<customer-id> GROUPING_TAGS=<tag>

# Microsoft Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Start-MpScan -ScanType FullScan
Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled
```

**Steps:**
1. Re-install agent on all affected hosts
2. Run full anti-malware scan
3. Review EDR telemetry for missed detections during gap
4. Check for persistence (registry, scheduled tasks, services)
5. **Isolate endpoint from network if IOCs found**

---

## 9. Vulnerability Management

### Vulnerability Scanning Disabled
**Severity:** HIGH | **SLA:** 2 hours

```bash
# Tenable/Nessus
curl -k -X POST "https://<host>/scans/<id>/launch" \
  -H "X-ApiKeys: accessKey=<key>;secretKey=<secret>"

# Qualys
qualys_scan --action resume --scan-ref <ref>
```

**Steps:**
1. Re-enable scanning for affected scope
2. Schedule emergency scan
3. Review CVEs disclosed during gap against asset inventory
4. Prioritise critical/high CVEs for emergency patching
5. Document unscanned assets in risk register

---

## 10. Network Segmentation

### Segmentation Controls Modified/Disabled
**Severity:** HIGH | **SLA:** 1 hour

```bash
# AWS – restore security group rules
aws ec2 authorize-security-group-egress \
  --group-id <sg-id> \
  --ip-permissions <baseline-rules-json>

# Cisco – restore VLAN ACLs
vlan access-map BLOCK_LATERAL 10
  action drop
  match ip address LATERAL_TRAFFIC
vlan filter BLOCK_LATERAL vlan-list <vlan-range>
```

**Steps:**
1. Restore segmentation rules from IaC (Terraform/Ansible)
2. Verify VLAN/subnet isolation with network scan
3. Review east-west traffic for anomalous cross-segment communication
4. Re-validate micro-segmentation in NSX/Prisma

---

## 11. Data Protection

### Data Protection Controls Disabled/Removed
**Severity:** CRITICAL | **SLA:** 30 minutes

1. Immediately re-enable data protection controls
2. Identify all affected data assets
3. Classify: PII, financial, health data
4. Assess GDPR Article 33 breach notification (72-hour clock starts now)
5. Notify DPO, Legal, Compliance immediately
6. **Preserve all evidence** before remediation begins

---

## 12. Escalation Matrix

| Risk Level | SLA | Notify | Action |
|------------|-----|--------|--------|
| CRITICAL_DRIFT | 15 min | CISO, SOC Lead, DPO | Immediate remediation; isolate if needed |
| HIGH_DRIFT | 1 hour | SOC Lead, Control Owner | Remediate within SLA; file ticket |
| MEDIUM_DRIFT | 4 hours | Control Owner | Schedule review; assess risk |
| BENIGN | 24 hours | Log only | No action required |

### Off-Hours Protocol
- All CRITICAL/HIGH drifts between 00:00–07:00 → escalate to on-call SOC engineer
- On-call: `soc-oncall@company.com` | PagerDuty: `P-SOC-CRITICAL`

### Unapproved Change Process
1. Set status to `Under_Review` in ITSM
2. Notify operator's manager
3. Investigate intent (malicious vs accidental)
4. If malicious: escalate to HR + Legal + CISO immediately
5. Preserve digital evidence before any remediation

---

*This playbook is a living document. Update after every major incident.*
*Next review: Quarterly | Owner: Security Engineering*
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[INFO] Remediation playbook written: {path}")


# ── Ground Truth Evaluation ───────────────────────────────────────────────────

def evaluate_model(results: list, labels_file: Path):
    """Compare predictions against ground truth labels (if available)."""
    if not labels_file.exists():
        print("[INFO] Labels file not found — skipping evaluation.")
        return

    labels_map = {}
    with open(labels_file, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels_map[row.get("drift_event_id", "").strip()] = row

    y_true, y_pred = [], []
    for r in results:
        if r["drift_event_id"] not in labels_map:
            continue
        true_anomaly = int(str(labels_map[r["drift_event_id"]].get("is_anomaly", "0")).strip()) == 1
        pred_anomaly = r["classification"] in ("CRITICAL_DRIFT", "HIGH_DRIFT")
        y_true.append(1 if true_anomaly else 0)
        y_pred.append(1 if pred_anomaly else 0)

    if not y_true:
        print("[WARN] No matching event IDs found in labels file.")
        return

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    print("\n" + "=" * 60)
    print(" MODEL EVALUATION vs. GROUND TRUTH")
    print("=" * 60)
    print(f"  Matched events    : {len(y_true)}")
    print(f"  True Positives    : {tp}")
    print(f"  False Positives   : {fp}")
    print(f"  True Negatives    : {tn}")
    print(f"  False Negatives   : {fn}")
    print(f"  Precision         : {precision:.3f} ({precision*100:.1f}%)")
    print(f"  Recall            : {recall:.3f} ({recall*100:.1f}%)")
    print(f"  F1 Score          : {f1:.3f}")
    print(f"  False Positive Rate: {fpr:.3f} ({fpr*100:.1f}%)")
    target = "MEETS TARGET" if precision >= 0.85 and recall >= 0.80 and fpr <= 0.15 else "REVIEW NEEDED"
    print(f"  Assessment        : {target}")
    print("=" * 60 + "\n")


# ── Output Writers ────────────────────────────────────────────────────────────

def write_results_csv(results: list, path: Path):
    if not results:
        return
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"[INFO] Results CSV written: {path}  ({len(results):,} rows)")


def write_explanations_json(explanations: list, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(explanations, f, indent=2, default=str)
    print(f"[INFO] Explanations JSON written: {path}  ({len(explanations)} records)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 70)
    print("  SECURITY CONTROL DRIFT DETECTION SYSTEM  v2.0")
    print("  Societe Generale Enterprise Security Hackathon")
    print("=" * 70 + "\n")

    t_start = time.perf_counter()

    # Step 1: Detect & Score
    engine  = DriftDetectionEngine(BASELINE_FILE, EVENTS_FILE)
    results = engine.process_all()
    write_results_csv(results, OUT_RESULTS)

    # Step 2: Explain
    exp_engine   = ExplainabilityEngine(results)
    explanations = exp_engine.generate_explanations()
    write_explanations_json(explanations, OUT_EXPL)

    # Step 3: Report
    reporter = ReportGenerator(results, explanations)
    reporter.write_summary_report(OUT_SUMMARY)
    reporter.write_audit_report(OUT_AUDIT)

    # Step 4: Playbook
    write_remediation_playbook(OUT_PLAYBOOK)

    # Step 5: Evaluate (optional)
    evaluate_model(results, LABELS_FILE)

    t_elapsed = time.perf_counter() - t_start

    # Final metrics
    total    = len(results)
    critical = sum(1 for r in results if r["classification"] == "CRITICAL_DRIFT")
    high     = sum(1 for r in results if r["classification"] == "HIGH_DRIFT")
    medium   = sum(1 for r in results if r["classification"] == "MEDIUM_DRIFT")
    benign   = sum(1 for r in results if r["classification"] == "BENIGN")

    print("\n" + "=" * 70)
    print("  PROCESSING COMPLETE")
    print("=" * 70)
    print(f"  Total events processed : {total:,}")
    print(f"  CRITICAL_DRIFT         : {critical:,}")
    print(f"  HIGH_DRIFT             : {high:,}")
    print(f"  MEDIUM_DRIFT           : {medium:,}")
    print(f"  BENIGN                 : {benign:,}")
    print(f"  Processing time        : {t_elapsed:.3f}s")
    print(f"  Throughput             : {total/t_elapsed:,.0f} events/sec")
    print(f"  Performance (< 5s)     : {'PASS' if t_elapsed < 5 else 'FAIL'}")
    print("\n  Output files:")
    for f_path in [OUT_RESULTS, OUT_SUMMARY, OUT_EXPL, OUT_AUDIT, OUT_PLAYBOOK]:
        sz = os.path.getsize(f_path) if f_path.exists() else 0
        print(f"    {f_path.name:<42}  {sz:>8,} bytes")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
