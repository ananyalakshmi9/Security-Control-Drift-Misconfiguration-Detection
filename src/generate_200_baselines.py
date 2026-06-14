#!/usr/bin/env python3
"""
generate_200_baselines.py
Generates a comprehensive 200-control baseline configuration store.
Covers 10 control domains × 20 controls each.
Output: sample_data/baseline_configs_200.json  (one JSON object per line)
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta

random.seed(42)
BASE_DIR = Path(__file__).parent.parent
OUT = BASE_DIR / "sample_data" / "baseline_configs_200.json"

BASELINE_TS   = "2026-01-01T00:00:00Z"
REVIEW_CYCLE  = "quarterly"

# ── Domain definitions ──────────────────────────────────────────────────────

DOMAINS = {

    "FW": {
        "domain": "Firewall",
        "systems": ["Palo Alto Networks", "Cisco ASA", "Fortinet FortiGate", "Check Point", "pfSense"],
        "criticality_pool": ["critical","critical","high","high","medium"],
        "compliance": ["CIS 3.1", "NIST AC-4", "NIST SC-7", "PCI-DSS 1.2"],
        "configs": [
            lambda i: {
                "allowed_inbound_ports": [22, 80, 443, 8443][:max(2, i % 4 + 1)],
                "allowed_outbound_ports": [80, 443, 53],
                "deny_outbound_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                "logging_enabled": True,
                "threat_prevention": "high",
                "encryption_enabled": True,
                "geo_blocking_enabled": True,
                "stateful_inspection": True,
                "default_deny": True,
                "max_sessions": 500000 + i * 10000,
                "ips_profile": "strict",
                "app_control_enabled": True,
            }
        ],
        "description": "Network perimeter firewall rule enforcement and traffic filtering",
    },

    "ENC": {
        "domain": "Encryption",
        "systems": ["AWS KMS", "Azure Key Vault", "HashiCorp Vault", "Thales HSM", "AWS RDS"],
        "criticality_pool": ["critical","critical","critical","high","high"],
        "compliance": ["GDPR 32", "NIST SC-13", "NIST SC-28", "PCI-DSS 3.4", "ISO 27001 A.10"],
        "configs": [
            lambda i: {
                "encryption_enabled": True,
                "encryption_algorithm": "AES-256",
                "key_rotation_days": 90,
                "key_length_bits": 256,
                "tls_minimum_version": "1.2",
                "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
                "at_rest_encryption": True,
                "in_transit_encryption": True,
                "log_encryption": True,
                "hsm_backed": True,
                "multi_region_replication": True,
                "auto_rotation_enabled": True,
            }
        ],
        "description": "Data-at-rest and in-transit encryption controls for sensitive assets",
    },

    "LOG": {
        "domain": "Logging",
        "systems": ["Splunk", "AWS CloudTrail", "Azure Monitor", "Elastic SIEM", "CrowdStrike Falcon"],
        "criticality_pool": ["critical","high","high","medium","medium"],
        "compliance": ["NIST AU-2", "NIST AU-12", "CIS 2.1", "GDPR 32", "ISO 27001 A.12"],
        "configs": [
            lambda i: {
                "logging_enabled": True,
                "log_retention_days": 365,
                "multi_region": True,
                "log_file_validation": True,
                "s3_bucket_logging": True,
                "cloudwatch_integration": True,
                "siem_forwarding_enabled": True,
                "immutable_logs": True,
                "compression_enabled": True,
                "encryption_at_rest": True,
                "alert_on_deletion": True,
                "min_log_level": "INFO",
                "audit_log_enabled": True,
                "log_shipping_interval_seconds": 60,
            }
        ],
        "description": "Centralized audit logging, retention, and SIEM forwarding controls",
    },

    "ACC": {
        "domain": "Access_Control",
        "systems": ["Okta", "Azure AD", "CyberArk", "BeyondTrust", "AWS IAM"],
        "criticality_pool": ["critical","critical","high","high","medium"],
        "compliance": ["NIST IA-2", "NIST IA-5", "CIS 5.3", "GDPR 25", "ISO 27001 A.9"],
        "configs": [
            lambda i: {
                "mfa_enabled": True,
                "mfa_method": "TOTP",
                "privileged_access_mfa": True,
                "session_timeout_minutes": 30,
                "max_login_attempts": 5,
                "lockout_duration_minutes": 15,
                "password_min_length": 14,
                "password_complexity_enabled": True,
                "password_expiry_days": 90,
                "password_history_count": 12,
                "just_in_time_access": True,
                "least_privilege_enforced": True,
                "service_account_mfa": True,
                "sso_enabled": True,
                "privileged_session_recording": True,
            }
        ],
        "description": "Identity and access management including MFA, PAM, and least privilege controls",
    },

    "DLP": {
        "domain": "DLP",
        "systems": ["Symantec DLP", "Microsoft Purview", "Forcepoint DLP", "McAfee DLP", "Nightfall AI"],
        "criticality_pool": ["critical","high","high","medium","medium"],
        "compliance": ["GDPR 25", "GDPR 32", "ISO 27001 A.13", "NIST SI-12", "PCI-DSS 3.3"],
        "configs": [
            lambda i: {
                "dlp_enabled": True,
                "email_scanning_enabled": True,
                "endpoint_dlp_enabled": True,
                "cloud_dlp_enabled": True,
                "usb_blocking_enabled": True,
                "print_blocking_pii": True,
                "screenshot_prevention": True,
                "data_classification_enabled": True,
                "classification_levels": ["Public", "Internal", "Confidential", "Restricted"],
                "pii_detection_enabled": True,
                "financial_data_detection": True,
                "health_data_detection": True,
                "policy_violation_alert": True,
                "quarantine_on_violation": True,
                "audit_all_transfers": True,
            }
        ],
        "description": "Data loss prevention controls across email, endpoint, cloud, and removable media",
    },

    "CLD": {
        "domain": "Cloud_Security",
        "systems": ["AWS Security Hub", "Azure Defender", "GCP Security Command Center", "Wiz", "Prisma Cloud"],
        "criticality_pool": ["critical","critical","high","high","medium"],
        "compliance": ["CIS 2.1", "NIST CM-2", "NIST CM-6", "CIS AWS Benchmark v1.4", "SOC 2 Type II"],
        "configs": [
            lambda i: {
                "security_hub_enabled": True,
                "config_rules_enabled": True,
                "guard_duty_enabled": True,
                "macie_enabled": True,
                "public_s3_blocked": True,
                "root_account_mfa": True,
                "cloudtrail_all_regions": True,
                "vpc_flow_logs": True,
                "ebs_encryption_by_default": True,
                "rds_deletion_protection": True,
                "lambda_tracing_enabled": True,
                "iam_password_policy_enforced": True,
                "unused_credentials_auto_disable_days": 90,
                "access_analyzer_enabled": True,
                "findings_auto_remediation": True,
            }
        ],
        "description": "Cloud security posture management (CSPM) controls across AWS/Azure/GCP",
    },

    "END": {
        "domain": "Endpoint",
        "systems": ["CrowdStrike Falcon", "Microsoft Defender ATP", "SentinelOne", "Carbon Black", "Cylance"],
        "criticality_pool": ["critical","high","high","medium","medium"],
        "compliance": ["NIST SI-3", "CIS 8.1", "CIS 8.2", "ISO 27001 A.12", "PCI-DSS 5.1"],
        "configs": [
            lambda i: {
                "edr_agent_enabled": True,
                "real_time_protection": True,
                "behavioral_analysis": True,
                "ransomware_protection": True,
                "threat_intel_enabled": True,
                "auto_quarantine_enabled": True,
                "device_control_enabled": True,
                "exploit_prevention": True,
                "memory_protection": True,
                "firewall_enabled": True,
                "disk_encryption_enforced": True,
                "os_patch_compliance_days": 30,
                "agent_version_enforcement": True,
                "threat_hunting_enabled": True,
                "isolation_on_detection": True,
            }
        ],
        "description": "Endpoint detection and response (EDR) controls for workstations and servers",
    },

    "VUL": {
        "domain": "Vulnerability",
        "systems": ["Tenable.io", "Qualys VMDR", "Rapid7 InsightVM", "Nessus", "AWS Inspector"],
        "criticality_pool": ["critical","high","high","medium","medium"],
        "compliance": ["NIST RA-5", "CIS 7.1", "CIS 7.7", "PCI-DSS 11.2", "ISO 27001 A.12"],
        "configs": [
            lambda i: {
                "scanning_enabled": True,
                "scan_frequency_days": 7,
                "authenticated_scanning": True,
                "web_app_scanning": True,
                "container_scanning": True,
                "iac_scanning": True,
                "sast_enabled": True,
                "dast_enabled": True,
                "critical_sla_days": 1,
                "high_sla_days": 7,
                "medium_sla_days": 30,
                "low_sla_days": 90,
                "auto_ticket_creation": True,
                "patch_validation_enabled": True,
                "zero_day_alert_immediate": True,
            }
        ],
        "description": "Vulnerability scanning, patch management SLAs, and risk-based remediation controls",
    },

    "NET": {
        "domain": "Network_Segmentation",
        "systems": ["Cisco ACI", "VMware NSX", "Illumio", "Akamai", "Palo Alto Prisma"],
        "criticality_pool": ["critical","critical","high","high","medium"],
        "compliance": ["NIST SC-7", "CIS 12.1", "CIS 12.7", "PCI-DSS 1.3", "ISO 27001 A.13"],
        "configs": [
            lambda i: {
                "micro_segmentation_enabled": True,
                "vlan_isolation": True,
                "dmz_enabled": True,
                "east_west_inspection": True,
                "north_south_inspection": True,
                "dns_filtering_enabled": True,
                "zero_trust_network_access": True,
                "lateral_movement_detection": True,
                "private_network_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                "inter_zone_policy": "deny_by_default",
                "subnet_flow_logging": True,
                "network_ids_enabled": True,
                "botnet_c2_blocking": True,
                "sinkholing_enabled": True,
                "max_hop_count": 3,
            }
        ],
        "description": "Network segmentation, micro-segmentation, and zero-trust connectivity controls",
    },

    "DAT": {
        "domain": "Data_Protection",
        "systems": ["Varonis", "Imperva", "IBM Guardium", "Oracle Audit Vault", "Informatica"],
        "criticality_pool": ["critical","critical","high","high","medium"],
        "compliance": ["GDPR 32", "PCI-DSS 3.4", "NIST SI-12", "HIPAA § 164.312", "ISO 27001 A.10"],
        "configs": [
            lambda i: {
                "data_masking_enabled": True,
                "tokenization_enabled": True,
                "database_activity_monitoring": True,
                "privileged_user_monitoring": True,
                "column_level_encryption": True,
                "backup_encryption": True,
                "cross_border_transfer_controls": True,
                "data_residency_enforced": True,
                "retention_policy_enforced": True,
                "right_to_erasure_capability": True,
                "data_lineage_tracking": True,
                "anomalous_access_alerting": True,
                "query_rate_limiting": True,
                "sensitive_field_redaction": True,
                "audit_all_pii_access": True,
            }
        ],
        "description": "Data protection, masking, tokenization, and privacy control enforcement",
    },
}


def make_control(domain_key: str, idx: int, domain_cfg: dict) -> dict:
    """Build one baseline control record."""
    sys_list = domain_cfg["systems"]
    system   = sys_list[idx % len(sys_list)]
    crit     = domain_cfg["criticality_pool"][idx % len(domain_cfg["criticality_pool"])]
    cfg_fn   = domain_cfg["configs"][0]
    cfg      = cfg_fn(idx)

    control_num = str(idx + 1).zfill(3)
    control_id  = f"{domain_key}-{control_num}"

    # Vary a few config values slightly per control to make it realistic
    cfg_copy = dict(cfg)
    if "session_timeout_minutes" in cfg_copy:
        cfg_copy["session_timeout_minutes"] = [15, 20, 30, 60][idx % 4]
    if "scan_frequency_days" in cfg_copy:
        cfg_copy["scan_frequency_days"] = [1, 3, 7, 14][idx % 4]
    if "log_retention_days" in cfg_copy:
        cfg_copy["log_retention_days"] = [90, 180, 365, 730][idx % 4]

    # Compliance mappings — pick 2-4 from domain pool
    comp_pool = domain_cfg["compliance"]
    num_std   = 2 + (idx % 3)
    comp_map  = comp_pool[:num_std]

    owner_dept = ["SOC", "IT Security", "Platform Engineering", "Compliance", "Risk"][idx % 5]
    review_date = f"2026-{str((idx % 12) + 1).zfill(2)}-01T00:00:00Z"

    return {
        "control_id":          control_id,
        "control_name":        f"{domain_cfg['domain']}_Control_{control_num}",
        "domain":              domain_cfg["domain"],
        "system":              system,
        "description":         domain_cfg["description"],
        "criticality":         crit,
        "owner_team":          owner_dept,
        "review_cycle":        REVIEW_CYCLE,
        "next_review_date":    review_date,
        "baseline_timestamp":  BASELINE_TS,
        "compliance_mappings": comp_map,
        "baseline_config":     cfg_copy,
    }


def main():
    records = []
    per_domain = 20

    for domain_key, domain_cfg in DOMAINS.items():
        for i in range(per_domain):
            rec = make_control(domain_key, i, domain_cfg)
            records.append(rec)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    print(f"Generated {len(records)} baseline controls → {OUT}")
    print(f"File size: {OUT.stat().st_size:,} bytes")

    # Print summary
    from collections import Counter
    domains = Counter(r["domain"] for r in records)
    crits   = Counter(r["criticality"] for r in records)
    print("\nDomain distribution:")
    for d, c in sorted(domains.items()):
        print(f"  {d:<25} {c:>3} controls")
    print("\nCriticality distribution:")
    for c, n in sorted(crits.items(), key=lambda x: -x[1]):
        print(f"  {c:<12} {n:>3} controls")


if __name__ == "__main__":
    main()
