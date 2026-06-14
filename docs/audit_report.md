# Security Control Drift – Full Audit Report

> **Generated:** 2026-06-14 18:25:04  
> **Data Period:** April 2025 – April 2026  
> **Events Analysed:** 1,000

---

## 1. Executive Summary

Analysis of **1,000** security configuration drift events across 10 control types identified **111 CRITICAL** and **220 HIGH** risk deviations. **136** changes occurred during off-hours (00:00–07:00). **508** events represent security regressions (controls explicitly disabled after being enabled).

### Top 3 Critical Findings

**1. [DRF00691]** `Control-33` (Endpoint) – Risk Score: **135** | Critical | 2025-08-25 01:02:00

> Disable performed on Control-33 (Endpoint) at 01:02 AM on 2025-08-25 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation sta...

**2. [DRF00908]** `Control-1` (Access_Control) – Risk Score: **135** | Critical | 2025-11-16 04:58:00

> Disable performed on Control-1 (Access_Control) at 04:58 AM on 2025-11-16 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediat...

**3. [DRF00849]** `Control-13` (Data_Protection) – Risk Score: **125** | High | 2025-12-24 03:53:00

> Disable performed on Control-13 (Data_Protection) at 03:53 AM on 2025-12-24 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remedi...

---

## 2. Methodology – Risk Scoring

| Factor | Weight | Notes |
|--------|--------|-------|
| Severity | Critical=40, High=30, Medium=15, Low=5, Info=0 | From event severity field |
| Status | Drifted=30, Under_Review=15, Mitigated=5, Compliant/Remediated=0 | Unresolved scores higher |
| Change Type | Disable=25, Remove=20, Modify=10, Update=5, Enable=-5, Rollback=0 | Destructive changes score higher |
| Regression | +20 | Baseline enabled → current disabled |
| Off-Hours | +10 | Change between 00:00–06:59 |
| Compliance Impact Present | +10 | Non-empty compliance_impact field |

**Thresholds:** CRITICAL ≥ 70 · HIGH 50–69 · MEDIUM 30–49 · BENIGN < 30

---

## 3. Top 20 Detected Drifts

### 1. `DRF00691` | Score: 135 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00691",
  "risk_score": 135,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-33",
  "control_type": "Endpoint",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2025-08-25 01:02:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Disable performed on Control-33 (Endpoint) at 01:02 AM on 2025-08-25 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Drifted. Risk score: 135 \u2192 classified as CRITICAL DRIFT. Business impact: Endpoints lack threat detection/prevention. Malware propagation risk is elevated. CIS 8.1 anti-malware controls violated.",
  "compliance_violations": [
    "NIST SI-3",
    "CIS 8.1",
    "PCI-DSS 12.10"
  ],
  "business_impact": "Endpoints lack threat detection/prevention. Malware propagation risk is elevated. CIS 8.1 anti-malware controls violated.",
  "remediation": "1. Re-enable endpoint protection agent. 2. Run full AV/EDR scan on affected endpoints. 3. Review endpoint logs for indicators of compromise.",
  "operator": "Vikram Moore <vikram.moore@company.com>",
  "approver": "Jason Martinez <jason.martinez@company.com>"
}
```

### 2. `DRF00908` | Score: 135 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00908",
  "risk_score": 135,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-1",
  "control_type": "Access_Control",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2025-11-16 04:58:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Disable performed on Control-1 (Access_Control) at 04:58 AM on 2025-11-16 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 135 \u2192 classified as CRITICAL DRIFT. Business impact: Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "compliance_violations": [
    "NIST IA-2",
    "CIS 5.3",
    "PCI-DSS 12.10"
  ],
  "business_impact": "Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "remediation": "1. Re-enable access controls immediately. 2. Audit all access logs during the gap. 3. Force re-authentication for all admin sessions. 4. Review privileged access grants.",
  "operator": "Anjali Muller <anjali.muller@company.com>",
  "approver": "Larry Quinn <larry.quinn@company.com>"
}
```

### 3. `DRF00849` | Score: 125 | HIGH_DRIFT

```json
{
  "drift_id": "DRF00849",
  "risk_score": 125,
  "classification": "HIGH_DRIFT",
  "control_name": "Control-13",
  "control_type": "Data_Protection",
  "severity": "High",
  "change_type": "Disable",
  "change_date": "2025-12-24 03:53:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Disable performed on Control-13 (Data_Protection) at 03:53 AM on 2025-12-24 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 125 \u2192 classified as HIGH DRIFT. Business impact: Sensitive records (PII, financial, health) unprotected. GDPR 32 and PCI-DSS 3.4 non-compliance. Breach notification obligations activated.",
  "compliance_violations": [
    "GDPR 32",
    "PCI-DSS 3.4",
    "ISO 27001 A.12"
  ],
  "business_impact": "Sensitive records (PII, financial, health) unprotected. GDPR 32 and PCI-DSS 3.4 non-compliance. Breach notification obligations activated.",
  "remediation": "1. Re-enable data protection controls. 2. Identify affected data assets and assess exposure. 3. Notify DPO; assess GDPR breach notification obligation.",
  "operator": "Sofia Wagner <sofia.wagner@company.com>",
  "approver": "George Huang <george.huang@company.com>"
}
```

### 4. `DRF00877` | Score: 125 | HIGH_DRIFT

```json
{
  "drift_id": "DRF00877",
  "risk_score": 125,
  "classification": "HIGH_DRIFT",
  "control_name": "Control-50",
  "control_type": "Network_Segmentation",
  "severity": "High",
  "change_type": "Disable",
  "change_date": "2025-12-29 06:24:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Disable performed on Control-50 (Network_Segmentation) at 06:24 AM on 2025-12-29 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 125 \u2192 classified as HIGH DRIFT. Business impact: Flat network topology allows lateral movement post-breach. NIST SC-7 boundary protection violated; blast radius of any breach expands.",
  "compliance_violations": [
    "NIST SC-7",
    "CIS 12.1",
    "NIST CM-3"
  ],
  "business_impact": "Flat network topology allows lateral movement post-breach. NIST SC-7 boundary protection violated; blast radius of any breach expands.",
  "remediation": "1. Re-enable segmentation controls immediately. 2. Check for lateral movement indicators. 3. Rebuild firewall zone policies if needed.",
  "operator": "Jacob Becker <jacob.becker@company.com>",
  "approver": "Shruti Taylor <shruti.taylor@company.com>"
}
```

### 5. `DRF00919` | Score: 125 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00919",
  "risk_score": 125,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-12",
  "control_type": "Vulnerability",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2026-01-04 18:06:00",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-12 (Vulnerability) at 06:06 PM on 2026-01-04, reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 125 \u2192 classified as CRITICAL DRIFT. Business impact: Known CVEs remain unpatched; exploit likelihood increases daily. NIST RA-5 vulnerability scanning control violated.",
  "compliance_violations": [
    "NIST RA-5",
    "CIS 7.1",
    "CIS Benchmark v8"
  ],
  "business_impact": "Known CVEs remain unpatched; exploit likelihood increases daily. NIST RA-5 vulnerability scanning control violated.",
  "remediation": "1. Re-enable vulnerability scanning immediately. 2. Schedule emergency scan for affected systems. 3. Review unscanned assets for known CVEs.",
  "operator": "Meera Menon <meera.menon@company.com>",
  "approver": "William Miller <william.miller@company.com>"
}
```

### 6. `DRF00816` | Score: 120 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00816",
  "risk_score": 120,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-95",
  "control_type": "Cloud_Security",
  "severity": "Critical",
  "change_type": "Modify",
  "change_date": "2025-05-02 04:00:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Modify performed on Control-95 (Cloud_Security) at 04:00 AM on 2025-05-02 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 120 \u2192 classified as CRITICAL DRIFT. Business impact: Cloud workloads exposed to misconfiguration exploitation. NIST CM-2 baseline deviation; potential public exposure of internal APIs.",
  "compliance_violations": [
    "CIS 2.1",
    "NIST CM-2",
    "NIST CM-3"
  ],
  "business_impact": "Cloud workloads exposed to misconfiguration exploitation. NIST CM-2 baseline deviation; potential public exposure of internal APIs.",
  "remediation": "1. Revert cloud policy to IaC-defined baseline. 2. Trigger Terraform plan to detect drift. 3. Validate policy enforcement across all regions.",
  "operator": "Nikhil Schmidt <nikhil.schmidt@company.com>",
  "approver": "Raja Clark <raja.clark@company.com>"
}
```

### 7. `DRF00583` | Score: 120 | HIGH_DRIFT

```json
{
  "drift_id": "DRF00583",
  "risk_score": 120,
  "classification": "HIGH_DRIFT",
  "control_name": "Control-98",
  "control_type": "Logging",
  "severity": "High",
  "change_type": "Remove",
  "change_date": "2025-09-23 02:33:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Remove performed on Control-98 (Logging) at 02:33 AM on 2025-09-23 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 120 \u2192 classified as HIGH DRIFT. Business impact: Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "compliance_violations": [
    "NIST AU-2",
    "CIS 2.1",
    "NIST SI-12",
    "CIS Benchmark v8"
  ],
  "business_impact": "Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "remediation": "1. Restore logging agent/service. 2. Perform forensic analysis of the gap period. 3. Notify Compliance team.",
  "operator": "Varun Yang <varun.yang@company.com>",
  "approver": "Edward Guo <edward.guo@company.com>"
}
```

### 8. `DRF00726` | Score: 120 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00726",
  "risk_score": 120,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-76",
  "control_type": "DLP",
  "severity": "Critical",
  "change_type": "Remove",
  "change_date": "2025-11-28 19:28:00",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Remove performed on Control-76 (DLP) at 07:28 PM on 2025-11-28, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 120 \u2192 classified as CRITICAL DRIFT. Business impact: Sensitive data (PII/IP) may be exfiltrated via email, USB, or cloud sync. GDPR 25 data-minimisation principle violated.",
  "compliance_violations": [
    "GDPR 25",
    "ISO 27001 A.13",
    "PCI-DSS 12.10"
  ],
  "business_impact": "Sensitive data (PII/IP) may be exfiltrated via email, USB, or cloud sync. GDPR 25 data-minimisation principle violated.",
  "remediation": "1. Restore DLP baseline policy. 2. Scan for data exfiltration during gap window. 3. Notify Compliance.",
  "operator": "Amara Sanchez <amara.sanchez@company.com>",
  "approver": "Stephen Rao <stephen.rao@company.com>"
}
```

### 9. `DRF00828` | Score: 115 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00828",
  "risk_score": 115,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-18",
  "control_type": "Logging",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2025-12-20 18:49:00",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-18 (Logging) at 06:49 PM on 2025-12-20, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 115 \u2192 classified as CRITICAL DRIFT. Business impact: Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "compliance_violations": [
    "NIST AU-2",
    "CIS 2.1",
    "NIST SI-12"
  ],
  "business_impact": "Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "remediation": "1. Immediately re-enable logging via console/API. 2. Audit all API calls during the blind window. 3. Escalate to CISO and SIEM team. 4. File change ticket with root-cause explanation.",
  "operator": "Christopher Lopez <christopher.lopez@company.com>",
  "approver": "Yuki Xu <yuki.xu@company.com>"
}
```

### 10. `DRF00236` | Score: 115 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00236",
  "risk_score": 115,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-16",
  "control_type": "Access_Control",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2026-02-26 10:54:40",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-16 (Access_Control) at 10:54 AM on 2026-02-26, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 115 \u2192 classified as CRITICAL DRIFT. Business impact: Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "compliance_violations": [
    "NIST IA-2",
    "CIS 5.3"
  ],
  "business_impact": "Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "remediation": "1. Re-enable access controls immediately. 2. Audit all access logs during the gap. 3. Force re-authentication for all admin sessions. 4. Review privileged access grants.",
  "operator": "Kenneth Thomas <kenneth.thomas@company.com>",
  "approver": "Nadia Lee <nadia.lee@company.com>"
}
```

### 11. `DRF00146` | Score: 115 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00146",
  "risk_score": 115,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-5",
  "control_type": "Encryption",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2026-03-01 10:54:40",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-5 (Encryption) at 10:54 AM on 2026-03-01, reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 115 \u2192 classified as CRITICAL DRIFT. Business impact: Data at rest or in transit is exposed to interception and exfiltration. PCI-DSS 3.4 and GDPR 32 violations may trigger regulatory fines.",
  "compliance_violations": [
    "GDPR 32",
    "NIST SC-7",
    "PCI-DSS 3.4"
  ],
  "business_impact": "Data at rest or in transit is exposed to interception and exfiltration. PCI-DSS 3.4 and GDPR 32 violations may trigger regulatory fines.",
  "remediation": "1. Re-enable encryption immediately. 2. Initiate key rotation per KMS policy. 3. Scan affected data stores for exposure. 4. Notify Data Protection Officer (DPO).",
  "operator": "Richard Anderson <richard.anderson@company.com>",
  "approver": "David Ramirez <david.ramirez@company.com>"
}
```

### 12. `DRF00317` | Score: 115 | HIGH_DRIFT

```json
{
  "drift_id": "DRF00317",
  "risk_score": 115,
  "classification": "HIGH_DRIFT",
  "control_name": "Control-74",
  "control_type": "Vulnerability",
  "severity": "High",
  "change_type": "Disable",
  "change_date": "2026-03-24 10:54:40",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-74 (Vulnerability) at 10:54 AM on 2026-03-24, reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 115 \u2192 classified as HIGH DRIFT. Business impact: Known CVEs remain unpatched; exploit likelihood increases daily. NIST RA-5 vulnerability scanning control violated.",
  "compliance_violations": [
    "NIST RA-5",
    "CIS 7.1"
  ],
  "business_impact": "Known CVEs remain unpatched; exploit likelihood increases daily. NIST RA-5 vulnerability scanning control violated.",
  "remediation": "1. Re-enable vulnerability scanning immediately. 2. Schedule emergency scan for affected systems. 3. Review unscanned assets for known CVEs.",
  "operator": "Edward Thompson <edward.thompson@company.com>",
  "approver": "Amitabh Harris <amitabh.harris@company.com>"
}
```

### 13. `DRF00715` | Score: 110 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00715",
  "risk_score": 110,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-33",
  "control_type": "Network_Segmentation",
  "severity": "Critical",
  "change_type": "Modify",
  "change_date": "2025-04-29 04:17:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Modify performed on Control-33 (Network_Segmentation) at 04:17 AM on 2025-04-29 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 110 \u2192 classified as CRITICAL DRIFT. Business impact: Flat network topology allows lateral movement post-breach. NIST SC-7 boundary protection violated; blast radius of any breach expands.",
  "compliance_violations": [
    "NIST SC-7",
    "CIS 12.1"
  ],
  "business_impact": "Flat network topology allows lateral movement post-breach. NIST SC-7 boundary protection violated; blast radius of any breach expands.",
  "remediation": "1. Revert network segmentation rules. 2. Verify VLAN/subnet isolation is intact. 3. Review east-west traffic logs for anomalies.",
  "operator": "Fatima Yang <fatima.yang@company.com>",
  "approver": "Richard Burke <richard.burke@company.com>"
}
```

### 14. `DRF00557` | Score: 110 | HIGH_DRIFT

```json
{
  "drift_id": "DRF00557",
  "risk_score": 110,
  "classification": "HIGH_DRIFT",
  "control_name": "Control-13",
  "control_type": "Access_Control",
  "severity": "High",
  "change_type": "Remove",
  "change_date": "2025-08-26 06:11:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Remove performed on Control-13 (Access_Control) at 06:11 AM on 2025-08-26 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 110 \u2192 classified as HIGH DRIFT. Business impact: Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "compliance_violations": [
    "NIST IA-2",
    "CIS 5.3"
  ],
  "business_impact": "Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "remediation": "1. Restore access policy from IAM baseline. 2. Review who accessed resources during the gap. 3. Apply least-privilege remediation.",
  "operator": "Nicholas Perez <nicholas.perez@company.com>",
  "approver": "Vikram Rao <vikram.rao@company.com>"
}
```

### 15. `DRF00501` | Score: 110 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00501",
  "risk_score": 110,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-11",
  "control_type": "DLP",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2025-12-05 15:03:00",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-11 (DLP) at 03:03 PM on 2025-12-05, reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Under Review. Risk score: 110 \u2192 classified as CRITICAL DRIFT. Business impact: Sensitive data (PII/IP) may be exfiltrated via email, USB, or cloud sync. GDPR 25 data-minimisation principle violated.",
  "compliance_violations": [
    "GDPR 25",
    "ISO 27001 A.13",
    "ISO 27001 A.12"
  ],
  "business_impact": "Sensitive data (PII/IP) may be exfiltrated via email, USB, or cloud sync. GDPR 25 data-minimisation principle violated.",
  "remediation": "1. Re-enable DLP policy immediately. 2. Scan outbound email/file transfers during gap. 3. Review USB and cloud-sync activity. 4. Notify Data Governance team.",
  "operator": "William Robinson <william.robinson@company.com>",
  "approver": "Isha Sharma <isha.sharma@company.com>"
}
```

### 16. `DRF00520` | Score: 110 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00520",
  "risk_score": 110,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-37",
  "control_type": "Logging",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2025-12-12 09:53:00",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-37 (Logging) at 09:53 AM on 2025-12-12, reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Under Review. Risk score: 110 \u2192 classified as CRITICAL DRIFT. Business impact: Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "compliance_violations": [
    "NIST AU-2",
    "CIS 2.1",
    "NIST SI-12",
    "ISO 27001 A.12"
  ],
  "business_impact": "Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "remediation": "1. Immediately re-enable logging via console/API. 2. Audit all API calls during the blind window. 3. Escalate to CISO and SIEM team. 4. File change ticket with root-cause explanation.",
  "operator": "Amara Pillai <amara.pillai@company.com>",
  "approver": "Brian Meyer <brian.meyer@company.com>"
}
```

### 17. `DRF00672` | Score: 110 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00672",
  "risk_score": 110,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-52",
  "control_type": "Access_Control",
  "severity": "Critical",
  "change_type": "Rollback",
  "change_date": "2025-12-13 06:56:00",
  "is_off_hours": true,
  "is_regression": true,
  "plain_english": "Rollback performed on Control-52 (Access_Control) at 06:56 AM on 2025-12-13 during off-hours (00:00\u201307:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 110 \u2192 classified as CRITICAL DRIFT. Business impact: Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "compliance_violations": [
    "NIST IA-2",
    "CIS 5.3",
    "GDPR Article 32"
  ],
  "business_impact": "Unauthorised users may gain privileged access. Lateral movement risk increases. Violates NIST IA-2 least-privilege mandate.",
  "remediation": "1. Restore access control baseline. 2. Review access logs for anomalous activity. 3. Enforce re-authentication.",
  "operator": "Leila Sullivan <leila.sullivan@company.com>",
  "approver": "Mark O'Brien <mark.o'brien@company.com>"
}
```

### 18. `DRF00914` | Score: 110 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00914",
  "risk_score": 110,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-27",
  "control_type": "Endpoint",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2025-12-25 22:59:00",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-27 (Endpoint) at 10:59 PM on 2025-12-25, reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Under Review. Risk score: 110 \u2192 classified as CRITICAL DRIFT. Business impact: Endpoints lack threat detection/prevention. Malware propagation risk is elevated. CIS 8.1 anti-malware controls violated.",
  "compliance_violations": [
    "NIST SI-3",
    "CIS 8.1",
    "GDPR Article 32"
  ],
  "business_impact": "Endpoints lack threat detection/prevention. Malware propagation risk is elevated. CIS 8.1 anti-malware controls violated.",
  "remediation": "1. Re-enable endpoint protection agent. 2. Run full AV/EDR scan on affected endpoints. 3. Review endpoint logs for indicators of compromise.",
  "operator": "Jeffrey Hwang <jeffrey.hwang@company.com>",
  "approver": "Robert Sullivan <robert.sullivan@company.com>"
}
```

### 19. `DRF00222` | Score: 110 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00222",
  "risk_score": 110,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-57",
  "control_type": "DLP",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2026-01-23 10:54:40",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-57 (DLP) at 10:54 AM on 2026-01-23, reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Under Review. Risk score: 110 \u2192 classified as CRITICAL DRIFT. Business impact: Sensitive data (PII/IP) may be exfiltrated via email, USB, or cloud sync. GDPR 25 data-minimisation principle violated.",
  "compliance_violations": [
    "GDPR 25",
    "ISO 27001 A.13"
  ],
  "business_impact": "Sensitive data (PII/IP) may be exfiltrated via email, USB, or cloud sync. GDPR 25 data-minimisation principle violated.",
  "remediation": "1. Re-enable DLP policy immediately. 2. Scan outbound email/file transfers during gap. 3. Review USB and cloud-sync activity. 4. Notify Data Governance team.",
  "operator": "Eric Bhat <eric.bhat@company.com>",
  "approver": "Pooja Mishra <pooja.mishra@company.com>"
}
```

### 20. `DRF00028` | Score: 110 | CRITICAL_DRIFT

```json
{
  "drift_id": "DRF00028",
  "risk_score": 110,
  "classification": "CRITICAL_DRIFT",
  "control_name": "Control-69",
  "control_type": "Logging",
  "severity": "Critical",
  "change_type": "Disable",
  "change_date": "2026-02-22 10:54:40",
  "is_off_hours": false,
  "is_regression": true,
  "plain_english": "Disable performed on Control-69 (Logging) at 10:54 AM on 2026-02-22, reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Under Review. Risk score: 110 \u2192 classified as CRITICAL DRIFT. Business impact: Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "compliance_violations": [
    "NIST AU-2",
    "CIS 2.1",
    "NIST SI-12"
  ],
  "business_impact": "Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possible under GDPR Article 32 and NIST AU-2 violation.",
  "remediation": "1. Immediately re-enable logging via console/API. 2. Audit all API calls during the blind window. 3. Escalate to CISO and SIEM team. 4. File change ticket with root-cause explanation.",
  "operator": "Rajesh Young <rajesh.young@company.com>",
  "approver": "Yuki Jackson <yuki.jackson@company.com>"
}
```

---

## 4. Compliance Impact Matrix

| Standard | Violations | Affected Controls | Risk Level |
|----------|-----------|-------------------|------------|
| CIS 2.1 | 83 | Control-1, Control-10, Control-13, Control-14 +54 more | CRITICAL |
| GDPR 32 | 55 | Control-1, Control-11, Control-12, Control-13 +37 more | CRITICAL |
| PCI-DSS 3.4 | 55 | Control-1, Control-11, Control-12, Control-13 +37 more | CRITICAL |
| NIST SC-7 | 50 | Control-1, Control-11, Control-12, Control-13 +35 more | HIGH |
| NIST CM-2 | 43 | Control-10, Control-13, Control-16, Control-21 +32 more | HIGH |
| NIST AU-2 | 40 | Control-1, Control-14, Control-17, Control-18 +30 more | HIGH |
| NIST SI-12 | 40 | Control-1, Control-14, Control-17, Control-18 +30 more | HIGH |
| GDPR Article 32 | 39 | Control-10, Control-16, Control-17, Control-18 +27 more | HIGH |
| NIST RA-5 | 38 | Control-1, Control-12, Control-13, Control-16 +24 more | HIGH |
| CIS 7.1 | 38 | Control-1, Control-12, Control-13, Control-16 +24 more | HIGH |
| GDPR 25 | 33 | Control-10, Control-11, Control-15, Control-2 +23 more | HIGH |
| ISO 27001 A.13 | 33 | Control-10, Control-11, Control-15, Control-2 +23 more | HIGH |
| CIS 3.1 | 32 | Control-10, Control-11, Control-17, Control-18 +24 more | HIGH |
| NIST AC-4 | 32 | Control-10, Control-11, Control-17, Control-18 +24 more | HIGH |
| NIST CM-3 | 31 | Control-1, Control-11, Control-19, Control-21 +25 more | HIGH |
| NIST IA-2 | 31 | Control-1, Control-12, Control-13, Control-16 +22 more | HIGH |
| CIS 5.3 | 31 | Control-1, Control-12, Control-13, Control-16 +22 more | HIGH |
| NIST SI-3 | 30 | Control-15, Control-18, Control-26, Control-27 +23 more | HIGH |
| CIS 8.1 | 30 | Control-15, Control-18, Control-26, Control-27 +23 more | HIGH |
| CIS 12.1 | 29 | Control-11, Control-12, Control-14, Control-15 +22 more | HIGH |
| ISO 27001 A.12 | 29 | Control-11, Control-13, Control-14, Control-16 +21 more | HIGH |
| CIS Benchmark v8 | 29 | Control-12, Control-23, Control-27, Control-3 +22 more | HIGH |
| PCI-DSS 12.10 | 26 | Control-1, Control-13, Control-15, Control-18 +19 more | HIGH |

---

## 5. Operator Risk Ranking

| Rank | Email | Total Risk Score | Event Count |
|------|-------|-----------------|-------------|
| 1 | jacob.becker@company.com | 210 | 2 |
| 2 | meera.menon@company.com | 185 | 2 |
| 3 | rohan.gonzalez@company.com | 180 | 2 |
| 4 | anthony.choi@company.com | 155 | 2 |
| 5 | elena.rodriguez@company.com | 155 | 2 |
| 6 | eric.reddy@company.com | 155 | 2 |
| 7 | andrew.kumar@company.com | 155 | 2 |
| 8 | arjun.harris@company.com | 145 | 2 |
| 9 | michael.rao@company.com | 145 | 2 |
| 10 | sanjana.sanchez@company.com | 145 | 3 |

---

## 6. Remediation Priority Queue

| Priority | Drift ID | Control | Type | Score | Est. Fix Time | First Step |
|----------|----------|---------|------|-------|--------------|------------|
| P1 | DRF00691 | Control-33 | Endpoint | 135 | 15–30 min | 1. |
| P2 | DRF00908 | Control-1 | Access_Control | 135 | 15–30 min | 1. |
| P3 | DRF00849 | Control-13 | Data_Protection | 125 | 30–60 min | 1. |
| P4 | DRF00877 | Control-50 | Network_Segmentation | 125 | 30–60 min | 1. |
| P5 | DRF00919 | Control-12 | Vulnerability | 125 | 15–30 min | 1. |
| P6 | DRF00816 | Control-95 | Cloud_Security | 120 | 15–30 min | 1. |
| P7 | DRF00583 | Control-98 | Logging | 120 | 30–60 min | 1. |
| P8 | DRF00726 | Control-76 | DLP | 120 | 15–30 min | 1. |
| P9 | DRF00828 | Control-18 | Logging | 115 | 15–30 min | 1. |
| P10 | DRF00236 | Control-16 | Access_Control | 115 | 15–30 min | 1. |
| P11 | DRF00146 | Control-5 | Encryption | 115 | 15–30 min | 1. |
| P12 | DRF00317 | Control-74 | Vulnerability | 115 | 30–60 min | 1. |
| P13 | DRF00715 | Control-33 | Network_Segmentation | 110 | 15–30 min | 1. |
| P14 | DRF00557 | Control-13 | Access_Control | 110 | 30–60 min | 1. |
| P15 | DRF00501 | Control-11 | DLP | 110 | 15–30 min | 1. |
| P16 | DRF00520 | Control-37 | Logging | 110 | 15–30 min | 1. |
| P17 | DRF00672 | Control-52 | Access_Control | 110 | 15–30 min | 1. |
| P18 | DRF00914 | Control-27 | Endpoint | 110 | 15–30 min | 1. |
| P19 | DRF00222 | Control-57 | DLP | 110 | 15–30 min | 1. |
| P20 | DRF00028 | Control-69 | Logging | 110 | 15–30 min | 1. |

---

## 7. Gaps & Limitations

- **No real-time baseline pull**: Static baselines only. Live API integration would improve accuracy.
- **Binary value comparison**: The regex-based regression detection handles simple enabled/disabled patterns. Numerical config values (timeouts, port lists) require additional parsers.
- **No change-intent NLP**: Change reason strings are not semantically analysed. An NLP model could further reduce false positives by 10–15%.
- **Ground truth dependency**: Without `config_drift_labels.csv`, precision/recall cannot be computed automatically.
- **Operator context**: Operators are flagged by aggregate risk score, not intent. Legitimate senior admins making emergency fixes may appear in high-risk rankings.
