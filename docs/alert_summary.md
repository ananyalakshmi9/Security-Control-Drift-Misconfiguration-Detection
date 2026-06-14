# 🚨 Security Alert Digest — SOC Priority Queue

> **Generated:** 2026-06-14 18:46:24  
> **Total Alerts:** 1000  
> **Dataset:** 1,000 drift events · Apr 2025 – Apr 2026

---

## Alert Priority Summary

| Priority | Level | Count | SLA | Escalation |
|----------|-------|-------|-----|------------|
| **P1** | CRITICAL — Page Now | **7** | 15 min | CISO, SOC Lead, DPO, On-Call Engineer... |
| **P2** | CRITICAL — 15 min | **71** | 60 min | CISO, SOC Lead... |
| **P3** | HIGH — Off-hours + Regression | **66** | 60 min | SOC Lead, Control Owner... |
| **P4** | HIGH — Active Drift | **23** | 60 min | SOC Lead, Control Owner... |
| **P5** | HIGH — In-Progress | **80** | 240 min | Control Owner... |
| **P6** | MEDIUM — Schedule Review | **466** | 1440 min | Control Owner, Risk Team... |
| **P8** | BENIGN — Log Only | **287** | N/A min | Auto-logged... |

---

## P1 Alerts — CRITICAL — Page Now (7 events)

### `ALT-691` — Control-33 (Endpoint)

| Field | Value |
|-------|-------|
| Risk Score | **135** |
| Severity | Critical |
| Change | Disable |
| Status | Drifted |
| Date | 2025-08-25 01:02:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Vikram Moore |
| SLA | 15 minutes |
| Compliance | NIST SI-3, CIS 8.1, PCI-DSS 12.10 |

**Required Action:** Isolate or disable the affected system immediately. Page CISO.

**Summary:** Disable performed on Control-33 (Endpoint) at 01:02 AM on 2025-08-25 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Drifted. Risk score: 135 → classified as CRIT...

**Remediation:** 1. Re-enable endpoint protection agent. 2. Run full AV/EDR scan on affected endpoints. 3. Review endpoint logs for indicators of compromise....

---

### `ALT-908` — Control-1 (Access_Control)

| Field | Value |
|-------|-------|
| Risk Score | **135** |
| Severity | Critical |
| Change | Disable |
| Status | Drifted |
| Date | 2025-11-16 04:58:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Anjali Muller |
| SLA | 15 minutes |
| Compliance | NIST IA-2, CIS 5.3, PCI-DSS 12.10 |

**Required Action:** Isolate or disable the affected system immediately. Page CISO.

**Summary:** Disable performed on Control-1 (Access_Control) at 04:58 AM on 2025-11-16 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 135 → classified ...

**Remediation:** 1. Re-enable access controls immediately. 2. Audit all access logs during the gap. 3. Force re-authentication for all admin sessions. 4. Review privileged access grants....

---

### `ALT-816` — Control-95 (Cloud_Security)

| Field | Value |
|-------|-------|
| Risk Score | **120** |
| Severity | Critical |
| Change | Modify |
| Status | Drifted |
| Date | 2025-05-02 04:00:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Nikhil Schmidt |
| SLA | 15 minutes |
| Compliance | CIS 2.1, NIST CM-2, NIST CM-3 |

**Required Action:** Isolate or disable the affected system immediately. Page CISO.

**Summary:** Modify performed on Control-95 (Cloud_Security) at 04:00 AM on 2025-05-02 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 120 → classified ...

**Remediation:** 1. Revert cloud policy to IaC-defined baseline. 2. Trigger Terraform plan to detect drift. 3. Validate policy enforcement across all regions....

---

### `ALT-715` — Control-33 (Network_Segmentation)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Modify |
| Status | Drifted |
| Date | 2025-04-29 04:17:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Fatima Yang |
| SLA | 15 minutes |
| Compliance | NIST SC-7, CIS 12.1 |

**Required Action:** Isolate or disable the affected system immediately. Page CISO.

**Summary:** Modify performed on Control-33 (Network_Segmentation) at 04:17 AM on 2025-04-29 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 110 → class...

**Remediation:** 1. Revert network segmentation rules. 2. Verify VLAN/subnet isolation is intact. 3. Review east-west traffic logs for anomalies....

---

### `ALT-672` — Control-52 (Access_Control)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Rollback |
| Status | Drifted |
| Date | 2025-12-13 06:56:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Leila Sullivan |
| SLA | 15 minutes |
| Compliance | NIST IA-2, CIS 5.3, GDPR Article 32 |

**Required Action:** Isolate or disable the affected system immediately. Page CISO.

**Summary:** Rollback performed on Control-52 (Access_Control) at 06:56 AM on 2025-12-13 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 110 → classifie...

**Remediation:** 1. Restore access control baseline. 2. Review access logs for anomalous activity. 3. Enforce re-authentication....

---

### `ALT-512` — Control-74 (Endpoint)

| Field | Value |
|-------|-------|
| Risk Score | **95** |
| Severity | Critical |
| Change | Update |
| Status | Drifted |
| Date | 2025-10-31 02:57:00 |
| Off-Hours | True |
| Regression | False |
| Operator | Brian Ghosh |
| SLA | 15 minutes |
| Compliance | NIST SI-3, CIS 8.1, GDPR Article 32 |

**Required Action:** Isolate or disable the affected system immediately. Page CISO.

**Summary:** Update performed on Control-74 (Endpoint) at 02:57 AM on 2025-10-31 during off-hours (00:00–07:00, suspicious window). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 95 → classified as CRITICAL DRIFT. Business impact: Endpoints lack threat detection/prev...

**Remediation:** 1. Restore endpoint security baseline. 2. Force agent update on all managed endpoints. 3. Validate EDR telemetry....

---

### `ALT-660` — Control-63 (Endpoint)

| Field | Value |
|-------|-------|
| Risk Score | **85** |
| Severity | Critical |
| Change | Update |
| Status | Drifted |
| Date | 2025-04-21 02:49:00 |
| Off-Hours | True |
| Regression | False |
| Operator | Sofia Sun |
| SLA | 15 minutes |
| Compliance | NIST SI-3, CIS 8.1 |

**Required Action:** Isolate or disable the affected system immediately. Page CISO.

**Summary:** Update performed on Control-63 (Endpoint) at 02:49 AM on 2025-04-21 during off-hours (00:00–07:00, suspicious window). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 85 → classified as CRITICAL DRIFT. Business impact: Endpoints lack threat detection/preventio...

**Remediation:** 1. Restore endpoint security baseline. 2. Force agent update on all managed endpoints. 3. Validate EDR telemetry....

---

## P2 Alerts — CRITICAL — 15 min (71 events)

### `ALT-919` — Control-12 (Vulnerability)

| Field | Value |
|-------|-------|
| Risk Score | **125** |
| Severity | Critical |
| Change | Disable |
| Status | Drifted |
| Date | 2026-01-04 18:06:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Meera Menon |
| SLA | 60 minutes |
| Compliance | NIST RA-5, CIS 7.1, CIS Benchmark v8 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-12 (Vulnerability) at 06:06 PM on 2026-01-04, reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 125 → classified as CRITICAL DRIFT. Business impact: Known CVEs rem...

**Remediation:** 1. Re-enable vulnerability scanning immediately. 2. Schedule emergency scan for affected systems. 3. Review unscanned assets for known CVEs....

---

### `ALT-726` — Control-76 (DLP)

| Field | Value |
|-------|-------|
| Risk Score | **120** |
| Severity | Critical |
| Change | Remove |
| Status | Drifted |
| Date | 2025-11-28 19:28:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Amara Sanchez |
| SLA | 60 minutes |
| Compliance | GDPR 25, ISO 27001 A.13, PCI-DSS 12.10 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Remove performed on Control-76 (DLP) at 07:28 PM on 2025-11-28, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 120 → classified as CRITICAL DRIFT. Business impact: Sensitive data (PII/IP...

**Remediation:** 1. Restore DLP baseline policy. 2. Scan for data exfiltration during gap window. 3. Notify Compliance....

---

### `ALT-828` — Control-18 (Logging)

| Field | Value |
|-------|-------|
| Risk Score | **115** |
| Severity | Critical |
| Change | Disable |
| Status | Drifted |
| Date | 2025-12-20 18:49:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Christopher Lopez |
| SLA | 60 minutes |
| Compliance | NIST AU-2, CIS 2.1, NIST SI-12 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-18 (Logging) at 06:49 PM on 2025-12-20, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 115 → classified as CRITICAL DRIFT. Business impact: Loss of audit tra...

**Remediation:** 1. Immediately re-enable logging via console/API. 2. Audit all API calls during the blind window. 3. Escalate to CISO and SIEM team. 4. File change ticket with root-cause explanation....

---

### `ALT-236` — Control-16 (Access_Control)

| Field | Value |
|-------|-------|
| Risk Score | **115** |
| Severity | Critical |
| Change | Disable |
| Status | Drifted |
| Date | 2026-02-26 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Kenneth Thomas |
| SLA | 60 minutes |
| Compliance | NIST IA-2, CIS 5.3 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-16 (Access_Control) at 10:54 AM on 2026-02-26, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 115 → classified as CRITICAL DRIFT. Business impact: Unauthoris...

**Remediation:** 1. Re-enable access controls immediately. 2. Audit all access logs during the gap. 3. Force re-authentication for all admin sessions. 4. Review privileged access grants....

---

### `ALT-146` — Control-5 (Encryption)

| Field | Value |
|-------|-------|
| Risk Score | **115** |
| Severity | Critical |
| Change | Disable |
| Status | Drifted |
| Date | 2026-03-01 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Richard Anderson |
| SLA | 60 minutes |
| Compliance | GDPR 32, NIST SC-7, PCI-DSS 3.4 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-5 (Encryption) at 10:54 AM on 2026-03-01, reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 115 → classified as CRITICAL DRIFT. Business impact: Data at rest or in t...

**Remediation:** 1. Re-enable encryption immediately. 2. Initiate key rotation per KMS policy. 3. Scan affected data stores for exposure. 4. Notify Data Protection Officer (DPO)....

---

### `ALT-501` — Control-11 (DLP)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Disable |
| Status | Under_Review |
| Date | 2025-12-05 15:03:00 |
| Off-Hours | False |
| Regression | True |
| Operator | William Robinson |
| SLA | 60 minutes |
| Compliance | GDPR 25, ISO 27001 A.13, ISO 27001 A.12 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-11 (DLP) at 03:03 PM on 2025-12-05, reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Under Review. Risk score: 110 → classified as CRITICAL DRIFT. Business impact: Sensitive data (PII/I...

**Remediation:** 1. Re-enable DLP policy immediately. 2. Scan outbound email/file transfers during gap. 3. Review USB and cloud-sync activity. 4. Notify Data Governance team....

---

### `ALT-520` — Control-37 (Logging)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Disable |
| Status | Under_Review |
| Date | 2025-12-12 09:53:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Amara Pillai |
| SLA | 60 minutes |
| Compliance | NIST AU-2, CIS 2.1, NIST SI-12, ISO 27001 A.12 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-37 (Logging) at 09:53 AM on 2025-12-12, reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Under Review. Risk score: 110 → classified as CRITICAL DRIFT. Business impact: Loss of audit t...

**Remediation:** 1. Immediately re-enable logging via console/API. 2. Audit all API calls during the blind window. 3. Escalate to CISO and SIEM team. 4. File change ticket with root-cause explanation....

---

### `ALT-914` — Control-27 (Endpoint)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Disable |
| Status | Under_Review |
| Date | 2025-12-25 22:59:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Jeffrey Hwang |
| SLA | 60 minutes |
| Compliance | NIST SI-3, CIS 8.1, GDPR Article 32 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-27 (Endpoint) at 10:59 PM on 2025-12-25, reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Under Review. Risk score: 110 → classified as CRITICAL DRIFT. Business impact: Endpoints lack t...

**Remediation:** 1. Re-enable endpoint protection agent. 2. Run full AV/EDR scan on affected endpoints. 3. Review endpoint logs for indicators of compromise....

---

### `ALT-222` — Control-57 (DLP)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Disable |
| Status | Under_Review |
| Date | 2026-01-23 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Eric Bhat |
| SLA | 60 minutes |
| Compliance | GDPR 25, ISO 27001 A.13 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-57 (DLP) at 10:54 AM on 2026-01-23, reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Under Review. Risk score: 110 → classified as CRITICAL DRIFT. Business impact: Sensitive data (PII/I...

**Remediation:** 1. Re-enable DLP policy immediately. 2. Scan outbound email/file transfers during gap. 3. Review USB and cloud-sync activity. 4. Notify Data Governance team....

---

### `ALT-28` — Control-69 (Logging)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Disable |
| Status | Under_Review |
| Date | 2026-02-22 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Rajesh Young |
| SLA | 60 minutes |
| Compliance | NIST AU-2, CIS 2.1, NIST SI-12 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-69 (Logging) at 10:54 AM on 2026-02-22, reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Under Review. Risk score: 110 → classified as CRITICAL DRIFT. Business impact: Loss of audit t...

**Remediation:** 1. Immediately re-enable logging via console/API. 2. Audit all API calls during the blind window. 3. Escalate to CISO and SIEM team. 4. File change ticket with root-cause explanation....

---

### `ALT-131` — Control-77 (DLP)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Disable |
| Status | Under_Review |
| Date | 2026-02-22 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Amitabh Davis |
| SLA | 60 minutes |
| Compliance | GDPR 25, ISO 27001 A.13 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-77 (DLP) at 10:54 AM on 2026-02-22, reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Under Review. Risk score: 110 → classified as CRITICAL DRIFT. Business impact: Sensitive data (PII...

**Remediation:** 1. Re-enable DLP policy immediately. 2. Scan outbound email/file transfers during gap. 3. Review USB and cloud-sync activity. 4. Notify Data Governance team....

---

### `ALT-168` — Control-72 (Firewall)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | Critical |
| Change | Modify |
| Status | Drifted |
| Date | 2026-03-27 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Neha Ramirez |
| SLA | 60 minutes |
| Compliance | CIS 3.1, NIST AC-4 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Modify performed on Control-72 (Firewall) at 10:54 AM on 2026-03-27, reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 110 → classified as CRITICAL DRIFT. Business impact: Network perimeter weak...

**Remediation:** 1. Revert to baseline allowed-port list. 2. Block any newly opened ports immediately. 3. Run traffic analysis to detect exploitation. 4. Update firewall change management log....

---

### `ALT-842` — Control-82 (Logging)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | Critical |
| Change | Disable |
| Status | Drifted |
| Date | 2025-07-15 18:08:00 |
| Off-Hours | False |
| Regression | False |
| Operator | Raja O'Brien |
| SLA | 60 minutes |
| Compliance | NIST AU-2, CIS 2.1, NIST SI-12, ISO 27001 A.12 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Disable performed on Control-82 (Logging) at 06:08 PM on 2025-07-15. Change reason stated: 'Emergency Fix'. Current remediation status: Drifted. Risk score: 105 → classified as CRITICAL DRIFT. Business impact: Loss of audit trail. Any breach during this window is undetectable. Regulatory fines possi...

**Remediation:** 1. Immediately re-enable logging via console/API. 2. Audit all API calls during the blind window. 3. Escalate to CISO and SIEM team. 4. File change ticket with root-cause explanation....

---

### `ALT-701` — Control-30 (Vulnerability)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | Critical |
| Change | Remove |
| Status | Under_Review |
| Date | 2025-08-26 13:24:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Elena Reilly |
| SLA | 60 minutes |
| Compliance | NIST RA-5, CIS 7.1, CIS Benchmark v8 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Remove performed on Control-30 (Vulnerability) at 01:24 PM on 2025-08-26, reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Under Review. Risk score: 105 → classified as CRITICAL DRIFT. Business impact: Known CVEs...

**Remediation:** 1. Restore vulnerability management baseline. 2. Run immediate scan on affected scope. 3. Prioritise critical CVEs for patching....

---

### `ALT-588` — Control-3 (Network_Segmentation)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | Critical |
| Change | Modify |
| Status | Under_Review |
| Date | 2025-09-06 03:32:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Charles Patel |
| SLA | 60 minutes |
| Compliance | NIST SC-7, CIS 12.1, PCI-DSS 12.10 |

**Required Action:** Begin emergency remediation. Notify CISO within 15 minutes.

**Summary:** Modify performed on Control-3 (Network_Segmentation) at 03:32 AM on 2025-09-06 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Under Review. Risk score: 105 ...

**Remediation:** 1. Revert network segmentation rules. 2. Verify VLAN/subnet isolation is intact. 3. Review east-west traffic logs for anomalies....

---

## P3 Alerts — HIGH — Off-hours + Regression (66 events)

### `ALT-849` — Control-13 (Data_Protection)

| Field | Value |
|-------|-------|
| Risk Score | **125** |
| Severity | High |
| Change | Disable |
| Status | Drifted |
| Date | 2025-12-24 03:53:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Sofia Wagner |
| SLA | 60 minutes |
| Compliance | GDPR 32, PCI-DSS 3.4, ISO 27001 A.12 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Disable performed on Control-13 (Data_Protection) at 03:53 AM on 2025-12-24 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 125 → classifie...

**Remediation:** 1. Re-enable data protection controls. 2. Identify affected data assets and assess exposure. 3. Notify DPO; assess GDPR breach notification obligation....

---

### `ALT-877` — Control-50 (Network_Segmentation)

| Field | Value |
|-------|-------|
| Risk Score | **125** |
| Severity | High |
| Change | Disable |
| Status | Drifted |
| Date | 2025-12-29 06:24:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Jacob Becker |
| SLA | 60 minutes |
| Compliance | NIST SC-7, CIS 12.1, NIST CM-3 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Disable performed on Control-50 (Network_Segmentation) at 06:24 AM on 2025-12-29 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 125 → clas...

**Remediation:** 1. Re-enable segmentation controls immediately. 2. Check for lateral movement indicators. 3. Rebuild firewall zone policies if needed....

---

### `ALT-583` — Control-98 (Logging)

| Field | Value |
|-------|-------|
| Risk Score | **120** |
| Severity | High |
| Change | Remove |
| Status | Drifted |
| Date | 2025-09-23 02:33:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Varun Yang |
| SLA | 60 minutes |
| Compliance | NIST AU-2, CIS 2.1, NIST SI-12, CIS Benchmark v8 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Remove performed on Control-98 (Logging) at 02:33 AM on 2025-09-23 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 120 → classified as HIGH D...

**Remediation:** 1. Restore logging agent/service. 2. Perform forensic analysis of the gap period. 3. Notify Compliance team....

---

### `ALT-317` — Control-74 (Vulnerability)

| Field | Value |
|-------|-------|
| Risk Score | **115** |
| Severity | High |
| Change | Disable |
| Status | Drifted |
| Date | 2026-03-24 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Edward Thompson |
| SLA | 60 minutes |
| Compliance | NIST RA-5, CIS 7.1 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Disable performed on Control-74 (Vulnerability) at 10:54 AM on 2026-03-24, reverting a security control from enabled to disabled (regression). Change reason stated: 'Security Update'. Current remediation status: Drifted. Risk score: 115 → classified as HIGH DRIFT. Business impact: Known CVEs remain ...

**Remediation:** 1. Re-enable vulnerability scanning immediately. 2. Schedule emergency scan for affected systems. 3. Review unscanned assets for known CVEs....

---

### `ALT-557` — Control-13 (Access_Control)

| Field | Value |
|-------|-------|
| Risk Score | **110** |
| Severity | High |
| Change | Remove |
| Status | Drifted |
| Date | 2025-08-26 06:11:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Nicholas Perez |
| SLA | 60 minutes |
| Compliance | NIST IA-2, CIS 5.3 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Remove performed on Control-13 (Access_Control) at 06:11 AM on 2025-08-26 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 110 → classified as...

**Remediation:** 1. Restore access policy from IAM baseline. 2. Review who accessed resources during the gap. 3. Apply least-privilege remediation....

---

### `ALT-930` — Control-67 (Network_Segmentation)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | High |
| Change | Update |
| Status | Drifted |
| Date | 2025-07-14 06:35:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Rohan Gonzalez |
| SLA | 60 minutes |
| Compliance | NIST SC-7, CIS 12.1, CIS Benchmark v8 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Update performed on Control-67 (Network_Segmentation) at 06:35 AM on 2025-07-14 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Drifted. Risk score: 105 → classif...

**Remediation:** 1. Restore network segmentation baseline. 2. Validate micro-segmentation policies. 3. Review inter-VLAN routing tables....

---

### `ALT-731` — Control-67 (Cloud_Security)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | High |
| Change | Update |
| Status | Drifted |
| Date | 2025-08-08 00:24:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Leila Lopez |
| SLA | 60 minutes |
| Compliance | CIS 2.1, NIST CM-2, GDPR Article 32 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Update performed on Control-67 (Cloud_Security) at 12:24 AM on 2025-08-08 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 105 → classified as...

**Remediation:** 1. Restore cloud security baseline. 2. Run cloud posture scan (CSPM tool). 3. Review misconfigurations in all accounts....

---

### `ALT-591` — Control-10 (Firewall)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | Critical |
| Change | Remove |
| Status | Mitigated |
| Date | 2026-01-15 05:47:00 |
| Off-Hours | True |
| Regression | True |
| Operator | Paul Thomas |
| SLA | 60 minutes |
| Compliance | CIS 3.1, NIST AC-4, GDPR Article 32 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Remove performed on Control-10 (Firewall) at 05:47 AM on 2026-01-15 during off-hours (00:00–07:00, suspicious window), reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Mitigated. Risk score: 105 → classified as CRI...

**Remediation:** 1. Restore firewall to baseline configuration. 2. Review traffic logs for anomalies. 3. Validate threat-prevention policies....

---

### `ALT-76` — Control-62 (Vulnerability)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | High |
| Change | Disable |
| Status | Drifted |
| Date | 2026-03-26 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Larry Martinez |
| SLA | 60 minutes |
| Compliance | NIST RA-5, CIS 7.1 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Disable performed on Control-62 (Vulnerability) at 10:54 AM on 2026-03-26, reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 105 → classified as HIGH DRIFT. Business impact: Known CVEs remain ...

**Remediation:** 1. Re-enable vulnerability scanning immediately. 2. Schedule emergency scan for affected systems. 3. Review unscanned assets for known CVEs....

---

### `ALT-81` — Control-23 (Vulnerability)

| Field | Value |
|-------|-------|
| Risk Score | **105** |
| Severity | High |
| Change | Disable |
| Status | Drifted |
| Date | 2026-04-05 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Zainab Bhat |
| SLA | 60 minutes |
| Compliance | NIST RA-5, CIS 7.1 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Disable performed on Control-23 (Vulnerability) at 10:54 AM on 2026-04-05, reverting a security control from enabled to disabled (regression). Change reason stated: 'Emergency Fix'. Current remediation status: Drifted. Risk score: 105 → classified as HIGH DRIFT. Business impact: Known CVEs remain un...

**Remediation:** 1. Re-enable vulnerability scanning immediately. 2. Schedule emergency scan for affected systems. 3. Review unscanned assets for known CVEs....

---

### `ALT-595` — Control-25 (Data_Protection)

| Field | Value |
|-------|-------|
| Risk Score | **100** |
| Severity | High |
| Change | Modify |
| Status | Drifted |
| Date | 2025-08-25 18:36:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Fatima White |
| SLA | 60 minutes |
| Compliance | GDPR 32, PCI-DSS 3.4, PCI-DSS 12.10 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Modify performed on Control-25 (Data_Protection) at 06:36 PM on 2025-08-25, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 100 → classified as HIGH DRIFT. Business impact: Sensitive reco...

**Remediation:** 1. Restore data protection baseline. 2. Audit data handling during exposure window. 3. Review retention and access policies....

---

### `ALT-986` — Control-50 (Data_Protection)

| Field | Value |
|-------|-------|
| Risk Score | **100** |
| Severity | High |
| Change | Modify |
| Status | Drifted |
| Date | 2025-10-24 08:26:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Nicholas Miller |
| SLA | 60 minutes |
| Compliance | GDPR 32, PCI-DSS 3.4, CIS Benchmark v8 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Modify performed on Control-50 (Data_Protection) at 08:26 AM on 2025-10-24, reverting a security control from enabled to disabled (regression). Change reason stated: 'Performance Tuning'. Current remediation status: Drifted. Risk score: 100 → classified as HIGH DRIFT. Business impact: Sensitive reco...

**Remediation:** 1. Restore data protection baseline. 2. Audit data handling during exposure window. 3. Review retention and access policies....

---

### `ALT-829` — Control-22 (Firewall)

| Field | Value |
|-------|-------|
| Risk Score | **100** |
| Severity | High |
| Change | Modify |
| Status | Drifted |
| Date | 2025-12-18 13:26:00 |
| Off-Hours | False |
| Regression | True |
| Operator | Christopher Davis |
| SLA | 60 minutes |
| Compliance | CIS 3.1, NIST AC-4, NIST CM-3 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Modify performed on Control-22 (Firewall) at 01:26 PM on 2025-12-18, reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 100 → classified as HIGH DRIFT. Business impact: Network perimeter weaken...

**Remediation:** 1. Revert to baseline allowed-port list. 2. Block any newly opened ports immediately. 3. Run traffic analysis to detect exploitation. 4. Update firewall change management log....

---

### `ALT-461` — Control-36 (Firewall)

| Field | Value |
|-------|-------|
| Risk Score | **100** |
| Severity | High |
| Change | Modify |
| Status | Drifted |
| Date | 2026-02-09 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Diya Anderson |
| SLA | 60 minutes |
| Compliance | CIS 3.1, NIST AC-4 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Modify performed on Control-36 (Firewall) at 10:54 AM on 2026-02-09, reverting a security control from enabled to disabled (regression). Change reason stated: 'Policy Change'. Current remediation status: Drifted. Risk score: 100 → classified as HIGH DRIFT. Business impact: Network perimeter weakened...

**Remediation:** 1. Revert to baseline allowed-port list. 2. Block any newly opened ports immediately. 3. Run traffic analysis to detect exploitation. 4. Update firewall change management log....

---

### `ALT-150` — Control-7 (Access_Control)

| Field | Value |
|-------|-------|
| Risk Score | **100** |
| Severity | High |
| Change | Modify |
| Status | Drifted |
| Date | 2026-03-06 10:54:40 |
| Off-Hours | False |
| Regression | True |
| Operator | Daniel Gonzalez |
| SLA | 60 minutes |
| Compliance | NIST IA-2, CIS 5.3 |

**Required Action:** Assign remediation ticket. Resolve within 1 hour.

**Summary:** Modify performed on Control-7 (Access_Control) at 10:54 AM on 2026-03-06, reverting a security control from enabled to disabled (regression). Change reason stated: 'Troubleshooting'. Current remediation status: Drifted. Risk score: 100 → classified as HIGH DRIFT. Business impact: Unauthorised users ...

**Remediation:** 1. Restore access control baseline. 2. Review access logs for anomalous activity. 3. Enforce re-authentication....

---

## Top 10 Operators by Alert Volume

| Rank | Operator | P1-P4 Alerts |
|------|----------|--------------|
| 1 | Jacob Becker | **2** |
| 2 | Rohan Gonzalez | **2** |
| 3 | Vikram Moore | **1** |
| 4 | Anjali Muller | **1** |
| 5 | Nikhil Schmidt | **1** |
| 6 | Fatima Yang | **1** |
| 7 | Leila Sullivan | **1** |
| 8 | Brian Ghosh | **1** |
| 9 | Sofia Sun | **1** |
| 10 | Meera Menon | **1** |

---

## Compliance Impact Summary

| Standard | Affected Alerts |
|----------|-----------------|
| `CIS 2.1` | 83 |
| `GDPR 32` | 55 |
| `PCI-DSS 3.4` | 55 |
| `NIST SC-7` | 50 |
| `NIST CM-2` | 43 |
| `NIST AU-2` | 40 |
| `NIST SI-12` | 40 |
| `GDPR Article 32` | 39 |
| `NIST RA-5` | 38 |
| `CIS 7.1` | 38 |

---

*Alert digest auto-generated by alert_system.py  •  Societe Generale Enterprise Security*
