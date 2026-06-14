# Security Control Drift – Remediation Playbook

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
