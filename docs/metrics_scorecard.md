#  Drift Detection – Success Metrics Scorecard

> **Generated:** 2026-06-14 21:01:06  
> **Ground Truth:** Rule-derived from event signals (313 anomalies, 687 benign)  
> **Dataset:** 1,000 drift events, Apr 2025 – Apr 2026

---

##  Metrics Summary

| # | Metric | Target | Result | Status |
|---|--------|--------|--------|--------|
| 1 | **Detection Rate (Recall)** | > 80% | **93.9%** |  **PASS** |
| 2 | **False Positive Rate** | < 15% | **5.4%** |  **PASS** |
| 3 | **Time Lag (Processing Speed)** | < 1 hour | **2.46ms for 1,000 events** |  **PASS** |
| 4 | **Explainability Coverage** | 100% (every alert has reason) | **100.0%** |  **PASS** |
| 5 | **Compliance Mapping Coverage** | Drifts → NIST/CIS/GDPR | **100.0%** |  **PASS** |

---

## Metric: Detection Rate (Recall)

**Result:** `93.9%` &nbsp;|&nbsp; **Target:** `> 80%` &nbsp;|&nbsp; ** PASS**

Caught 294 of 313 truly risky events. Missed 19.

### Confusion Matrix

| | Predicted Risky | Predicted Benign |
|--|----------------|------------------|
| **Actually Risky** | TP = 294  | FN = 19  |
| **Actually Benign** | FP = 37  | TN = 650  |

| Metric | Value |
|--------|-------|
| Precision | 88.8% |
| Recall (Detection Rate) | 93.9% |
| F1 Score | 91.3% |

---

## Metric: False Positive Rate

**Result:** `5.4%` &nbsp;|&nbsp; **Target:** `< 15%` &nbsp;|&nbsp; ** PASS**

Wrongly flagged 37 of 687 benign events.

---

## Metric: Time Lag (Processing Speed)

**Result:** `2.46ms for 1,000 events` &nbsp;|&nbsp; **Target:** `< 1 hour` &nbsp;|&nbsp; ** PASS**

Avg 2.46ms for 1,000 events (2.46µs/event). Scales to 24.6ms for 10K events. Target < 1 hour: FAR exceeded.

### Performance Breakdown

| Scenario | Time |
|----------|------|
| 1,000 events (dataset) | 2.46ms |
| Per event | 2.46µs |
| 10,000 events | 24.6ms |
| 100,000 events | 246ms |
| 1,000,000 events | ~2.5s |

---

## Metric: Explainability Coverage

**Result:** `100.0%` &nbsp;|&nbsp; **Target:** `100% (every alert has reason)` &nbsp;|&nbsp; ** PASS**

331/331 CRITICAL+HIGH alerts explained (plain-English: 331, compliance: 331, remediation: 331, operator: 331). Avg quality: 4.0/4 components.

---

## Metric: Compliance Mapping Coverage

**Result:** `100.0%` &nbsp;|&nbsp; **Target:** `Drifts → NIST/CIS/GDPR` &nbsp;|&nbsp; ** PASS**

331/331 alerts mapped to compliance standards. 331 alerts map to ≥2 standards. Frameworks covered: NIST, CIS, GDPR, PCI, ISO. 23 unique standards referenced.

### Compliance Standards Covered

| Framework | Alerts Mapped |
|-----------|---------------|
| NIST | 335 |
| CIS | 272 |
| GDPR | 127 |
| PCI | 81 |
| ISO | 62 |

**Top violated standards:**

| Standard | Violations |
|----------|------------|
| `CIS 2.1` | 83 |
| `GDPR 32` | 55 |
| `PCI-DSS 3.4` | 55 |
| `NIST SC-7` | 50 |
| `NIST CM-2` | 43 |
| `NIST AU-2` | 40 |
| `NIST SI-12` | 40 |
| `GDPR Article 32` | 39 |

---

##  False Positive Analysis

**37 false positives** — events our model flagged as risky but were benign.

**Patterns in false positives:**

| Pattern | Count |
|---------|-------|
| change_type = Modify | 11 |
| change_type = Disable | 10 |
| change_type = Remove | 8 |
| severity = Critical | 34 |
| severity = High | 3 |

> **Fix:** Add a whitelist for `Enable + Compliant` events; these are security improvements and should not be flagged.

---

## 🔍 False Negative Analysis (Missed Drifts)

**19 missed drifts** — risky events our model didn't catch.

> **Fix:** Lower `THRESHOLD_MEDIUM` from 30 to 25 to catch borderline cases.

---

## 🔧 Tuning Guide

| If this metric fails | Fix in drift_detector.py |
|---------------------|-------------------------|
| Detection Rate < 80% | Lower `THRESHOLD_HIGH` from 50 → 45 |
| FPR > 15% | Raise `THRESHOLD_CRITICAL` from 70 → 75 OR add Enable+Compliant whitelist |
| Explainability < 100% | Re-run `drift_detector.py` to regenerate `drift_explanations.json` |
| Compliance gaps | Add missing types to `COMPLIANCE_MAP` dict |
