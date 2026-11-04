# Hunt Tuning Notes: Baseline Noise & False-Positive Elimination

> **Author:** Yogesh Thakur · **Phase:** Phase 2 (Test harness and synthetic data)  
> **Key Interview Takeaway:** Demonstrating how realistic baseline noise forces detection engineering discipline and query tuning.

---

## 1. Case Study 1: HB-ID-001 (Password Spray vs. User Typos)

### The Challenge
When testing against our synthetic baseline containing 50 benign enterprise users, we observed that employees occasionally enter the wrong password, generating `ResultType == "50126"` events in `SigninLogs`.

### Naive Detection Failure
A simple query looking for:
```kql
SigninLogs
| where ResultType == "50126"
| summarize FailedAttempts = count() by IPAddress
| where FailedAttempts >= 5
```
**Failed the baseline test with multiple false positives.** When a single user forgot their password and retried 5 times in the morning from their corporate IP, the query flagged the employee as a password spray attacker.

### The Tuning Solution
Password spraying is inherently **broad across accounts**, whereas brute force is **deep on a single account**. We tuned the query to:
1. Use `dcount(UserPrincipalName)` instead of `count()`.
2. Bucket by `bin(TimeGenerated, 30m)` to detect time-compressed bursts.
3. Require `FailedUsers >= 10`.

```kql
| summarize
    FailedUsers = dcount(UserPrincipalName),
    Attempts = count(),
    SampleUsers = make_set(UserPrincipalName, 20)
    by IPAddress, bin(TimeGenerated, window)
| where FailedUsers >= minUsers
```

### Result
- **Attack Dataset (`scenario-01`):** 40 distinct users attacked by `203.0.113.50` -> **Fires 1 high-confidence lead**.
- **Benign Baseline Dataset:** 10 individual user typos scattered across 6 hours -> **0 false positive rows returned**.

---

## 2. Case Study 2: HB-CL-001 (Mass Cloud File Download vs. Standard Workflows)

### The Challenge
In Microsoft 365 / SharePoint environments, employees regularly download documents, presentations, and spreadsheets as part of their day-to-day job duties.

### Naive Detection Failure
A query that simply alerted on high raw download activity:
```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| summarize count() by AccountId
| where count_ >= 10
```
Triggered numerous false positives during morning hours as employees opened project files and presentation decks.

### The Tuning Solution
1. Introduce a tumbling time window `bin(Timestamp, 1h)`.
2. Calibrate `minDownloads = 50` files per hour.
3. Bundle `make_set(tostring(ActivityObjects), 10)` so SOC analysts can immediately triage document sensitivity without running secondary queries.

### Result
- **Attack Dataset (`scenario-03`):** 65 files downloaded in 15 minutes by compromised admin account -> **Fires alert**.
- **Benign Baseline Dataset:** Standard employees downloading 1-3 files -> **0 false positives**.

