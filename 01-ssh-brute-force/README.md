# Incident 01 — SSH Brute-Force Detection & Investigation

## Status

In progress.

## Objective

Simulate repeated failed SSH authentication attempts against a Linux host in a controlled lab, ingest the resulting logs into Microsoft Sentinel, detect suspicious authentication activity with KQL, investigate the event sequence, and document analyst conclusions and remediation.

## Lab Environment

Fill this section in as the lab is built.

| Component | Value |
|---|---|
| SIEM | Microsoft Sentinel |
| Endpoint | Ubuntu Linux VM |
| Log source | TBD |
| Authentication service | OpenSSH |
| Detection language | KQL |

## Detection Hypothesis

A single source generating an unusually high number of failed SSH authentication attempts within a short period may indicate brute-force or password-guessing activity.

## Data Collection

Document:

- how the Ubuntu authentication logs are generated
- how logs are forwarded to Sentinel
- which Sentinel table receives the events
- the relevant fields used for investigation

## Detection Query

The final working KQL query will be stored in [`detection.kql`](./detection.kql).

Questions the query should answer:

- Which source generated the failed authentications?
- How many failures occurred?
- Over what time period?
- Which account(s) were targeted?
- Did a successful login follow the failed attempts?

## Alert Evidence

Add sanitized screenshots to the `evidence/` folder.

Recommended evidence:

1. Sentinel query showing failed SSH authentications
2. Aggregated failures by source
3. Timeline or correlated events
4. Evidence showing whether authentication eventually succeeded

Do not publish credentials, tokens, tenant/subscription identifiers, private hostnames, or other sensitive information.

## Investigation

Document the analyst workflow here as the incident is investigated.

### Initial Triage

TBD.

### Scope Analysis

TBD.

### Authentication Correlation

TBD.

### Analyst Assessment

TBD.

## Timeline

| Time | Event | Analyst Note |
|---|---|---|
| TBD | First failed authentication | TBD |
| TBD | Detection threshold exceeded | TBD |
| TBD | Last observed attempt | TBD |

## MITRE ATT&CK Mapping

**T1110 — Brute Force**

The final report should explain why the observed evidence supports this mapping rather than applying the technique label automatically.

## Containment & Remediation

Potential recommendations to evaluate after the investigation:

- review whether SSH must be publicly reachable
- enforce SSH key-based authentication where appropriate
- disable unnecessary password authentication
- restrict source networks or apply access controls
- implement rate limiting or automated blocking
- monitor for successful authentication following repeated failures
- review the targeted account for subsequent suspicious activity

## Lessons Learned

TBD after completing the investigation.

## Detection Improvements

TBD after testing the initial detection logic and identifying false-positive or coverage limitations.
