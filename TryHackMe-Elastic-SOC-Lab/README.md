# TryHackMe SOC Investigation Lab — Elastic SIEM

**[View TryHackMe public results summary →](https://tryhackme.com/soc-sim/public-summary/4f350a99b8ce4cf49de7b788d41df5e56d78d48d17d83be95ebef244c2cf5aec600a53452ed321199a5bfa0619a1237a)**

## Overview

Hands-on SOC alert-triage exercise using Elastic Stack (ELK), Kibana, Sysmon process events, and email telemetry. The objective was to investigate alerts, distinguish malicious activity from benign activity, correlate related events, and document classification and response recommendations.

## Tools and Data Sources

- **Elastic Stack / Kibana** — SIEM log exploration and event investigation
- **Sysmon** — Windows process-creation and file-creation telemetry
- **Email event logs** — suspicious sender, subject, content, and attachment review
- **TryHackMe** — simulated SOC investigation environment

## Investigation Workflow

1. Review the alert and supporting event fields.
2. Inspect process names, parent-child relationships, command lines, paths, and timestamps.
3. Review email sender, recipient, subject, content, and attachment indicators.
4. Correlate related alerts on the same host and across a timeline.
5. Classify each alert as a true positive or false positive.
6. Decide whether escalation is warranted and document evidence, indicators, and recommended remediation.

## Key Investigation: Potential Data Exfiltration

A sequence of events on host `win-3450` suggested possible collection of sensitive files and DNS-based exfiltration:

1. PowerShell created `PowerView.ps1` in the user's Downloads folder, a potential Active Directory reconnaissance tool.
2. PowerShell launched `net.exe` to map `\\FILESRV-01\SSF-FinancialRecords` as drive `Z:`.
3. PowerShell launched `Robocopy.exe` to copy files from the mapped drive into a local folder named `exfiltration`.
4. The mapped drive was disconnected.
5. Multiple `nslookup.exe` processes queried subdomains of `haz4rdw4re.io`. The subdomains contained encoded-looking strings, consistent with a possible DNS tunnelling or data-exfiltration technique.

**Assessment:** The combined sequence was substantially more suspicious than any one event in isolation. The events suggested possible unauthorized collection and attempted external transfer; the logs provided did not, by themselves, prove that the transfer succeeded.

## Other Alert Types Investigated

- Suspicious external emails and possible phishing or scam messages
- Suspicious Windows process parent-child relationships
- PowerShell script creation in a Downloads directory
- Network drive mapping and disconnection
- Potentially benign Windows processes, including `rdpclip.exe`, `taskhostw.exe`, `WUDFHost.exe`, `TrustedInstaller.exe`, and `svchost.exe`

## Lab-Reported Results

- **True-positive identification rate:** 100%
- **False-positive identification rate:** 75%
- **Alerts closed:** 35
- **Mean dwell time:** 17 minutes

These figures are the results reported by the lab dashboard.

## Skills Demonstrated

- SIEM investigation and log analysis in Kibana
- Windows endpoint investigation using Sysmon
- Email threat triage
- Process lineage and command-line analysis
- Timeline correlation across related alerts
- Recognition of possible reconnaissance, collection, and exfiltration activity
- True-positive / false-positive classification
- Escalation decisions and incident-report writing

## Important Notes

This was a simulated lab environment. Findings describe potential malicious behavior based on the supplied telemetry; they do not establish that an external transfer succeeded. Remediation actions are recommendations unless explicitly performed in the lab.

No real user data, credentials, or sensitive organizational files should be included in this repository.
