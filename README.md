# SOC Incident Response Lab

This repository documents hands-on SOC investigations and incident-response exercises completed in simulated lab environments. Each case focuses on evidence-based alert triage, event correlation, classification, escalation decisions, and practical remediation.

> **Lab disclaimer:** These are simulated exercises, not production incidents. Findings and response actions are described only to the extent supported by the available lab telemetry.

## Investigations

| # | Investigation | Platform | Outcome |
|---|---|---|---|
| 01 | [SSH Brute Force Investigation](./01-ssh-brute-force/) | Microsoft Sentinel / Linux | 8 failed SSH attempts detected; no subsequent successful login found |
| 02 | [Defender Trojan Detection and Quarantine](./02-defender-trojan-quarantine/) | Microsoft Defender / Windows event telemetry | Trojan detection recorded; quarantine succeeded |
| 03 | [Atomic Red Team Download and Execution](./03-atomic-red-team-download-execution/) | Linux / PowerShell / process telemetry | Download-to-execution sequence identified; authorization and outcome require validation |

## Skills Practised

- Alert triage and true-positive / false-positive classification
- SIEM investigation with KQL and Splunk SPL
- Windows endpoint, Linux, and process telemetry analysis
- Process lineage, command-line, file-path, and timestamp review
- Investigation of script execution and suspicious downloads
- Correlation of related events and timeline construction
- MITRE ATT&CK mapping where supported by evidence
- Escalation decisions, containment, remediation, and case documentation

## Investigation Approach

For each case, I document the alert context, relevant evidence, investigation steps, assessment rationale, affected entities, escalation decision, and recommended response. I distinguish confirmed observations from hypotheses and identify missing telemetry rather than treating an alert description alone as proof.

## Repository Structure

```text
SOC-Incident-Response-Lab/
├── README.md
├── 01-ssh-brute-force/
│   ├── README.md
│   ├── detection.kql
│   └── evidence/
├── 02-defender-trojan-quarantine/
│   └── README.md
└── 03-atomic-red-team-download-execution/
    └── README.md
```

## Author

Smith Nunes
