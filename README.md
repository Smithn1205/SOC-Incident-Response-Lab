# SOC Incident Response Lab

I built this repository to document hands-on SOC investigations using lab environments that I control. My goal is to practise the same workflow I would use as a SOC analyst: collect logs, identify suspicious activity, investigate what happened, build a timeline, map the activity to MITRE ATT&CK, and decide what action should be taken next.

All activity in this repository is simulated. No production systems or third-party environments are used.

## Investigations

| # | Incident | Platform | Status |
|---|---|---|---|
| 01 | SSH Brute-Force Detection and Investigation | Microsoft Sentinel / Linux | Complete |
| 02 | Suspicious PowerShell Activity | Microsoft Sentinel / Defender XDR | Planned |
| 03 | Windows Authentication Anomaly | Microsoft Sentinel | Planned |
| 04 | Web Attack / WAF Investigation | Cloudflare | Planned |

## What I am practising

- Microsoft Sentinel and KQL
- Splunk and SPL
- Log analysis and event correlation
- Alert triage and investigation
- Timeline reconstruction
- MITRE ATT&CK mapping
- Linux and Windows security monitoring
- Detection logic and tuning
- Containment and remediation thinking
- Writing clear incident notes

## Repository Structure

```text
SOC-Incident-Response-Lab/
├── README.md
└── 01-ssh-brute-force/
    ├── README.md
    ├── detection.kql
    └── evidence/
```

Each investigation is written as a small case file rather than a collection of screenshots. I include the environment, log source, detection logic, investigation steps, timeline, conclusion, and what I would improve next.

## Author

Smith Nunes — M.Sc. Computer Science (Cybersecurity), Berlin, Germany
