# SOC Incident Response Lab

This repo is where I keep my hands-on SOC and incident response labs. I am using these labs to practise the kind of work I would do as a SOC analyst: collect logs, search for suspicious activity, investigate what happened, build a timeline, and document the result.

Everything here is done in lab environments that I own or control. None of the cases are production incidents.

## Investigations

| # | Investigation | Platform | Status |
|---|---|---|---|
| 01 | SSH Brute Force Investigation | Microsoft Sentinel / Linux | Complete |
| 02 | Suspicious PowerShell Activity | Microsoft Sentinel / Defender XDR | Planned |
| 03 | Windows Authentication Anomaly | Microsoft Sentinel | Planned |
| 04 | Web Attack / WAF Investigation | Cloudflare | Planned |

## Skills I am practising

- Microsoft Sentinel and KQL
- Splunk and SPL
- Log analysis
- Alert triage
- Event correlation
- Timeline building
- MITRE ATT&CK mapping
- Linux and Windows security monitoring
- Detection queries
- Containment and remediation
- Incident documentation

## Repo structure

```text
SOC-Incident-Response-Lab/
├── README.md
└── 01-ssh-brute-force/
    ├── README.md
    ├── detection.kql
    └── evidence/
```

I want each lab to read like a small SOC case rather than just a folder of screenshots. I include what I set up, what I detected, how I investigated it, what I concluded, and what I would do next in a real environment.

## Author

Smith Nunes
