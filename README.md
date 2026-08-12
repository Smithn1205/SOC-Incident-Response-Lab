# SOC Incident Response Lab

Hands-on cybersecurity portfolio focused on SOC detection, SIEM investigation, threat hunting, and incident response.

## Purpose

This repository documents simulated security incidents investigated in controlled lab environments. Each case is designed to demonstrate practical analyst skills such as log analysis, detection engineering, incident triage, timeline reconstruction, MITRE ATT&CK mapping, and remediation planning.

> **Note:** All incidents are simulated in lab environments. No production incidents or third-party systems are represented here.

## Planned Investigations

| # | Incident | Platform | Status |
|---|---|---|---|
| 01 | SSH Brute-Force Detection & Investigation | Microsoft Sentinel / Linux | In progress |
| 02 | Suspicious PowerShell Activity | Microsoft Sentinel / Defender XDR | Planned |
| 03 | Windows Authentication Anomaly | Microsoft Sentinel | Planned |
| 04 | Web Attack / WAF Investigation | Cloudflare | Planned |

## Skills Demonstrated

- Microsoft Sentinel and KQL
- Splunk and SPL
- Log analysis and event correlation
- Incident triage and investigation
- MITRE ATT&CK mapping
- Linux and Windows security monitoring
- Network and cloud security
- Detection logic and alert tuning
- Incident documentation and remediation

## Repository Structure

```text
SOC-Incident-Response-Lab/
├── README.md
├── 01-ssh-brute-force/
│   ├── README.md
│   ├── detection.kql
│   └── evidence/
├── 02-suspicious-powershell/
├── 03-windows-authentication-anomaly/
└── 04-cloudflare-waf-investigation/
```

## Investigation Methodology

Each case will document:

1. Incident summary
2. Lab environment and log sources
3. Detection hypothesis
4. Detection query
5. Alert evidence
6. Investigation steps
7. Event timeline
8. MITRE ATT&CK mapping
9. Containment and remediation recommendations
10. Lessons learned and detection improvements

## Author

Smith Nunes — M.Sc. Computer Science (Cybersecurity), Berlin, Germany
