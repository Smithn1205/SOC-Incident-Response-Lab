# Incident 01: SSH Brute-Force Detection and Investigation

## Overview

For my first SOC investigation, I built an Ubuntu VM in Azure, sent its SSH authentication logs into Microsoft Sentinel, and generated a short burst of failed SSH attempts from a system I control.

The test produced **8 invalid-user authentication attempts in about 2.6 seconds** against `soc-linux-01`. My KQL query grouped the events by source, username, and host and triggered on the burst. I then checked whether any successful SSH login followed the failures.

**Result:** the activity was detected, but there was no successful authentication after the failed attempts.

**Classification:** Simulated true positive — unsuccessful SSH brute-force-style activity.

## Lab Setup

| Component | Configuration |
|---|---|
| SIEM | Microsoft Sentinel |
| Log Analytics workspace | `law-sentinel-lab` |
| Linux host | `soc-linux-01` |
| Operating system | Ubuntu Server 24.04.4 LTS |
| Authentication service | OpenSSH |
| Log collection | Azure Monitor Agent (AMA) |
| Data Collection Rule | `dcr-soc-linux-syslog` |
| Sentinel table | `Syslog` |
| Query language | KQL |

SSH was restricted at the Azure Network Security Group to my own public IP. Password authentication stayed disabled and I used SSH keys for administration.

## Log Flow

```text
Ubuntu SSH logs
      ↓
Syslog (auth / authpriv)
      ↓
Azure Monitor Agent
      ↓
Data Collection Rule
      ↓
Log Analytics
      ↓
Microsoft Sentinel
```

Before generating the failed logins, I sent a simple test marker through `authpriv` and confirmed it appeared in the Sentinel `Syslog` table. This gave me a quick way to confirm that the whole logging path was working before starting the investigation.

## Detection Idea

My detection idea was simple: if one source generates several invalid SSH authentication attempts against the same host in a short period, I want that activity to stand out for investigation.

For this lab I used a threshold of **5 failed attempts**. I treated that as a lab threshold, not a production recommendation. In a real environment I would tune it against normal login behaviour and false positives.

## KQL Detection

The working query is saved in [`detection.kql`](./detection.kql).

```kusto
Syslog
| where TimeGenerated > ago(30m)
| where Computer == "soc-linux-01"
| where ProcessName == "sshd"
| where SyslogMessage startswith "Invalid user"
| extend SourceIP = extract(@"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", 1, SyslogMessage)
| extend TargetUser = extract(@"Invalid user (\S+)", 1, SyslogMessage)
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, TargetUser, Computer
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

The query filters for SSH events, extracts the source IP and username from the raw Syslog message, counts the attempts, and records the first and last event time.

## What I Found

| Field | Result |
|---|---|
| Host | `soc-linux-01` |
| Username | `wronguser` |
| Failed attempts | **8** |
| First event | `2026-09-04 18:17:51.325 UTC` |
| Last event | `2026-09-04 18:17:53.959 UTC` |
| Duration | About **2.6 seconds** |

All eight failures came from the same test source and targeted the same invalid username.

## Investigation

### 1. Confirm the raw events

I first searched the `Syslog` table for SSH events from `soc-linux-01`. The relevant records looked like this:

```text
Invalid user wronguser from <source-ip> port <source-port>
```

There were eight matching events in rapid succession.

### 2. Group the failures

I used KQL to group the events by source IP, username, and host. This showed one source making eight attempts against `wronguser` on `soc-linux-01`.

### 3. Check for a successful login

After confirming the failures, I searched for SSH messages beginning with `Accepted` after the burst started.

The query returned no results, so I found no successful SSH authentication after the failed attempts.

## Timeline

| Time (UTC) | Event |
|---|---|
| 18:17:51.325 | First invalid-user SSH attempt |
| 18:17:51.718 | Second attempt |
| 18:17:52.113 | Third attempt |
| 18:17:52.517 | Fourth attempt |
| 18:17:52.869 | Fifth attempt — detection threshold reached |
| 18:17:53.239 | Sixth attempt |
| 18:17:53.611 | Seventh attempt |
| 18:17:53.959 | Eighth and final attempt |
| After the burst | No successful SSH authentication found |

## MITRE ATT&CK

**T1110 — Brute Force**

I mapped the activity to the high-level Brute Force technique because the lab was designed around repeated SSH authentication attempts. I did not use the Password Guessing sub-technique because password authentication was disabled and the test did not involve guessing passwords.

## What I Would Do in a Real SOC

If I saw the same pattern in a real environment, I would:

- check whether the source IP is known or expected,
- confirm which accounts were targeted,
- look for a successful login after the failures,
- check whether the same source targeted other systems,
- review the host for activity after the authentication attempts,
- keep SSH key-based authentication enabled where possible,
- restrict SSH access to trusted networks or source addresses,
- consider rate limiting or automated blocking for repeated failures,
- tune the alert threshold based on the environment's normal behaviour.

## Conclusion

This lab gave me a complete basic SOC workflow: I collected Linux authentication logs, found repeated SSH failures in Sentinel, wrote a KQL detection, built a short timeline, and checked whether the activity resulted in a successful login.

The final result was **8 failed SSH attempts from one source with no successful authentication afterward**.

## What I Learned

A few things stood out during the lab:

- I should verify the logging path before generating test activity. The Syslog marker made troubleshooting much easier.
- Raw SSH logs can generate more than one message for a single connection, so I filtered specifically for `Invalid user` to avoid double-counting related `Connection closed` events.
- Firewall rules need to be checked as a complete rule set. I found an older broad SSH allow rule during setup and removed it so only my own source IP could reach port 22.
- Counting failures is only the first part of the investigation. Checking whether a successful login followed the failures is what helped determine the actual outcome.
