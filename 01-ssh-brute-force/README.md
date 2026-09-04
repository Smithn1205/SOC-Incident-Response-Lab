# Incident 01: SSH Brute Force Lab

## Overview

For this lab I created an Ubuntu VM in Azure and sent its SSH authentication logs to Microsoft Sentinel.

I then generated a short burst of failed SSH attempts from my own system. The test created **8 invalid-user attempts in about 2.6 seconds** against `soc-linux-01`.

I used KQL to find and group the failed attempts, then checked whether a successful SSH login happened after them.

**Result:** 8 failed SSH attempts were detected and no successful authentication was found afterward.

This was a controlled lab test, not a real production incident.

## Lab Setup

| Component | Setup |
|---|---|
| SIEM | Microsoft Sentinel |
| Log Analytics workspace | `law-sentinel-lab` |
| Linux host | `soc-linux-01` |
| OS | Ubuntu Server 24.04.4 LTS |
| SSH service | OpenSSH |
| Log collection | Azure Monitor Agent |
| Data Collection Rule | `dcr-soc-linux-syslog` |
| Table | `Syslog` |
| Query language | KQL |

SSH access to the VM was limited to my own public IP through an Azure Network Security Group. Password authentication was disabled and I used an SSH key to connect.

## Log Flow

```text
Ubuntu SSH logs
      ↓
Syslog
      ↓
Azure Monitor Agent
      ↓
Data Collection Rule
      ↓
Log Analytics
      ↓
Microsoft Sentinel
```

Before creating the failed logins, I sent a simple Syslog test message and confirmed that it reached the `Syslog` table. This helped me confirm that log collection was working first.

## Detection

If the same source makes several invalid SSH login attempts in a short time, I want to see it clearly in Sentinel.

For this lab I used **5 failed attempts** as the threshold.

## KQL Query

The query is saved in [`detection.kql`](./detection.kql).

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

The query filters SSH events, pulls out the source IP and username, counts the failed attempts, and shows the first and last event time.

## Results

| Field | Result |
|---|---|
| Host | `soc-linux-01` |
| Username | `wronguser` |
| Failed attempts | **8** |
| First event | `2026-09-04 18:17:51.325 UTC` |
| Last event | `2026-09-04 18:17:53.959 UTC` |
| Duration | About **2.6 seconds** |

All 8 attempts came from the same test source and targeted the same invalid username.

## Investigation

### 1. Check the raw SSH events

I searched the `Syslog` table for SSH events from `soc-linux-01`.

The failed events looked like this:

```text
Invalid user wronguser from <source-ip> port <source-port>
```

I found 8 matching events close together.

### 2. Group the failed attempts

I grouped the events by source IP, username, and host. This showed one source making 8 attempts against `wronguser` on `soc-linux-01`.

### 3. Check for a successful login

After that, I searched for SSH events beginning with `Accepted` after the failed attempts started.

The query returned no results, so I found no successful SSH authentication after the failed attempts.

## Timeline

| Time (UTC) | Event |
|---|---|
| 18:17:51.325 | First invalid-user attempt |
| 18:17:51.718 | Second attempt |
| 18:17:52.113 | Third attempt |
| 18:17:52.517 | Fourth attempt |
| 18:17:52.869 | Fifth attempt |
| 18:17:53.239 | Sixth attempt |
| 18:17:53.611 | Seventh attempt |
| 18:17:53.959 | Eighth attempt |
| After the attempts | No successful SSH login found |

## MITRE ATT&CK

**T1110 - Brute Force**

I mapped this lab to T1110 because it involved repeated authentication attempts against SSH.

I did not use the Password Guessing sub-technique because password authentication was disabled and this test did not involve guessing passwords.

## Response

If I saw the same activity in a real environment, I would:

- check whether the source IP is known or expected
- see which usernames were targeted
- check for any successful login after the failures
- see whether the same source tried other hosts
- review the host for suspicious activity after the login attempts
- keep key-based SSH authentication where possible
- restrict SSH access to trusted sources
- consider blocking or rate limiting repeated failures
- adjust the detection threshold based on normal activity

## Conclusion

I collected the SSH logs, found the failed attempts, wrote a KQL query, built a timeline, and checked whether the attempts led to a successful login.

The final result was **8 failed SSH attempts from one source with no successful authentication afterward**.

## What I Learned

- Confirm log collection before starting the test.
- Filter the SSH messages carefully to avoid counting the same connection more than once.
- Check the full firewall rule set, not just one rule.
- Always check whether failed login attempts were followed by a successful login.
