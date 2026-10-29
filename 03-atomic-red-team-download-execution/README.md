# Incident 03: Suspicious Atomic Red Team Download and PowerShell Execution

## Summary

| Field | Finding |
|---|---|
| Environment | TryHackMe SAL1 simulated SOC investigation |
| Host | `Lin-005` |
| User context | `yani.zubair` |
| Activity | Repository download, permission change, and PowerShell script execution attempt |
| Classification | **True positive for the observed suspicious activity** |
| Escalation | **Yes — escalate for validation of authorization and follow-on activity** |
| Confirmed impact | Not established by the available events |

## Alert Context

The investigation identified a command sequence on Linux involving a download from GitHub, a permission change, and an attempt to run a PowerShell installer:

```bash
wget https://github.com/redcanaryco/atomic-red-team.git
chmod +x install-atomicredteam.ps1
pwsh install-atomicredteam.ps1
```

The recorded activity was associated with host `Lin-005` and user `yani.zubair`. The sequence suggests that files were downloaded, the installer was marked executable, and PowerShell was invoked to run it.

## What the Commands Mean

- `wget`: downloads content from a URL. The command shown references the Atomic Red Team GitHub repository.
- `chmod +x`: adds execute permission to the named file.
- `pwsh`: launches PowerShell, here with the installer script as the argument.
- `install-atomicredteam.ps1`: the script named in the execution attempt.

Atomic Red Team is a security testing project. Its presence can be consistent with authorized adversary-emulation testing, but the tool name alone does not prove the activity was approved or malicious.

## Investigation and Assessment

### Evidence observed

1. A `wget` command referenced the Atomic Red Team repository.
2. A `chmod +x` command referenced `install-atomicredteam.ps1`.
3. A `pwsh` command attempted to run the installer script.
4. The commands formed a coherent download-to-execution sequence.

### Classification rationale

**True positive for the detected behavior:** the telemetry describes the command sequence that triggered the alert. This is not, by itself, proof of malicious intent. Atomic Red Team can be used legitimately by security teams, so authorization and surrounding activity must be checked before labeling the operator's actions malicious.

The available evidence does not establish whether the installer completed successfully, whether tests were executed, or whether the host was compromised.

## Escalation Decision

**Escalate for investigation.** Confirm whether the activity was part of an approved security test. Review the full command lines, parent and child processes, script output, file creation, network connections, and subsequent activity on the host. If authorized testing is confirmed and no harmful behavior occurred, document the validation and close according to the SOC procedure. If authorization is absent or additional suspicious behavior is found, continue incident response.

## Recommended Investigation Steps

- Review the process-creation events around the download and script execution timestamps.
- Identify parent process, child process, working directory, and complete command-line arguments.
- Check whether the repository and installer were actually downloaded and whether the script ran to completion.
- Search for subsequent Atomic Red Team test executions and related process or network activity.
- Check whether the activity matches a documented test window or approved change.
- Preserve relevant events and command lines in the case record.

These are recommended follow-up steps; they should not be described as completed unless the corresponding logs confirm them.

## Key Indicators

| Indicator | Value |
|---|---|
| Host | `Lin-005` |
| User | `yani.zubair` |
| Download utility | `wget` |
| Permission utility | `chmod +x` |
| PowerShell executable | `pwsh` |
| Script | `install-atomicredteam.ps1` |
| Repository reference | `github.com/redcanaryco/atomic-red-team` |

<!-- Portfolio review: Add investigation of Atomic Red Team download and execution. -->

## Conclusion

The alert is a **true positive for suspicious download-and-execution behavior**, and escalation is appropriate until authorization and the outcome are validated. The evidence supports the observed command sequence, but it does not independently prove malicious intent or successful compromise. This report describes a simulated lab investigation, not a production incident.
