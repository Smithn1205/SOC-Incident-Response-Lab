# Incident 02: Defender Trojan Detection and Quarantine

## Summary

| Field | Finding |
|---|---|
| Environment | TryHackMe SAL1 simulated SOC environment |
| Alert source | Microsoft Defender Antivirus / Windows Defender Operational telemetry |
| Alert rule | Suspicious Trojan Quarantined by Defender |
| Observed time | 26 October 2026, 16:33:57.729 (lab event timestamp; timezone not confirmed) |
| Host | `DESIGN-TRYHATME` |
| User context | `TRYHATME\\Armaan.Terry` |
| Threat name | `Trojan:Win32/Pacman` |
| Reported severity | Medium threat severity; alert rule shown as Low |
| Action | Quarantine |
| Action status | Success |
| Execution status | Suspended |
| Threat status | Concrete |
| Classification | **True positive (lab evidence)** |
| Escalation | **No immediate escalation after successful containment; validate endpoint telemetry and escalate if additional compromise evidence appears** |

## Alert Context

Microsoft Defender reported a Trojan detection and recorded a successful quarantine action. The event details identify the target file as:

```text
C:\Users\Armaan.Terry\Downloads\PacMan.exe
```

The event also reports the following process image:

```text
C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
```

The recorded remediation description states that the operation completed successfully. Execution status is reported as suspended.

## Evidence and Assessment

### Evidence observed

- Defender identified the threat as `Trojan:Win32/Pacman`.
- The affected file path points to `PacMan.exe` in the user's Downloads directory.
- Defender's recorded action was `Quarantine`, with status `Success`.
- The event reports execution as suspended, which is consistent with Defender intervening in the activity.
- The alert details show a threat URL associated with Microsoft's threat information page.

### Classification rationale

**True positive** is the most defensible lab classification because the endpoint protection telemetry explicitly records a Trojan detection and a successful quarantine action. This classification applies to the simulated alert and does not establish that a real-world endpoint was compromised.

One field requires validation: the reported process image is Chrome, while the quarantined target is `PacMan.exe`. These may represent different roles in the detection record, but the available screenshot alone does not establish their relationship. Confirm the original event fields and related process-creation telemetry before concluding that Chrome executed the file.

## Investigation Steps

1. Reviewed the alert rule, threat name, host, timestamp, severity, and Defender data source.
2. Checked the target file path and the process image recorded in the event.
3. Verified the reported remediation action and status: quarantine succeeded.
4. Reviewed the execution and threat status fields.
5. Identified the process-image/target-file discrepancy as a follow-up validation item.
6. Based the disposition on the available endpoint-protection evidence rather than assuming that quarantine alone proves the entire host is clean.

## Escalation Decision

**No immediate escalation is required in this lab case if the successful quarantine is confirmed and no related suspicious activity is found.** Escalate to incident response if subsequent review identifies execution before quarantine, persistence, additional malware detections, suspicious network activity, credential access, or other signs of compromise.

## Recommended Remediation and Validation

- Confirm the file remains quarantined and has not been restored.
- Review Defender's full alert and action details to verify the target file, process image, and action result.
- Search nearby process-creation events for `PacMan.exe`, Chrome's parent/child process relationships, and any script or command-line activity around the alert time.
- Review other Defender detections and endpoint events for the same host and user.
- Check for suspicious outbound connections or persistence indicators around the same time.
- Run an updated Defender scan according to the lab's response workflow.
- Preserve the alert and relevant event records for the case notes.

These are recommended validation steps; the screenshots establish the recorded quarantine action, not that every follow-up check was completed.

## Indicators and Key Fields

| Indicator / field | Value |
|---|---|
| Threat name | `Trojan:Win32/Pacman` |
| Target file | `C:\Users\Armaan.Terry\Downloads\PacMan.exe` |
| Reported process image | `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe` |
| Host | `DESIGN-TRYHATME` |
| Defender action | `Quarantine` |
| Action status | `Success` |
| Execution status | `Suspended` |

## Conclusion

The lab alert is classified as a **true positive** because Defender explicitly reported a Trojan detection and a successful quarantine action. The appropriate disposition is to record the containment result, verify the process-to-file relationship, and check for related activity before treating the endpoint as fully clean. The case is based on simulated lab telemetry and should not be presented as a real production incident.
