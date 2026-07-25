# Investigating Windows Event ID 1102 Security Log Was Cleared

## Context

Clearing the Windows Security log removes records that may be needed to determine what happened on the system. If the action cannot immediately be connected to authorized administration, maintenance, or testing, it is serious enough to treat as possible evidence destruction until a legitimate reason is confirmed.

Event ID 1102 does not automatically prove that an attack occurred. However, it should trigger an investigation into who cleared the log, why it was cleared, and what activity occurred beforehand. Microsoft classifies Event ID 1102 as having medium-to-high importance for security monitoring.

There are legitimate reasons for an authorized administrator to manually clear the Security log.

One example is when the Security log has reached its configured maximum size while its retention policy is set to **Do not overwrite events**. In this situation, Windows may be unable to continue recording new security events. An authorized administrator may preserve or archive the existing log and then clear it so Windows can resume recording new events.

Another legitimate reason is to reset an authorized staging, sandbox, or validation environment used to test a new security policy, audit configuration, logging structure, or system change before it is introduced into production. Clearing the previous events can provide a clean baseline for evaluating only the activity generated under the new configuration.

A personal learning or training lab is a separate use case. In that environment, the log may be cleared to isolate newly generated events, reproduce specific activity, or make the resulting evidence easier to analyze. This should not be confused with a production-relevant staging environment used to validate changes before deployment.

A technically defensible manual-clearing scenario is one in which:

1. The log is full or causing an operational problem.
2. Existing events are preserved, exported, or archived when they may still be needed.
3. An authorized administrator performs the clearing.
4. The reason, authorization, and time of the action are documented.

Depending on the configured retention policy, Windows may overwrite older events or automatically archive a full log. Manual clearing is therefore not always necessary and should not be treated as a routine action without a documented reason.

Potentially malicious reasons for clearing the Security log include:

+ Hiding evidence of an attempted or successful data exfiltration.
+ Hiding malware execution or files dropped onto the system.
+ Removing records that could help a security analyst reconstruct earlier activity.
+ Delaying an investigation by forcing the analyst to search for evidence through other logs and data sources.

This investigation was performed directly on a standalone Windows 11 Home endpoint using Windows Event Viewer and the logging functions built into Windows. The system was not connected to Active Directory, and no SIEM was used. The investigation therefore focuses on evidence available directly from a non-domain-joined Windows endpoint.

I attempted to enable command-line recording for process-creation events, but the **Process Command Line** field remained empty. Microsoft lists the **Include command line in process creation events** policy as supported on Windows Pro, Enterprise, Education, and IoT Enterprise editions, but not Windows Home. Windows 11 Home was therefore treated as the likely limitation in this investigation.

Event ID 4688 could still show that `wevtutil.exe` was launched by `powershell.exe`, but it could not display the complete PowerShell command and its arguments. The process relationship was therefore recorded, while the exact command line could not be confirmed from Event ID 4688 alone.

After the Security log was cleared, only two events were present in the log: Event ID 4688 and Event ID 1102. Event ID 4688 recorded the creation of `wevtutil.exe` with `powershell.exe` as its parent process immediately before Event ID 1102 recorded that the Security log had been cleared.

The objectives of this investigation are to:

+ Extract relevant information from Event IDs 1102 and 4688.
+ Correlate the process-creation event with the clearing of the Security log.
+ Determine whether the activity was performed by an authorized person or may represent unauthorized activity.
+ Identify the evidence and limitations available when investigating the activity directly through Windows Event Viewer.

## Proof Of Concept

**Step 1.** Open PowerShell as administrator.

**Step 2.** Run the following command to clear the Windows Security log:

`wevtutil cl Security`

![event-id-1102-powershell.png](./Images/event-id-1102-powershell.png)

Fig 1. PowerShell command used to clear the Windows Security log.

**Step 3.** Open Windows Event Viewer and navigate to `Windows Logs` > `Security`.

**Step 4.** Select Event ID 1102 and review the information available in the General tab and XML view.

![event-id-1102-generic.png](./Images/event-id-1102-generic.png)

Fig 2. Event ID 1102 — General tab.

![event-id-1102-xml-system-v2.png](./Images/event-id-1102-xml-system-v2.png)

Fig 3. Event ID 1102 — Details tab, XML view: System section.

![event-id-1102-xml-event-data-v2.png](./Images/event-id-1102-xml-event-data-v2.png)

Fig 4. Event ID 1102 — Details tab, XML view: UserData section.

**Step 5.** Review the only other event remaining in the Security log, Event ID 4688, to identify process-creation activity that may be correlated with Event ID 1102.

![event-id-1102-correlate-4688-generic.png](./Images/event-id-1102-correlate-4688-generic.png)

Fig 5. Event ID 4688 — General tab.

![event-id-1102-correlate-4688-xml-system.png](./Images/event-id-1102-correlate-4688-xml-system.png)

Fig 6. Event ID 4688 — Details tab, XML view: System section.

![event-id-1102-correlate-4688-xml-event-data.png](./Images/event-id-1102-correlate-4688-xml-event-data.png)

Fig 7. Event ID 4688 — Details tab, XML view: EventData section.

**Step 6.** Extract the relevant fields from Event IDs 1102 and 4688 for correlation and analysis.

## Extracted Details

### Event ID 1102 Details

| Field Name | Why it matters | Data |
| --- | --- | --- |
| `EventID` | Confirms which event record is being reviewed. | 1102 |
| `TimeCreated SystemTime` | Shows exactly when the Security log was cleared. | `2026-04-29T09:31:01.2611834Z` (4/29/2026 4:31:01 PM) |
| `SubjectUserSid` | Identifies the Windows account linked to the action. | `S-1-5-21-...-1001` |
| `SubjectUserName` | Shows the name of the account that cleared the log. | Redacted |
| `SubjectLogonId` | Identifies the login session used to clear the log. | `0x2f78a` |
| `ClientProcessId` | Identifies the process that requested the log clearing. | `22188` |

### Event ID 4688 Details

| Field Name | Why it matters | Data |
| --- | --- | --- |
| `EventID` | Confirms which event record is being reviewed. | 4688 |
| `TimeCreated SystemTime` | Shows when the process was created so it can be compared with Event ID 1102. | `2026-04-29T09:31:01.2413832Z` (4/29/2026 4:31:01 PM) |
| `SubjectUserSid` | Identifies the Windows account linked to the process creation. | `S-1-5-21-...-1001` |
| `SubjectUserName` | Shows the name of the account that created the process. | Redacted |
| `SubjectLogonId` | Shows whether the process was created during the same login session as Event ID 1102. | `0x2f78a` |
| `NewProcessId` | Can be compared with the ClientProcessId from Event ID 1102 to connect the two events. | `0x56ac` |
| `NewProcessName` | Shows which program was started. | `C:\Windows\System32\wevtutil.exe` |
| `ParentProcessName` | Shows which program launched the new process. | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | Would show the command and arguments used. It is also important when the field is empty. | Empty |
| `TokenElevationType` | Shows whether the process was running with elevated access. | `%%1937` |

## Analysis

### Inspecting The Event ID and Time

After the log was cleared by me, there were only two event on the security logs, 1102 and 4688. Event ID 1102 is about security log was cleared. Event ID 4688 is about a new process created. These two events were created at the same so the evidence support that they are correlated.

### Inspecting The

### Correlated With The Event ID 4688

This event ID 4688 referred to a process creation process. In this event, it was shown that the security clearing command was performed on PowerShell before the data got wiped.

## Conclusion

This log clearing was performed by me, the authorized admin of my computer for this lab as explained in the Analysis section. This is a legitimate action. There is no trace of attackers. This is the placeholder.

## Recommendation

+ Set up an alert for Event ID 1102 so the action can be reviewed as soon as it occurs.
+ Follow the principle of least privilege. Do not give administrative permissions to users who do not need them for their responsibilities.
+ Confirm the action with the designated point of contact or authorized administrator, even when it was performed by an approved account. An authorized account can still be compromised or misused, especially when the activity occurs outside expected working or maintenance hours.

## MITRE ATT&CK Reference

---
