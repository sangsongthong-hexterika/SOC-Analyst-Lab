# Investigating Windows Event ID 1102 Security Log Was Cleared

## Context

Clearing the Windows Security log removes records that may be needed to understand what happened on the system. If the action was not part of authorized administration or testing, it may indicate that something serious happened and that the person responsible wanted to hide it from security professionals.

Event ID 1102 records when the Windows Security audit log is cleared. It does not automatically prove that an attack occurred, but it should receive medium-to-high attention and be investigated until the reason for the action is confirmed.

There are legitimate reasons for an authorized administrator to clear the Security log manually.

One example is when the Security log has reached its maximum configured size while the retention policy is set to ***Do not overwrite events***. Windows may stop recording new security events under this configuration. The existing records may be preserved or archived before an authorized administrator clears the log so that Windows can continue recording new events.

Another reason is to reset an authorized staging, sandbox, or validation environment before testing a new audit policy, logging configuration, security setting, or system change. Clearing the previous records provides a clean baseline for reviewing only the events created under the new configuration.

A personal learning or training lab is a separate use case. In that environment, the log may be cleared to isolate newly generated events and make them easier to review. This should not be confused with a production-related environment used to test changes before deployment.

A technically defensible manual-clearing scenario is one in which:

+ The log is full or causing an operational problem.
+ Existing events are preserved or archived when they may still be needed.
+ An authorized administrator performs the clearing.
+ The reason and authorization are documented.

Depending on the configured retention policy, Windows may overwrite older events or automatically archive a full log. Manual clearing is therefore not required in every situation.

Potentially malicious reasons for clearing the Security log include:

+ Hiding evidence of attempted or successful data exfiltration.
+ Hiding malware execution or files placed on the system.
+ Removing records that could help an analyst understand earlier activity.
+ Delaying an investigation by forcing the analyst to search through other evidence sources.

This investigation was performed directly on a standalone Windows 11 Home endpoint using Windows Event Viewer. The system was not connected to Active Directory, and no SIEM was involved. The scope is limited to understanding Event ID 1102 and the evidence available from the endpoint itself.

After the Security log was cleared, only Event ID 1102 and Event ID 4688 remained in the Security log. Event ID 4688 records process creation, so it is reviewed as a supporting event to identify the process activity recorded immediately before the log was cleared. It is not the main focus of the investigation or a wider event-correlation exercise.

I attempted to enable command-line recording for process-creation events, but the ***Process Command Line*** field remained empty. Microsoft lists the ***Include command line in process creation events*** policy as supported on Windows Pro, Enterprise, Education, and IoT Enterprise editions, but not Windows Home. Windows 11 Home was therefore treated as the likely limitation in this investigation.

Event ID 4688 could still show which program was created and which program launched it, but it could not show the complete command and its arguments.

The objectives of this investigation are to:

+ Review the important fields recorded in Event ID 1102.
+ Understand what Event ID 1102 can reveal about a Security log clearing.
+ Identify why the event may represent either legitimate or suspicious activity.
+ Review Event ID 4688 only as supporting process evidence available after the log was cleared.

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

**Step 5.** Review the only other event remaining in the Security log, Event ID 4688, to identify the process activity recorded immediately before Event ID 1102.

![event-id-1102-correlate-4688-generic.png](./Images/event-id-1102-correlate-4688-generic.png)

Fig 5. Event ID 4688 — General tab.

![event-id-1102-correlate-4688-xml-system.png](./Images/event-id-1102-correlate-4688-xml-system.png)

Fig 6. Event ID 4688 — Details tab, XML view: System section.

![event-id-1102-correlate-4688-xml-event-data.png](./Images/event-id-1102-correlate-4688-xml-event-data.png)

Fig 7. Event ID 4688 — Details tab, XML view: EventData section.

**Step 6.** Extract the relevant fields from Event IDs 1102 and 4688 for review and analysis.

## Extracted Details

### Event ID 1102 Details

| Field Name | Why it matters | Data |
| --- | --- | --- |
| `EventID` | Confirms that the event records the Security log being cleared. | 1102 |
| `TimeCreated SystemTime` | Shows exactly when the Security log was cleared. | `2026-04-29T09:31:01.2611834Z` (4/29/2026 4:31:01 PM) |
| `SubjectUserSid` | Identifies the Windows account connected to the action. | `S-1-5-21-...-1001` |
| `SubjectUserName` | Shows the account name connected to the action. | Redacted |
| `SubjectLogonId` | Identifies the login session in which the action occurred. | `0x2f78a` |
| `ClientProcessId` | Shows the process ID connected to the log-clearing request. | `22188` |

### Event ID 4688 Details

| Field Name | Why it matters | Data |
| --- | --- | --- |
| `EventID` | Confirms that the supporting event records a newly created process. | 4688 |
| `TimeCreated SystemTime` | Shows when the process was created in relation to the log clearing. | `2026-04-29T09:31:01.2413832Z` (4/29/2026 4:31:01 PM) |
| `NewProcessId` | Identifies the newly created process and can be checked against the process ID in Event ID 1102. | `0x56ac` |
| `NewProcessName` | Shows which program was created. | `C:\Windows\System32\wevtutil.exe` |
| `ParentProcessName` | Shows which program launched the new process. | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | Would show the command and its arguments, but this field was not recorded. | Empty |
| `TokenElevationType` | Shows the type of access token given to the new process. | `%%1937` |

## Analysis

### Inspecting Event ID 1102

Event ID 1102 confirmed that the Windows Security log was cleared on April 29, 2026, at 4:31:01 PM.

This event does not prove by itself whether the action was legitimate or malicious. However, it should still be investigated because clearing the Security log may remove records needed to understand what happened earlier on the system. While there are legitimate reasons to clear the log, the same action can also be used to hide traces of malicious activity.

The time was expected in this lab because I performed the action intentionally during the afternoon. In another environment, the time of the event can help determine whether the activity requires more attention. For example, a log-clearing event at 3:25 AM may appear more suspicious than one during normal working hours.

However, timing alone does not prove intent. Activity during normal working hours may look less suspicious, but it can still be unauthorized or malicious. It may simply be easier for an analyst to overlook or feel less urgency to investigate.

### Inspecting the Account and Login Session

The `SubjectUserSid` and `SubjectUserName` fields identify the Windows account connected to the Security log clearing.

The `SubjectLogonId`, `0x2f78a`, identifies the login session in which the action occurred. In this lab, these fields pointed to the account and login session I used to perform the action.

### Identifying the Process Behind the Log Clearing

After the Security log was cleared, only Event IDs 1102 and 4688 remained in Windows Event Viewer. Event ID 4688 was therefore reviewed as supporting evidence to identify the process connected to Event ID 1102.

Event ID 1102 recorded the `ClientProcessId` as 22188. Event ID 4688 recorded the `NewProcessId` as `0x56ac`, which is the hexadecimal form of `22188`. The matching process IDs connect the process recorded in Event ID 4688 to the log-clearing action recorded in Event ID 1102.

The NewProcessName identified the process as:

`C:\Windows\System32\wevtutil.exe`

The ParentProcessName identified the program that launched it as:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

This shows that PowerShell launched `wevtutil.exe`, which was the Windows utility connected to the Security log clearing. This is consistent with the action documented in the Proof of Concept.

### Inspecting the Process Access and Evidence Limitation

The `TokenElevationType` value was `%%1937`, which represents an elevated token. This shows that `wevtutil.exe` ran with elevated access and supports the Proof of Concept, where PowerShell was opened with administrator privileges before the clearing command was executed.

However, the `CommandLine` field in Event ID 4688 was empty. Windows Event Viewer recorded that PowerShell launched `wevtutil.exe`, but it did not capture the complete command or its arguments.

The exact command used in the lab was documented separately in the Proof of Concept:

`wevtutil cl Security`

I attempted to enable command-line recording for process-creation events, but the field remained empty. Microsoft lists the Include command line in process creation events policy as supported on Windows Pro, Enterprise, Education, and IoT Enterprise editions, but not Windows Home. Windows 11 Home was therefore treated as the likely limitation in this investigation.

Because the command line was not recorded, Event ID 4688 alone cannot prove that the arguments supplied to `wevtutil.exe` were `cl Security`. The connection is instead supported by the matching process IDs, the process chain, the timing of the two events, and the documented Proof of Concept.

### Determining Whether the Action Was Authorized

The Security log clearing was authorized because I intentionally performed the action as the administrator of the endpoint for this lab.

I logged into the account identified in Event ID 1102, opened PowerShell with administrator privileges, and ran the Security log-clearing command. The event data and supporting process information are consistent with the action documented in the Proof of Concept.

In another environment, the account name and administrative access would not be enough to confirm that the activity was legitimate. An authorized account could be compromised or misused, so the action would still need to be verified with the account owner, designated point of contact, or approved maintenance records.

## Conclusion

Event ID 1102 confirmed that the Windows Security log was cleared on April 29, 2026, at 4:31:01 PM. The event identified the Windows account, login session, and client process connected to the action.

The supporting Event ID 4688 record showed that PowerShell launched `wevtutil.exe`, which received an elevated token. Its NewProcessId matched the ClientProcessId recorded in Event ID 1102, supporting that this was the process connected to the Security log clearing.

The complete command line was not captured, which limited what could be confirmed from Event ID 4688 alone. However, the remaining endpoint evidence was consistent with the command documented in the Proof of Concept.

Based on the known lab activity, the Security log clearing was legitimate and authorized. In an uncontrolled environment, Event ID 1102 should still be investigated because the same action could be used to remove evidence and hide earlier malicious activity.

## Recommendation

+ Set up an alert for Event ID 1102 so the action can be reviewed as soon as it occurs.
+ Follow the principle of least privilege. Do not give administrative permissions to users who do not need them for their responsibilities.
+ Confirm the action with the designated point of contact or authorized administrator, even when it was performed by an approved account. An authorized account can still be compromised or misused, especially when the activity occurs outside expected working or maintenance hours.

## MITRE ATT&CK Reference

The activity investigated in this lab maps to the following MITRE ATT&CK framework details:

| Tactic | Technique | ID | Detail |
| --- | --- | --- | --- |
| Defense Impairment | Disable or Modify Tools: Clear Windows Event Logs | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Adversaries may clear Windows Event Logs to hide evidence of their activity. MITRE lists wevtutil cl security as one method used to clear the Windows Security log. |
| Execution | Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell was used to launch `wevtutil.exe`. Adversaries may also abuse PowerShell to execute commands and other programs on Windows systems. |

These mappings describe adversary techniques that match the recorded actions. They do not mean that the authorized activity performed in this lab was malicious.

---
