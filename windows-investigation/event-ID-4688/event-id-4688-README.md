# Investigating Process Creation Using Event ID 4688

## Context

On a Windows OS, Event ID 4688 (Process Creation) allows an analyst to monitor:

+ Process execution tracking
+ Program and script execution visibility

Each time a process is created, it is recorded in this log. This enables analysts to review what has been executed on a machine and identify potentially suspicious activity.

Rather than immediately determining if a process is malicious, analysts use this data to identify unusual patterns and indicators, such as unexpected parent-child relationships, abnormal file paths, or irregular privilege usage. These indicators guide further investigation.

This approach supports early detection. Relying only on visible impact does not cover all attack types. For example:

+ Ransomware is highly visible due to system disruption
+ Data exfiltration may occur silently without obvious signs

By monitoring process creation events, analysts can detect suspicious behavior before significant damage occurs.

## Proof Of Concept

Open Windows Event View, filtered the current log, and search for event ID 4688.

![SOC_EventID_4688__GeneralTab-v3.png](./Images/SOC_EventID_4688__GeneralTab-v3.png)

![SOC_EventID_4688_DetailsTab_XML-view_v3_system.png](./Images/SOC_EventID_4688_DetailsTab_XML-view_v3_system.png)

![SOC_EventID_4688_DetailsTab_XML-view_v3_eventData.png](./Images/SOC_EventID_4688_DetailsTab_XML-view_v3_eventData.png)

## Analysis

### Inspecting The Process

The process name is `lsass.exe` which is a system process. The creator process name is `wininit.exe` which is another system process. This indicate that the investigated process is a child process of another system process. The reason that investigating the parent and child process is important is because in a normal situation the expected behavior is the expect system process parent create expect system process child. If it is a malicious behavior, the process `lsass.exe` might be created by user process which can be the behavior of an attacker.

`wininit.exe` is the expect parent process that creates `lsass.exe`

### Checking File Path

Checking the paths, both are in `C:\Windows\System32` which is the usual system application path. Windows separates paths into system-protected paths and user-writable paths. An attacker needs a path with write and excuse permission with or without administration privillege in order to create or run malicious files or process.

Paths with user-writable and execution without adminisitration rights by default on Windows usually are

``` jsx

`C:\Users\`
`C:\Temp\`
`C:\AppData\`
```

These paths are attackers' initial target paths to download malicious files or create a process to run malicious files, run ordinary Windows binaries called Living Off The Land (LOL) with malicious attempts, exfiltration, or attempt privilege escaltion. This is why an analyst should check the file path and use it as an indicator to do further investigation.

### Investigate The User

The next indicator to distingush between a normal expect behaviour and a maclious one is to check the user that runs the process.

Baseline SIDs and their meaning:

| SID | Meaning |
| --- | --- |
| `S-1-5-18` | SYSTEM |
| `S-1-5-19` | Local Service |
| `S-1-5-20` | Network Service |

Patterns recognition of `S-1-5-*`

`S` -> SID
`1` -> revision
`5` -> NT Authority

This tells me that an SID with this pattern is `S-1-5-*` is a Windows built-in system/authority account.

According to the evidence in the screenshot, the SID shown was `S-1-5-18`. It corresponds to the SYSTEM account. This means the user who execused this process is a system user which is the expecting behavior from the process created by `lssas.exe`.

Malicious user indicator is regular user account creating the original process that supposed to be done by a system account. Then, they escalate their privillege to a system or administrator account to run the process.

### Investigating Privilege Escalation Attempt

According to the evidence in the screenshots

``` jsx
TokenElevationType = `%%1936` (default)
Integrity level = System (expected for `lsass.exe`)
```

Default token means no elevation of privilege appears. This showed the expected normal system behavior; therfore there is no privilege escalation attempt found.

## Conclusion

This is a normal system process. My machine is not currently under attack.

After investigate  file paths and user, the file path `C:\Windows\System32` and the user which is the system according to System User ID appear to behave according to expected normal system behavior. There is no PE attempt according to this process inspection.

## Recommendation

No danger yet. Keep monitoring for malicious software installation or excusion.

## MITRE ATT&CK Reference
