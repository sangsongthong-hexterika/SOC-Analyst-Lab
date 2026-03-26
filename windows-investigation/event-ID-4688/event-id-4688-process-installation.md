# Investigating Process Creation Using Event ID 4688

## Context

On a windows OS, Event ID 4688 Process Creation is where an analyst can check the log for

+ app installation succession
+ app that is running
+ suspicious or malicious app that is running --> to see that the investigated machine is under attacks or not

## Proof Of Concept

Open Windows Event View, filtered the current log, and search for event ID 4688.

![SOC_EventID_4688__GeneralTab-v3.png](./Images/SOC_EventID_4688__GeneralTab-v3.png)

![SOC_EventID_4688_DetailsTab_XML-view_v3_system.png](./Images/SOC_EventID_4688_DetailsTab_XML-view_v3_system.png)

![SOC_EventID_4688_DetailsTab_XML-view_v3_eventData.png](./Images/SOC_EventID_4688_DetailsTab_XML-view_v3_eventData.png)

## Analysis

The process name is lsass.exe which is a system process. The creator process name is wininit.exe which is another system process. This indicate that the investigated process is a child process of another system process.

Checking the paths, both are in `C:\Windows\System32` which is the usual system application path.

Malicious paths usually are

+ user path
+ temp path

It said that the user is N/A which points to system.

Malicious user indicators are

+ regular user excusing the app
+ regular user escalate their privillege to a system or administrator to run the app

There is no proof of PE attempt.

## Conclusion

This is a normal system process. My machine is not currently under attack.

## Recommendation

No danger yet. Keep monitoring for malicious software installation or excusion.

## MITRE ATT&CK Reference
