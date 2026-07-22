# Investigating Windows Event ID 4624/4625 Success/Failed Logon Attempt

## Context

This lab investigates logon success and failure events on a Windows endpoint using Windows Event Viewer.

Logon success and failure events are important from a security perspective because multiple logon failures, such as 500 failures followed by one success, may indicate brute-force or password-guessing attempts by an attacker. A small number of failures might indicate that a normal user mistyped or forgot their credentials. However, these are only possible interpretations. A small number of failures does not guarantee that the activity was caused by a normal user. The timing and frequency of the events also matter.

The focus of this investigation is Windows Event ID 4624, which records a successful logon, and Event ID 4625, which records a failed logon.

The objectives of this investigation are to:

+ identify a trace of login failure.
+ extract relevant information from the event record.
+ determines whether the captured 4625 and 4624 represent the same logon activity.

## Proof Of Concept

**Step 1.** Log out from my computer.
**Step 2.** Attempt to log back in while intentionally entering the wrong password. This triggers one failed-logon event, Event ID 4625.

![event-id-4625-generic.png](./Images/event-id-4625-generic.png)

Fig 1. Event ID 4625 General Tab

![event-id-4625-xml-system.png](./Images/event-id-4625-xml-system.png)

Fig 2. Event ID 4625 XML View System

![event-id-4625-xml-event-data-1.png](./Images/event-id-4625-xml-event-data-1.png)

Fig 3. Event ID 4625 XML View EventData 1

![event-id-4625-xml-event-data-2.png](./Images/event-id-4625-xml-event-data-2.png)

Fig 4. Event ID 4625 XML View EventData 2

**Step 3.** Log back in using the correct password. This should trigger a successful-logon event, Event ID 4624.

A nearby Event ID 4624 was selected for examination. Later field analysis showed that the captured Event ID 4624 was a service logon rather than the corresponding successful interactive logon from this step. The event was retained so its fields could be compared with the captured Event ID 4625.

![event-id-4624-generic.png](./Images/event-id-4624-generic.png)

Fig 5. Event ID 4624 General Tab

![event-id-4624-xml-system.png](./Images/event-id-4624-xml-system.png)

Fig 6. Event ID 4624 XML View System

![event-id-4624-xml-event-data-1.png](./Images/event-id-4624-xml-event-data-1.png)

Fig 7. Event ID 4624 XML View EventData 1

![event-id-4624-xml-event-data-2.png](./Images/event-id-4624-xml-event-data-2.png)

Fig 8. Event ID 4624 XML View EventData 2

**Step 4.** Review and extract the data details.

### Event ID 4625 Logon Failure Detail Extracted

#### Event ID 4625 System section

| Field Name | What it records | Data |
| --- | --- | --- |
| EventID | The Windows event identifier. | `4625` |
| TimeCreated SystemTime | When the event was recorded. | `2026-04-29T08:53:38.2376170Z` — 29 April 2026, 3:53:38 PM local time |

#### Event ID 4625 EventData section

| Field Name | What it records | Data |
| --- | --- | --- |
| TargetUserName | Account involved in the attempted logon. | Redacted |
| TargetDomainName | Local-computer or domain context of the account. | Redacted |
| Status | Main authentication failure status code. | `0xc000006d` |
| SubStatus | More specific authentication failure status code. | `0xc000006a` |
| LogonType | Type of logon being attempted. | `2` |
| LogonProcessName | Trusted Windows logon process used for the attempt. | `User32` |
| ProcessName | The executable that requested or initiated the logon. | `C:\Windows\System32\svchost.exe` |
| IpAddress | Source network address recorded by the event. | 127.0.0.1 |

### Event ID 4624 Logon Success Detail Extracted

#### Event ID 4624 System section

| Field Name | What it records | Data |
| --- | --- | --- |
| EventID | The Windows event identifier. | `4624` |
| TimeCreated SystemTime | When the event was recorded. | `2026-04-29T08:55:30.2406223Z` — 29 April 2026, 3:55:30 PM local time |

#### Event ID 4624 EventData section

| Field Name | What it records | Data |
| --- | --- | --- |
| TargetUserName | Account for which the logon session was created. | `SYSTEM` |
| TargetDomainName | Local-computer or domain context of the account. | `NT AUTHORITY` |
| LogonType | Type of logon that occurred. | `5` |
| LogonProcessName | Trusted Windows logon process used for the attempt. | `Advapi` |
| ProcessName | The executable that requested or initiated the logon. | `C:\Windows\System32\services.exe` |
| IpAddress | Source network address recorded by the event. | `-` |

## Analysis

### Examine Event IDs

In this lab, the goal is to check the logon attempts to see if the logon failure and success correlated or not.
The event ID 4625 is logon attempt failed and the event ID 4624 is logon attempt successful.

### Examine The Timestamps

To check the timestamps, take a look at the system time of both events. Event ID 4625 logon attempt failure happened at `29 April 2026, 3:53:38 PM local time` while the event ID 4624 logon attempt success happened at `29 April 2026, 3:55:30 PM local time`. Both of them happened on the same day with the event ID 4624 happened after event ID 4625 with time different of 1 minute and 52 seconds apart. The times occured very close together making this check worth investigating. However, timestamps alone is not enough to conclude that this successful logon is the result of correct logon from event ID 4625 because event 4624 records all kind of logon success attempts, not just from logging back on from the local user account logon. It captures a successful logon of a service account as well therefore it is crucial to analyse other fields before concluding.

### Identify Accounts Involved

The related fields are `TargetUserName` and `TargetDomainName`. On Event ID 4625, the `TargetUsername` and `TargetDomainName` were my local username and my local device's name, which I redacted, which is different from the `TargetUsername` of event ID 4624 which were `SYSTEM` and `NT AUTHORITY`. If both event IDs point to the same account, it supported that these two events are correlated but it cannot conclude that without looking further. However, in this lab, the accounts involved are different. The accounts associated with event ID 4625 pointed to my account's username and which were unique and were redacted but the accounts associated with event ID 4624 is Microsoft's built-in system account (`SYSTEM` and `NT AUTHORITY` are not two separate accounts:

+ SYSTEM = target account name;
+ NT AUTHORITY = the authority/domain context for that account.

Together they identify one Windows security principal.) which appear in all Windows so I did not need to redact. This point alone showed that both events were pointed to different accounts. Different target accounts show that they cannot be the failed and successful records of the same account logon attempt.

### Interpret The LogonType

Event ID 4625's `LogonType` was `2` but event ID 4624's `LogonType` was `5`. Logon Type 2 means Interactive: a user attempted to log on directly to the computer which matched what I have been testing. Logon Type 5 means Service: the Service Control Manager started a service. This is not the same category of logon as Type 2. This is one of the strongest pieces of evidence that the records represent different activities.

### Examine LogonProcessName

Event ID 4625's `LogonProcessName` is `User32`. This is consistent with Windows handling an interactive user logon attempt. Event ID 4624's `LogonProcessName` is `Advapi`. This indicates a different Windows logon mechanism was used. Different values are a signal to investigate further. Matching values would make the events look more consistent, but would not prove they belong together. Here, `User32` versus `Advapi` supports the stronger differences already found in the target accounts and logon types.

### Examine ProcessName

The caller process associated with the failed logon request of event ID 4625 was recorded in the `ProcessName` which was `C:\Windows\System32\svchost.exe`. This connected with the failed authentication request. The caller process that attempted or requested the logon of event ID 4624 was recorded in the `ProcessName` which was `C:\Windows\System32\services.exe`. This refers to Windows Service Control Manager activity. So far, the 4624 combination is internally consistent:

+ `SYSTEM`
+ `NT AUTHORITY`
+ `Logon Type 5`
+ `Advapi`
+ `services.exe`

Together, those fields identified that event ID 4624 was a successful service logon.

### Examine The Source Address

Event ID 4625 recorded the source IP address as `127.0.0.1` which is the localhost which refers to this computer, not cloud or other computer. Event ID 4624 didn't record the source IP address. The `-` means the field was not populated for that event, not necessarily that networking did not exist.

### Read the 4625 failure Codes

On event ID 4625, the`Status` record was `0xC000006D` and `SubStatus` record was `0xC000006A`.

Their meanings are:

`0xC000006D`: The logon failed because of a bad username or authentication information.
`0xC000006A`: The password was incorrect.

These fields are not present in 4624 because 4624 records a successful logon, so it has no failure status to explain.

## Conclusion

The reason I chain them together is because the events happened close together so I compared them. However the results showed that

+ the target accounts differ
+ the logon types differs
+ the logon processes differ

Therefore there are two conclusion from the comparison of these two. The first one is time alone is insufficient to treat the 4624 as the corresponding successful version of the 4625. The second one is these two events are not the failed and successful records of the same logon attempt.

## Recommendation

+ Configure an appropriate account-lockout threshold and lockout duration for the environment. The policy should allow reasonable user mistakes while limiting repeated password-guessing attempts. Avoid setting the threshold too low because attackers could deliberately lock legitimate users out of their accounts.
+ Use strong, unique passwords and avoid reusing the same password across different accounts. A password manager can help users create and store unique passwords.
+ Enable multi-factor authentication where available. Even if an attacker obtains the correct password, MFA can prevent them from completing the login without the additional authentication factor.

## MITRE ATT&CK Reference

| Technique ID | Name | Tactic | Relevance |
| --- | --- | --- | --- |
| T1110 | Brute Force | Credential Access | Repeated authentication failures may indicate brute-force activity when examined together with the targeted accounts, source addresses, timing, frequency, and logon types. |
| T1110.001 | Password Guessing | Credential Access | Repeated Event ID 4625 records against one account, particularly with an incorrect-password status, may indicate that multiple passwords are being guessed against that account. |
| T1110.003 | Password Spraying | Credential Access | A small number of failed attempts distributed across many accounts may indicate password spraying. A low failure count for each account does not automatically mean that the activity is benign. |

MITRE defines password guessing as repeatedly trying passwords against an account and password spraying as trying one password or a small password list across many accounts to reduce the risk of account lockout.

Relevant mitigations:

M1036 — Account Use Policies
M1027 — Password Policies
M1032 — Multi-factor Authentication
