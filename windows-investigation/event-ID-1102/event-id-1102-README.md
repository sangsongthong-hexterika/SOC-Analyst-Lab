# Investigating Windows Event ID 1102 Security Log Was Cleared

## Context

This lab investigates when the security log was deleted on a Windows endpoint using Windows Event Viewer.

If performs by an unauthorized user, it is an important indicator that something happened. This something is bad enough that the attacker wanted to hide from the security professionals.

The focus of this investigation is Windows Event ID 1102, which records when a security audit log was clear.

When this event happens it is an indication that something happened which was bad enough that someone attempt to hide it from the record unless it was performed by an authorized admin.

The objectives of this investigation are to:

+ To extract relevant information from the event record
+ To determine whether the activity represents a legitimate behavior performed by the authorized people or by an attacker.

Examples of good reasons why an authorized admin perform it are:

+ To reclaim the space on the computer when the log has taken up a lot of space.
+ It is a lab.

Examples of bad reasons why an attacker perform it:

+ To hide their data exfiltration attempt.
+ To hide their malware dropping which makes it more difficult for the security analyst to track and secure the system. If they don't know which application or file is infected with the malware, they will have to take time digging. By the time they find it, some damages may have already occured.

## Proof Of Concept

Step 1. Run `PowerShell.ps` as administrator.
Step 2. Type this command to wipe all the logs: `wevtutil cl Security`.

![event-id-1102-powershell.png](./Images/event-id-1102-powershell.png)

Fig 1. A PowerShell command clearing the log.

Step 3. Open `Windows Event Viewer` and search for the event ID `1102`.

![event-id-1102-general-tab.png](./Images/event-id-1102-general-tab.png)

Fig 2. Event Viewer General Tab

![event-id-1102-xml-system.png](./Images/event-id-1102-xml-system.png)

Fig 3. Event Viewer Details Tab XML View System

![event-id-1102-xml-user-data.png](./Images/event-id-1102-xml-user-data.png)

Event Viewer Details Tab XML View UserData

Step 4. Review event details.

### Event Detail Extracted

| Field Name | Data |
| --- | --- |
| Event ID | 1102 |
| SubjectUserSid | `S-1-5-21-...-1001` |
| SubjectUserName | Redacted My Real Username |
| SubjectDomainName | Redacted My Real Domain Name |
| SubjectLogonID | `0x2f78a` |

## Analysis

Taking a look at the data from the Event Viewer XML, the criteria for analysis are:

| Field Name | What it tells me? | Why it is an indicator? |
| --- | --- | --- |

### Inspecting The Event ID

### Inspecting Account Name

### Inspecting Logon ID

### Inspecting Source

## Conclusion

This log wiped is performed by me, the authorized admin of my computer for this lab as explained in the Analysis section. This is a legitimate action. There is no trace of attackers.

## Recommendation

+ Set up an alert when this event is performed.
+ Follow the least privilege rule. Do not give authorization power to any users who should not have.
+ Communicate with the point of contact or the authorized admin if the action is performed by them if you are unsured even if the account who perform this action is an authorized account. An authorized account can be compromised as well especially when the action time is from unusual hours.

## MITRE ATT&CK Reference

---

CEU Submission Info

**Author:** Sangsongthong Chantaranothai  
**Blog Title:** Investigating Windows Event ID 1102 Security Log Was Cleared
**Blog URL:**
**Date Published:**  
