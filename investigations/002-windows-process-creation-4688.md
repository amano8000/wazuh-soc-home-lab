# Investigation 002: Windows Process Creation (Event ID 4688)

## 1. Overview

| Field | Details |
|---|---|
| Investigation ID | 002 |
| Investigation Type | Windows Process Creation |
| SIEM | Wazuh |
| Endpoint | PEKKA |
| Wazuh Agent ID | 002 |
| Windows Event ID | 4688 |
| Wazuh Rule ID | 67027 |
| Wazuh Alert Level | 3 — Low |
| Event Channel | Windows Security |
| Event Provider | Microsoft-Windows-Security-Auditing |
| Status | Initial analysis completed; signature verification pending |

## 2. Objective

Investigate a Windows process-creation event collected by Wazuh, identify the executable and its parent process, examine the associated security context, and assess whether the available evidence indicates suspicious activity.

## 3. Event Evidence

The following details were extracted from the Wazuh event:

- **Computer:** PEKKA
- **Event ID:** 4688
- **New Process:** `C:\Windows\System32\RuntimeBroker.exe`
- **Parent Process:** `C:\Windows\System32\svchost.exe`
- **Creator Account:** `PEKKA$`
- **Creator Domain:** `WORKGROUP`
- **Creator SID:** `S-1-5-18`
- **Target Account:** `Asus`
- **Target Domain:** `PEKKA`
- **Token Elevation Type:** Limited token (Type 3)
- **Event Record ID:** 199149
- **Event Time:** 2026-10-19 07:24:04 UTC

The process command line was empty in the collected event.

## 4. Investigation and Analysis

### Step 1: Identify the process

The event records the creation of `RuntimeBroker.exe`, a Windows component associated with managing permissions for certain applications.

### Step 2: Examine the parent process

The recorded parent process was `svchost.exe`, a Windows process that hosts services. Both process names are commonly found on legitimate Windows systems, but their names alone do not prove that this execution was benign.

### Step 3: Identify the security context

The creator SID `S-1-5-18` identifies the Local System security context.

The target account was `Asus` in the `PEKKA` domain. This identifies the account associated with the new process in the event.

### Step 4: Review token elevation

The event reported `TokenElevationTypeLimited (3)`, indicating that the new process received a limited access token rather than a full elevated token.

### Step 5: Review the Wazuh alert

Wazuh matched the event to rule `67027`, with alert level 3 and description `A process was created.`

This is a process-creation detection, not a verdict that the activity is malicious.

## 5. Wazuh Threat Hunting Query

The following query can be used to locate process-creation events for this endpoint:

```text
agent.name:"PEKKA" AND data.win.system.eventID:"4688"
```

Set the time range to include the event timestamp and apply the query.

## 6. Initial Assessment

The recorded process path, parent process, and token type are consistent with possible routine Windows activity. However, the available event does not establish that the executable is authentic or that the execution was harmless.

The process command line was not populated in the event, limiting the available execution context.

### Additional verification required

- Verify the Authenticode signature of `RuntimeBroker.exe`.
- Confirm that the signer is Microsoft and the signature status is valid.
- Review surrounding process-creation events for unusual parent-child relationships.
- Investigate further if additional evidence indicates suspicious behavior.

## 7. Conclusion

Successfully collected and examined Windows Security Event ID 4688 in Wazuh. Identified the process name, parent process, creator security context, associated target account, and token elevation type.

**Initial disposition:** No clear evidence of malicious activity in the available event fields. Final benign classification is pending executable signature verification and any necessary contextual investigation.

## 8. Skills Demonstrated

- Windows Security Event Log analysis
- Wazuh SIEM alert investigation
- Windows process and parent-process analysis
- Security identifier and account-context interpretation
- Token elevation analysis
- Threat hunting using event IDs
- Evidence-based incident assessment
