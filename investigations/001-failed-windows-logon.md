# Investigation 001: Windows Failed Logon

## Objective
Validate Windows Security event collection and alert generation in Wazuh using a controlled failed-login test.

## Lab Environment
- SIEM: Wazuh
- Manager operating system: Ubuntu
- Monitored endpoint: Windows (`PEKKA`)
- Wazuh agent ID: `002`
- Data source: Windows Security Event Log

## Alert Details
- Windows Event ID: `4625`
- Wazuh Rule ID: `60122`
- Wazuh Rule Level: `5`
- Alert: Logon Failure — Unknown user or bad password
- Target username: `wazuh_test_user`
- Logon type: `2` (interactive)
- Source address: `::1` (IPv6 loopback)
- Failure substatus: `0xc0000064` (unknown username)
- Event time: `2026-10-18 17:47:06 UTC`

## Investigation
1. Verified that the Windows endpoint was connected to the Wazuh manager.
2. Enabled auditing for failed logon attempts.
3. Generated a controlled failed-login attempt using a test username.
4. Verified Windows Event ID `4625` in the Security log.
5. Located the corresponding alert in Wazuh Threat Hunting.
6. Reviewed the username, source address, logon type, failure reason, and alert severity.

## Findings
The event is consistent with the controlled test. The target username was the test account name, the failure substatus indicated an unknown username, and the source address was the local IPv6 loopback address.

A single failed logon does not establish a brute-force attack.

## MITRE ATT&CK Validation
The alert's Wazuh mapping referenced T1531 (Account Access Removal). This behavior was not demonstrated by the event, so the mapping should not be treated as evidence that T1531 occurred.

## Disposition
**Benign test activity — detection validation successful.**

## Evidence
- `../screenshots/wazuh-agent-active.png`
- `../screenshots/windows-event-4625.png`
- `../screenshots/wazuh-alert-60122.png`

## Skills Demonstrated
- Windows Security Event Log analysis
- SIEM alert investigation
- Wazuh agent and event validation
- Authentication failure triage
- MITRE ATT&CK mapping validation
- Incident documentation
