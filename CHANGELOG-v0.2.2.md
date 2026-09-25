# v0.2.2 TA Compatibility Corrections

- Cisco ASA 302013 connection IDs added and validated unique in the generated corpus.
- Cisco IOS authentication success/failure and configuration changes added alongside routing events.
- AWS CloudTrail event sources and request/response structures made service/event-specific.
- Defender moved to `ms:defender:eventhub` with `category` + `properties` Event Hub layout.
- FortiGate moved to `fortigate_traffic`.
- Ivanti expanded to patch/update/package deployment telemetry.
- Junos moved from `junos:syslog` to TA base sourcetype `juniper`; authentication success/failure added.
- Linux auditd expanded with PAM/user/session/account/group/credential records and multipart process records.
- Palo Alto traffic expanded to the complete 61-field `extract_traffic` CSV layout used by the installed TA.
- Windows Security moved to `XmlWinEventLog:Security`.
- Windows Sysmon moved to `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.
- Windows Security change coverage added: 4720, 4726, 4738, 4728/4729, 4732/4733.
- Tenable vulnerability records reshaped with top-level asset addressing and richer plugin/CVE/CVSS metadata.
