# v0.2.3 Generator/Data Compatibility Corrections

This release changes generated data only. No vendor Splunk TA is modified.

## Windows XML
- Windows Security and Sysmon both use `sourcetype=XmlWinEventLog`.
- Security keeps `source=XmlWinEventLog:Security`.
- Sysmon keeps `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.
- Every generated `<Data Name=...>` EventData attribute now uses single quotes.
- Security 4624, 4625, 4688, 4769 and account/group Change events 4720, 4726, 4738, 4728/4729, 4732/4733 remain represented.
- Sysmon IDs 1, 3, 11, and 22 retain event-appropriate fields.

## Network / AAA
- Junos authentication remains on `sourcetype=juniper`, now with a minority of native-style `SSHD_LOGIN_FAILED` records alongside `UI_LOGIN_EVENT` successes.
- Junos BGP/RPD remains under `sourcetype=juniper:junos:firewall`.
- TACACS now includes PASS and FAIL outcomes with failure reasons while PASS remains the majority.

## Update / endpoint telemetry
- WSUS now includes Installed, Failed, Downloaded, Pending, and RebootRequired outcomes with realistic update titles/KB IDs.
- Microsoft Defender keeps the Event Hub schema and existing `AdvancedHunting-DeviceEvents` records.
- Added paired `AdvancedHunting-AlertInfo` and `AdvancedHunting-AlertEvidence` records for malware/detection coverage.

## Zeek certificate quality
- X.509 fingerprints are now SHA-256 formatted hexadecimal values when an input label was not already a valid cryptographic fingerprint.

## Preserved from v0.2.2
- Cisco ASA numeric connection IDs
- Cisco IOS authentication/configuration events
- service-correct AWS CloudTrail schemas
- `fortigate_traffic`
- native PAN-OS Traffic CSV layout
- Ivanti patch/update records
- expanded Linux audit records
- Defender Event Hub conversion
- Tenable TA-oriented schema

## Final validation correction

- WSUS update catalog is constrained to updates available before the April 6-10, 2026 campaign window. The generated cumulative-update examples now use February/March 2026 KBs rather than post-campaign April releases.
