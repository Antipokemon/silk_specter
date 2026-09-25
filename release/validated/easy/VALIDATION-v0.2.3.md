# SILK SPECTER v3 v0.2.3 Validation Status

## Build statistics

- Scenario: Easy
- Campaign window: 2026-04-06 through 2026-04-10 UTC
- Total events: 56,844
- Background events: 55,731
- Malicious/campaign observations: 1,096
- Benign scenario/lookalike observations: 17
- Hosts/devices/services represented: 750
- Sourcetypes represented: 36
- Draft questions: 25
- Easy detection SPL files: 9
- Sites in canonical environment: 20
- Automated tests: 34 passing

## Malicious observations by campaign phase

| Phase | Observations |
|---|---:|
| Reconnaissance | 100 |
| Initial Access | 50 |
| Execution | 98 |
| Persistence | 96 |
| Privilege Escalation | 40 |
| Credential Access | 90 |
| Discovery | 191 |
| Lateral Movement | 91 |
| Command and Control | 140 |
| Collection | 78 |
| Collection / Staging | 85 |
| Exfiltration | 7 |
| Defense Evasion / Cleanup | 30 |
| **Total** | **1,096** |

## Generator/data compatibility checks

The automated suite verifies:

- ASA 302013 numeric unique connection IDs
- Cisco IOS login success/failure, configuration changes, and routing
- service-correct CloudTrail sources and event-specific parameters
- Defender Event Hub `category` + `properties` layout
- Defender DeviceEvents plus AlertInfo/AlertEvidence populations
- FortiGate `fortigate_traffic`
- Ivanti patch/update/package fields
- Junos success/failure authentication under `juniper`
- Junos BGP/RPD separation under `juniper:junos:firewall`
- TACACS PASS/FAIL diversity with required identity/device fields
- WSUS Installed/Failed/Downloaded/Pending/RebootRequired diversity
- Linux audit authentication/account/credential/change multipart coverage
- PAN Traffic exact installed-transform CSV width/order
- Windows Security/Sysmon both use `XmlWinEventLog` with channel-specific `source`
- every Windows EventData `Name` attribute uses single quotes
- Windows Security 4720/4726/4738/4728/4729/4732/4733 coverage and core fields
- Sysmon 1/3/11/22 coverage and event-appropriate fields
- Tenable TA-oriented schema
- Zeek X.509 cryptographic fingerprint formatting

The broader suite also validates campaign time bounds, no ground-truth leakage, deterministic HEC metadata, Corelight sourcetypes, EventRecordID ordering, question/hint structure, multi-vendor network design, and full Easy lifecycle activity.

## Runtime Splunk validation still required

After loading a fresh index, validate the installed TAs against at least:

- Windows Security extraction from `source=XmlWinEventLog:Security`
- Sysmon extraction from `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Juniper Authentication and Network/Change mappings
- TACACS Authentication outcomes
- WSUS update status fields
- Defender AlertInfo/AlertEvidence and Malware-model fields
- Zeek X.509 certificate fields
- previously verified ASA/IOS/AWS/FortiGate/PAN/Ivanti/auditd/Tenable sources
