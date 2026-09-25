# Validated Splunk TA / source contracts

This file is a **do-not-regress contract** for generated data. Vendor TAs are external dependencies and must not be modified to accept synthetic shortcuts. Fix the generator instead.

## Windows Security

- `sourcetype=XmlWinEventLog`
- `source=XmlWinEventLog:Security`
- Native XML EventData uses single-quoted `Name` attributes: `<Data Name='TargetUserName'>...`.
- Current required coverage: 4624, 4625, 4688, 4769, 4720, 4726, 4738, 4728, 4729, 4732, 4733.
- Account/group-change events require appropriate `Subject*`, `Target*`, and `Member*` fields.

## Windows Sysmon

- `sourcetype=XmlWinEventLog`
- `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- EventData `Name` attributes use single quotes.
- Required IDs/fields:
  - 1: Image, CommandLine, ProcessId, ParentProcessId, ParentImage, User, ProcessGuid, ParentProcessGuid
  - 3: Image, ProcessId, User, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol, Initiated
  - 11: Image, ProcessId, TargetFilename, CreationUtcTime
  - 22: Image, ProcessId, QueryName, QueryStatus, QueryResults
- EventRecordID must rise by event time per host/channel.

## Zeek/Corelight-style JSON

Generated event payloads are Zeek JSON. Splunk metadata must use the installed Corelight/Zeek TA contracts:

- connection -> `bro:conn:json`
- DNS -> `bro:dns:json`
- HTTP -> `bro:http:json`
- TLS/SSL -> `bro:ssl:json`
- SMB file activity -> `bro:smb_files:json`
- DCE/RPC -> `bro:dce_rpc:json`
- files -> `bro:files:json`
- X.509 -> `bro:x509:json`

Do not introduce `stream:*`. X.509 fingerprints must be valid hexadecimal SHA-1/SHA-256-shaped values.

## Cisco ASA

- `sourcetype=cisco:asa`
- `%ASA-6-302013` requires a numeric connection/session ID immediately after `TCP connection`.
- Connection IDs should be unique in the generated corpus.

## Cisco IOS

- `sourcetype=cisco:ios`
- Include routing/OSPF plus operational authentication/change records.
- Auth examples use native `%SEC_LOGIN-5-LOGIN_SUCCESS` and `%SEC_LOGIN-4-LOGIN_FAILED` shapes.
- Configuration changes use `%SYS-*-CONFIG_I` / `%SYS-5-CONFIG_I`-compatible records.

## FortiGate

- `sourcetype=fortigate_traffic`
- Keep native FortiGate key/value traffic payloads.

## Juniper

- Authentication/admin events enter as `sourcetype=juniper` so the installed TA can route/parse them.
- Retain successful `UI_LOGIN_EVENT` and a minority of failed SSH authentication events with user/source/device context.
- Junos BGP/RPD routing events remain `sourcetype=juniper:junos:firewall`.

## Palo Alto

- `sourcetype=pan:traffic`
- Emit native PAN-OS Traffic CSV in the exact field order/width expected by the installed TA `extract_traffic` transform. Do not use abbreviated synthetic CSV.

## AWS CloudTrail

- `sourcetype=aws:cloudtrail`
- `eventSource` must match `eventName` service.
- Request/response structures must be operation-specific, not generic `resource=synthetic-N` placeholders.
- Examples: S3 GetObject uses bucketName/key; Secrets Manager GetSecretValue uses secretId; STS AssumeRole uses roleArn/roleSessionName; RDS/ELB/ECR/SSM/Lambda/CloudFront use their own service sources.

## Microsoft Defender

- `sourcetype=ms:defender:eventhub`
- Event Hub envelope uses `category` with data fields beneath `properties`.
- Preserve `AdvancedHunting-DeviceEvents`; detection/malware coverage uses AlertInfo/AlertEvidence-style Event Hub records with shared Alert IDs and realistic detection/evidence fields.

## Tenable

- `sourcetype=tenable:io:vuln`
- Top-level `ipv4`/`ip` and `asset_fqdn` are populated.
- Vulnerability identity includes plugin.id, plugin.name, plugin.family, plugin.synopsis, CVE/CVSS/risk metadata where appropriate.
- `port.port` and `port.protocol` remain populated.

## Linux auditd

- `sourcetype=linux_audit`
- Include realistic multipart SYSCALL/EXECVE/PROCTITLE plus USER_AUTH, USER_LOGIN, USER_ACCT, credential acquisition/refresh, and account/group/password-management audit records.

## TACACS / WSUS / Ivanti

- TACACS keeps fields server, user, device, src, service, result and includes mostly PASS with a minority FAIL/REJECT where appropriate.
- WSUS client JSON includes device, server, status, timestamp, title, update_id, with Installed majority and Failed/Downloaded/Pending/RebootRequired minorities.
- Ivanti events include patch/update/package identity, target device, version/file/package data, and success/failure.

## Regression enforcement

Run `python3 -m unittest discover -s tests -v`. TA compatibility tests are release blockers. If Splunk runtime behavior disagrees with these local tests, fix the generator/test contract and document the runtime validation result; do not patch the vendor TA.
