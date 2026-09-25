# SILK SPECTER v3 v0.3.0 validation / readiness status

## Validated runtime baseline

The user confirmed **v0.2.3 Easy passed all target Splunk checks** after the generator/TA compatibility work. v0.3.0 retains those validated source-native contracts and regenerates the same 56,844-event Easy baseline while adding repository, scenario, and time-window infrastructure.

## Current Easy build statistics

- Scenario: Easy
- Status: validated
- Campaign default window: 2026-04-06 through 2026-04-10 UTC
- Total events: 56,844
- Background events: 55,731
- Malicious/campaign observations: 1,096
- Benign scenario/lookalike observations: 17
- Hosts/devices/services represented: 750
- Sourcetypes represented: 36
- Current starter questions: 25 / target 180
- Canonical ingest: `dataset/easy/hec/events.jsonl`

## Local validation

Run:

```bash
python3 -m unittest discover -s tests -v
```

Current v0.3.0 result: **40 tests passing**.

The suite covers the historical v0.2.3 compatibility checks plus repository/scenario readiness:

- ASA 302013 numeric unique connection IDs
- Cisco IOS authentication/configuration/routing activity
- service-correct AWS CloudTrail schemas
- Defender Event Hub DeviceEvents and AlertInfo/AlertEvidence
- FortiGate supported sourcetype
- PAN-OS native traffic CSV layout
- Junos auth success/failure and RPD separation
- TACACS outcome diversity
- WSUS status diversity
- Ivanti patch/update fields
- Linux audit auth/account/credential multipart records
- generic XmlWinEventLog with channel-specific sources
- Windows EventData single-quote compatibility
- Security 4720/4726/4738/4728/4729/4732/4733 coverage
- Sysmon 1/3/11/22 event-appropriate fields
- Tenable schema
- Zeek/Corelight metadata and X.509 fingerprint realism
- campaign time bounds and HEC metadata
- monotonic EventRecordID by host/channel
- full Easy lifecycle coverage
- network path observability
- multi-vendor firewall policy
- participant ground-truth isolation
- question/hint consistency
- Easy/Medium/Hard scenario quality gates
- question-bank artifact presence
- reusable semantic network-flow validation

## Time-window regression proof

The Easy generator was also run with:

```text
start=2026-05-04T00:00:00Z
end=2026-05-08T23:59:59Z
```

A reduced test corpus generated entirely inside that window. Representative embedded raw timestamps for PAN-OS, Cisco ASA, Windows/Sysmon, and Zeek shifted to May together with HEC `_time`; the generator did not merely rewrite Splunk metadata.

## Scenario status

- Easy: validated
- Medium: authoring
- Hard: authoring

Medium/Hard are not runtime-validated yet and must not be represented as complete. Their configs, question-bank schemas, time windows, site scopes, and module extension points are present so work can continue without redesigning the framework.

## Runtime release gate for future scenarios

For any new or changed parser-sensitive scenario:

1. regenerate;
2. pass local tests;
3. load into a **fresh** Splunk index;
4. validate installed TA field extraction;
5. validate relevant CIM/data models;
6. validate reference SPL/answer key;
7. only then set scenario status to `validated`.

See `AGENTS.md`, `docs/TA_COMPATIBILITY.md`, and `docs/SPLUNK_LOAD.md`.
