# AGENTS.md — SILK SPECTER / Asteron CTF engineering contract

This file is the primary handoff for any future coding agent working in this repository. Read it before changing generators, scenarios, questions, detections, or Splunk ingest metadata.

The purpose of this document is to preserve the work already spent validating generated telemetry against the installed Splunk technology add-ons. Do **not** rediscover or “simplify” these contracts unless an actual target-lab validation proves they changed.

---

## 1. Project mission

Build a modern Splunk investigation/CTF environment inspired by BOTS-style exercises, using a fictional multinational critical-infrastructure enterprise called **Asteron Utilities Group, Inc.**

The exercise should train analysts to:

- discover data sources in Splunk rather than being handed exact sourcetypes;
- pivot across Windows, Linux, network, cloud, identity, endpoint-security, application, physical-access, and management telemetry;
- reconstruct attack paths through the network;
- distinguish actor behavior from legitimate vulnerability scanning, management, maintenance, and administrative activity;
- investigate detections/findings without assuming every finding is malicious;
- find malicious activity that generated no finding;
- reconstruct collection, staging, and exfiltration;
- recognize equivalent functions across different firewall/router/security vendors;
- progress from guided Easy discovery to independent Medium/Hard investigation.

The current actor is **SILK SPECTER**, a fictional actor whose methodology is inspired by publicly documented Volt Typhoon/G1017 tradecraft. Do not claim fictional actions are exact real-world Volt Typhoon actions or attribution.

All offensive behavior is represented as inert synthetic telemetry. Do not add live exploit payloads, credential-dumping code, malware, or operational exfiltration tooling.

---

## 2. Current validated state

Repository version: read `VERSION`.

The last fully Splunk-validated generated corpus before repository hardening was **v0.2.3 Easy**. The user confirmed that version passed all checks in the target Splunk lab.

Current Easy baseline after the v0.3.0 repository/time-window refactor:

- 56,844 generated events
- 36 sourcetypes
- 750 hosts/devices/services represented
- 1,096 malicious/campaign observations
- 17 benign scenario/lookalike observations
- default UTC window: 2026-04-06 00:00:00 through 2026-04-10 23:59:59
- 25 validated starter questions, target 180
- 34 legacy generator/TA compatibility tests from v0.2.3 plus repository-readiness tests

Scenario quality gates:

- `easy`: `validated`
- `medium`: `authoring`
- `hard`: `authoring`

**Never mark Medium or Hard `validated` merely because code runs.** They require a distinct campaign path, question bank, detections/findings, fresh-index load, installed-TA field validation, and relevant CIM checks.

Use `python3 scripts/scenario_status.py` or `make status`.

---

## 3. Repository source of truth

Important paths:

```text
AGENTS.md                         this engineering contract
VERSION                           repository/release version
config/sites.json                 canonical 20-site environment
config/network_devices.json       layered vendor/device placement policy
config/directory.json             AD/domain/admin model
config/services.json              enterprise/AWS service model
config/identity.json              identity/enrichment context
config/actors/                    actor profiles
config/scenarios/                 scenario status/window/scope/seed/index

generator/generate.py             scenario CLI / Easy validated dispatcher
generator/core/state.py           event store, metadata normalization, HEC output
generator/core/scenario.py        UTC scenario windows / relative timeline helper
generator/core/network.py         semantic network-flow contract for new work
generator/renderers/              source-native event renderers
generator/background.py           enterprise background/noise
generator/corroboration.py        current Easy corroborating campaign evidence
generator/attack_expansion.py     current Easy lifecycle expansion

tests/                            release-blocking local tests
question_bank/                    scenario question/answer/hint source pools
participant/                      participant-facing documentation/exports
instructor/                       ground truth, reference SPL, findings, answer data
docs/                             architecture/load/authoring contracts
splunk/app/TA-asteron-v3          ONLY the Asteron HEC-envelope ingest helper
splunk/ingest/load_hec.sh         canonical file loader
scripts/load_to_splunk.sh         host-side Podman workflow, includes CLI login
```

Generated release data under `dataset/<scenario>/raw` and `dataset/<scenario>/hec` is reproducible and intentionally ignored by normal Git adds. The release ZIP may include it for immediate loading.

---

## 4. Non-negotiable Splunk rule: fix the generator, not the vendor TA

The target lab already has vendor/product TAs. Synthetic events must match them.

Do not add local field extractions to make malformed synthetic logs look correct. Do not change official/vendor TA transforms to accept abbreviated data. If fields do not populate, compare the generated native format to the installed TA contract and fix the generator.

`docs/TA_COMPATIBILITY.md` is the concise compatibility contract. The following details are especially important.

### Windows Security

Keep:

```text
sourcetype=XmlWinEventLog
source=XmlWinEventLog:Security
```

EventData must use single quotes:

```xml
<Data Name='TargetUserName'>user0451</Data>
```

Do not use channel-specific sourcetype metadata for the target lab.

Required current coverage includes 4624, 4625, 4688, 4769 and account/group changes 4720, 4726, 4738, 4728, 4729, 4732, 4733.

### Windows Sysmon

Keep:

```text
sourcetype=XmlWinEventLog
source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

EventData Name attributes use single quotes. Current required IDs include 1, 3, 11, 22 with event-appropriate native fields.

### EventRecordID

Windows/Sysmon EventRecordID must be monotonically increasing by event time within each host/channel. Use `EventStore.record_id_at()`, not generation order.

### Zeek/Corelight-style network data

Payloads are Zeek JSON. Splunk metadata uses:

```text
bro:conn:json
bro:dns:json
bro:http:json
bro:ssl:json
bro:smb_files:json
bro:dce_rpc:json
bro:files:json
bro:x509:json
```

There are no separate synthetic SMB command/status log families in this exercise; current SMB evidence is `smb_files` plus DCE/RPC/connection evidence where appropriate.

Do not add legacy `stream:*` sources.

### Cisco ASA

`%ASA-6-302013` requires a numeric connection/session ID after `TCP connection`. Current tests require unique IDs in the generated corpus.

### Cisco IOS

Keep routing/OSPF plus `%SEC_LOGIN-5-LOGIN_SUCCESS`, `%SEC_LOGIN-4-LOGIN_FAILED`, and `%SYS-*-CONFIG_I` configuration-change activity.

### Palo Alto

`pan:traffic` must be emitted in the full native PAN-OS traffic CSV layout expected by the installed `extract_traffic` transform. Do not return to abbreviated CSV.

### FortiGate

Use `fortigate_traffic`, not `fortigate:traffic`.

### Juniper

- administrative/authentication events: `sourcetype=juniper`
- BGP/RPD firewall/routing family currently validated under `juniper:junos:firewall`
- preserve successful UI login plus minority failed SSH authentication activity

### AWS CloudTrail

Use service-correct `eventSource`, `eventName`, requestParameters, and responseElements. Never fall back to generic `{"resource":"synthetic-N"}` for unrelated AWS APIs.

### Defender

Use `ms:defender:eventhub`, with `category` plus fields inside `properties`. Preserve DeviceEvents and AlertInfo/AlertEvidence malware/detection coverage.

### Tenable

Keep TA-oriented top-level asset fields (`ipv4`/`ip`, `asset_fqdn`) and plugin identity/synopsis/CVE/CVSS metadata.

### Linux auditd

Retain multipart native audit relationships and auth/account/credential-management records in addition to SYSCALL/EXECVE/PROCTITLE.

### Other validated quality requirements

Retain TACACS success/failure diversity, WSUS status diversity, realistic Ivanti update/package records, and hash-formatted Zeek X.509 fingerprints.

---

## 5. Time model and scenario windows

Every scenario config in `config/scenarios/` owns:

- `start` UTC ISO-8601
- `end` UTC ISO-8601
- deterministic `seed`
- target `index`
- `scope_sites`
- status and question target

Do not hard-code calendar dates in new scenario modules. Use:

```python
ScenarioContext.at(day_offset, hour, minute, second)
```

The Easy campaign was refactored so its authored timeline moves when `--start`/`--end` is changed. The raw source timestamps must move with Splunk metadata; do not only rewrite HEC `_time`.

Generation example:

```bash
python3 generator/generate.py \
  --scenario easy \
  --start 2026-05-04T00:00:00Z \
  --end 2026-05-08T23:59:59Z \
  --output /tmp/easy-shifted
```

The generator checks every event against the declared scenario window and must fail if an event falls outside it.

Global background behavior must be based on each site’s IANA time zone. Store all final event times in UTC. Do not make every global user active in the same UTC work window, and do not generate all users continuously throughout the day. Water/power/NOC operations may have 24/7 shift behavior; corporate user activity should cluster around local business hours; maintenance/backups can occur at local off-hours.

The actor should frequently blend into plausible local activity windows, with selected anomalies/mistakes outside them.

---

## 6. Network realism and correlation invariants

The network is segmented by **location and function**. Asteron has 20 routed site aggregates. See `docs/NETWORK_PURPOSE_AND_LAYOUT.md` and `config/sites.json`.

Primary inter-site transport is Internet-based encrypted IPsec VPN, with selected direct site-to-site tunnels for critical dependencies. Large sites use three security/firewall vendor layers; small sites use two.

Network observability rules:

1. Create one semantic flow/session and reuse the same facts across all observations.
2. Source/destination IP, ports, protocol, timing, NAT direction, bytes, and role relationships must not independently randomize between Zeek, firewall, endpoint, VPN, cloud flow, or remote authentication records.
3. Use `generator/core/network.py` for new campaign modules. `NetworkFlow` validates tuples; `NetworkLedger` can enforce required observation families.
4. Major attack transitions should have at least one defensible network observation unless the transport/location genuinely prevents it.
5. Site-to-site VPN Internet transport is encrypted; sensors on the trusted side can observe internal flows. Do not pretend to decrypt the VPN itself.
6. TLS inspection is selective. Some gateways/WAF/proxies can expose application detail; other flows should remain TLS metadata only.
7. Cloud DNS stays cloud-native unless resolving internal Asteron resources.

Desired correlation pattern:

```text
endpoint process
 -> endpoint network
 -> Zeek/Corelight connection/protocol
 -> firewall/NAT/VPN boundary
 -> remote authentication
 -> remote process/file/cloud action
```

---

## 7. Environment model that must remain stable unless intentionally versioned

Organization: **Asteron Utilities Group, Inc.**

Asteron is a company-of-companies operating water, power/grid, engineering, infrastructure, regional operations, and digital services.

Canonical forest:

```text
ASTERON.LOCAL
├── US.ASTERON.LOCAL
├── EU.ASTERON.LOCAL
├── AU.ASTERON.LOCAL
├── APAC.ASTERON.LOCAL
└── LATAM.ASTERON.LOCAL
```

Normal user login is username/password. Privileged/special-service administration uses CAC/certificate-backed access where appropriate. PAWs and jump hosts are expected admin origins. Network-device AAA is intentionally mixed TACACS+/RADIUS.

Enterprise services include AD/DNS/DHCP, PKI/CAC, Tenable, VDI, ServiceNow, secure file transfer, print, SCCM/MECM, WSUS, Ivanti, self-managed GitLab, Atlassian, Defender, Trellix, backup, monitoring, vulnerability management, physical-access/badging, and AWS service platforms.

AWS organization is **service-oriented**, not just generic Dev/Test/Prod. Services such as GitLab, Atlassian, web, AI/analytics, data, observability, artifacts, and engineering data may each have lifecycle accounts and regional ownership.

Do not redesign the enterprise for each difficulty. The same environment persists; attack path, scope, visibility, notables, and investigative complexity change.

---

## 8. Difficulty design contract

### Easy

- U.S.-only campaign scope, but multiple U.S. locations.
- Multiple firewall vendors and Windows/Linux/cloud/network sources.
- Network path must be traceable.
- External reconnaissance may include identifiable public scanners (for example a Censys-style scanner) and a separate malicious cloud-provider address.
- Include recon/enumeration, initial access, execution, persistence, privilege escalation, credential access, discovery, lateral movement, C2/operator activity, collection, **simple staging**, exfiltration, and selective cleanup.
- Exfil is comparatively obvious: large outbound transfer to a rare destination with endpoint/network/DLP/firewall corroboration.
- Findings are useful but include benign/questionable activity.
- First questions teach Splunk data discovery; `| tstats values(sourcetype) where index=* by index` is the canonical initial teaching query.

### Medium

- Same enterprise, larger geographic/vendor scope.
- Different attack path from Easy while retaining SILK SPECTER/Volt Typhoon-inspired methodology.
- More legitimate administrative lookalikes and multiple authentication paths.
- Required data staging becomes more explicit: collection -> staging directory -> archive/compression -> transfer -> cleanup.
- Findings expose fragments, not the complete path.
- More cross-source and cross-region questions.

### Hard

- Same global environment, potentially all 20 sites.
- Heterogeneous controls, sparse findings, partial visibility, substantial valid-account/LOTL overlap.
- Legitimate secure-file-transfer/MFT abuse is preferred for exfil; analyst proves unauthorized use through context rather than a plainly bad destination.
- Include OT-adjacent pre-positioning and management-plane investigation without requiring PLC programming knowledge.
- Some important actor activity produces no finding.

Each tier gets a **separate Splunk index and separate detection pack**. Easy findings must never search Medium/Hard indexes, and vice versa.

---

## 9. SILK SPECTER Easy answer-bearing facts

Treat current question answers as stable interfaces. Before changing any value used by a question, search `question_bank/easy/questions.csv`, `instructor/questions/easy_questions.csv`, and the answer key.

Examples of sensitive answer-bearing data include:

- index name
- source/sourcetype names
- first compromised host
- service accounts/user identities
- actor/cloud/provider addresses
- specific cross-site destination hosts
- exfil destination/domain
- canonical exfil byte count
- ordering/timestamps used in timeline answers

The Easy canonical exfil connection is intentionally a single answer-bearing large transfer. Do not add arbitrary extra `bro:conn:json` transfers to the same destination if a question sums bytes unless you update the question/answer/reference SPL and revalidate it.

---

## 10. Question-bank rules

Target total:

- Easy 180
- Medium 170
- Hard 150

Files live in `question_bank/<scenario>/`.

A question is not release-ready until:

1. supporting telemetry exists;
2. intended answer is deterministic;
3. instructor reference SPL or deterministic validation exists;
4. no unintended alternative also satisfies the wording;
5. hints are present;
6. participant export contains no answer/reference/ground-truth leakage.

Hint philosophy:

- Easy: usually two hints. Early questions teach commands/concepts, including `tstats`; scaffolding fades quickly.
- Medium: usually three hints: concept -> likely telemetry relationships -> search strategy.
- Hard: usually three strategic hints; exact sourcetype names should generally not appear until late, if at all.

Hints should teach **how to investigate**, not progressively spell the answer.

Do not populate Medium/Hard answer files before their telemetry exists. Empty schema files are preferable to invented answer keys.

---

## 11. Detections/findings/notables

Detection results are training evidence, not truth labels.

Instructor ground truth may classify results as benign, benign administrative, questionable, suspicious, malicious, or high-confidence malicious. Participants do not see these labels.

The corpus should contain:

- benign vulnerability-management/recon hits (Tenable, SCCM, Ivanti, monitoring, etc.);
- questionable authentication/admin findings;
- clearly malicious endpoint/web/application detections;
- malicious activity with no finding;
- unrelated suspicious activity where appropriate.

Easy/Medium/Hard detection packs must be index-scoped to their own scenario.

Do not create a finding for every malicious action; that turns investigation into alert-clicking.

---

## 12. Participant vs instructor data separation

Participant material contains only:

- organization/environment background;
- topology/network purpose;
- naming conventions/context;
- scenario briefing/start point;
- questions and hints;
- Easy-only discovery guide where appropriate.

Never put these in participant raw/docs:

```text
truth_label
malicious=true
attack_event
campaign phase labels
activity_id / evidence graph IDs
MITRE technique IDs as hidden answers
expected finding disposition
reference SPL
answer key
actor ground-truth timeline
```

Generated participant event IDs should be opaque.

Instructor material may contain the evidence graph, techniques, truth labels, dispositions, reference SPL, answers, and activity relationships.

---

## 13. Generating data

Validated Easy default:

```bash
python3 generator/generate.py \
  --scenario easy \
  --output dataset/easy \
  --background-events 5000 \
  --enterprise-background-events 45000
```

or:

```bash
make generate-easy
```

The generator clears stale raw shards before writing a new corpus.

`generator/generate.py --scenario medium` and `--scenario hard` intentionally refuse to generate while their status is `authoring`. This is a quality gate, not a bug.

To enable a new scenario:

1. implement its distinct campaign module;
2. add detections/findings;
3. author initial question pool;
4. add scenario-specific tests;
5. generate and load a fresh Splunk index;
6. verify installed TA fields and relevant CIM data models;
7. set config status to `validated` only after runtime checks pass.

---

## 14. Testing and release gates

Always run:

```bash
python3 -m unittest discover -s tests -v
```

or:

```bash
make validate
```

Local tests must cover:

- campaign time bounds;
- all three scenario registry/status files;
- no participant ground-truth leakage;
- deterministic HEC event count/metadata;
- source/sourcetype contracts;
- TA-specific payload shapes;
- Windows EventRecordID ordering;
- required lifecycle phases;
- multi-vendor firewall policy;
- Windows/Linux Sysmon presence;
- network path observability/correlation;
- question uniqueness and hint coverage;
- question/answer key alignment;
- source-diverse background realism.

Then perform a **fresh-index Splunk runtime validation**. Local tests do not substitute for the installed TA behavior.

Do not reload corrected events into the old index. Already indexed events retain old metadata/raw.

---

## 15. Splunk load workflow

Full instructions: `docs/SPLUNK_LOAD.md`.

Preferred command:

```bash
./scripts/load_to_splunk.sh easy asteron_easy_v030
```

The workflow must include interactive CLI authentication:

```bash
podman exec -it --user splunk splunk \
  /opt/splunk/bin/splunk login
```

Do not put credentials in `-auth user:password` commands or repository files.

The validated environment uses container name `splunk`; Splunk administrative CLI commands run as OS user `splunk`. The copied source data is temporary and may be removed after successful indexing.

---

## 16. Git/release workflow

This repository is intended to be placed directly under Git.

Recommended initialization:

```bash
git init
git add .
git status
git commit -m "baseline: validated Asteron Easy generator and CTF framework"
```

`.gitignore` excludes bulky reproducible raw/HEC datasets and event-level ground truth from normal Git history. The source generator/configs/tests/question masters/docs are the version-controlled source of truth.

Before committing a generator change:

1. update code/config;
2. regenerate relevant scenario;
3. run tests;
4. compare manifest/counts/ground truth/question answers;
5. load a fresh Splunk validation index when parser behavior is affected;
6. update changelog/VALIDATION docs;
7. commit source changes;
8. package a release with `scripts/package_release.sh` if needed.

Do not commit passwords, Splunk session tokens, proprietary TA files, or external vendor packages.

---

## 17. Adding a new APT without repeating this project’s mistakes

Use the existing Asteron platform as a reusable telemetry engine.

1. Create `config/actors/<actor>.json`.
2. Record the public reporting/ATT&CK source snapshot under `research/`.
3. Define behavior library and objectives before writing logs.
4. Define scenario scopes/windows/seeds/indexes/status.
5. Reuse validated renderers and TA contracts. Do not invent new simplified JSON when a native format already exists.
6. Build a causal activity graph first: identities, sessions, processes, files, network flows, cloud sessions.
7. Render multiple observations from the same state.
8. Create realistic benign equivalents/lookalikes.
9. Add detections/findings with instructor dispositions.
10. Author questions only after evidence is stable.
11. Validate local schemas/tests.
12. Load fresh Splunk indexes and verify runtime extraction/CIM.
13. Only then mark scenario validated and expand question counts/background volume.

If a new actor needs a telemetry family not currently present, first identify the target TA/parser contract and add a source-native renderer plus regression test. Never solve it by modifying the TA.

---

## 18. Quality bar

Asteron should feel like a functioning enterprise in which an analyst reconstructs an intrusion from mutually consistent evidence—not a bag of obvious IOCs.

Prefer fewer high-fidelity source families over a larger number of toy records. However, broad environment variety is an explicit training goal: Windows, Linux, cloud, identity, endpoint, physical access, multiple network vendors, management services, and network telemetry should all coexist.

Harder tiers become difficult through:

- more paths;
- more vendor/region variation;
- longer correlations;
- legitimate lookalikes;
- partial detections;
- normal administrative tooling;
- ambiguous but resolvable context;

—not through malformed data, missing required parser fields, or arbitrary timestamp inconsistency.

When in doubt, preserve the validated source-native contract and make the investigation harder through context rather than worse telemetry.
