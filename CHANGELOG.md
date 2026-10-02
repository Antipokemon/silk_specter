# Changelog

## Unreleased

### Canonical-source cleanup

- Made `question_bank/<track>/` the single committed question/answer/hint source and merged instructor metadata/answer types into those files.
- Removed duplicate instructor/participant question exports, duplicate static-event ground-truth CSVs, legacy generated ground-truth copies, the historical release snapshot, and the duplicate participant topology SVG.
- Changed notable generation to use `scenario_data/<track>/attack_events.jsonl` directly.
- Updated tests and documentation to the canonical layout and added loader workflow checks for all tracks.


### Track/data consistency

- Standardized all tracks on committed static answer-bearing campaign files under `scenario_data/<track>/attack_events.jsonl`.
- Added the validated Easy campaign as static evidence without changing the committed Easy participant dataset.
- Added ingest-ready `raw/` and `hec/` baseline datasets for Medium and Hard under `dataset/<track>/`.
- Standardized generated layout, manifests, expected counts, and scenario-scoped ground truth across Easy/Medium/Hard.

### Questions and difficulty tracks

- Easy question bank: 180 questions / 360 hints.
- Medium question bank: 170 questions / 510 hints with static multi-region campaign evidence.
- Hard question bank: 150 questions / 450 hints with global/OT-adjacent static campaign evidence.
- Preserved subject grouping and explicit answer-format guidance for multi-value answers.

### Notables

- Added deterministic synthetic ES-style notable feeds under `dataset/<track>/notables/`.
- Added expected campaign findings plus benign/questionable notable noise.
- Noise scales with difficulty: Easy 25, Medium 60, Hard 120 noise events.
- Added `scripts/load_notables.sh` with track-index drilldown substitution.
- Added instructor-only notable ground truth without leaking disposition into participant events.

### Repository cleanup

- Consolidated release history into this file.
- Added `docs/QUICKSTART.md` for a short generate/index/ingest/notable workflow.
- Simplified the root README and generation documentation.
- Added Make targets for all three tracks.

## v0.3.0 — repository/reproducibility baseline

- Added `AGENTS.md`, Git-ready project files, scenario registry, UTC scenario windows, reusable network-flow helpers, and repository-readiness tests.
- Added Easy/Medium/Hard scenario configuration and question-bank architecture.
- Added network-layout, TA-compatibility, Splunk-load, scenario-authoring, and question-bank documentation.
- Preserved the validated v0.2.3 Easy corpus and TA/data contracts.

## v0.2.3 — generator/data compatibility corrections

- Standardized Windows Security and Sysmon on `sourcetype=XmlWinEventLog` with channel-specific `source` values.
- Added/retained Security 4624, 4625, 4688, 4769 and account/group change events.
- Preserved Sysmon IDs 1, 3, 11, and 22 with event-appropriate fields.
- Added Junos authentication failures, TACACS PASS/FAIL diversity, WSUS status diversity, and Defender AlertInfo/AlertEvidence Event Hub records.
- Corrected X.509 fingerprint formatting and constrained WSUS examples to the campaign date window.

## v0.2.2 — TA compatibility corrections

- Corrected Cisco ASA connection IDs, Cisco IOS auth/config events, AWS CloudTrail service schemas, Defender Event Hub layout, FortiGate sourcetype, Ivanti update telemetry, Junos sourcetypes, Linux audit coverage, PAN-OS traffic shape, Windows source metadata, and Tenable schema.
