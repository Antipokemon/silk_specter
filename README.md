# SILK SPECTER

SILK SPECTER is a synthetic Splunk investigation/CTF for the fictional Asteron Utilities Group. It contains Easy, Medium, and Hard tracks with fixed answer-bearing APT evidence and regenerable background noise.

## Start here

For the operator workflow, use **[`docs/QUICKSTART.md`](docs/QUICKSTART.md)**.

```bash
make validate
make generate-easy       # or generate-medium / generate-hard
./scripts/load_to_splunk.sh easy asteron_easy_v001
./scripts/load_notables.sh easy asteron_easy_v001 notable
```

Medium and Hard are still runtime-validation gated, so their load command requires `ALLOW_AUTHORING=1` until their Splunk validation is complete.

## Source-of-truth layout

```text
scenario_data/<track>/attack_events.jsonl   fixed APT evidence
question_bank/<track>/questions.csv         canonical questions + reference metadata
question_bank/<track>/answers.csv           canonical answers + answer types
question_bank/<track>/hints.csv             canonical hints
dataset/<track>/                             generated/ingest-ready participant data
splunk/detections/<track>/                   track detection searches
instructor/findings/                         expected finding dispositions
```

There is only one committed question/answer/hint source: `question_bank/<track>/`. Participant CSV copies and separate instructor question copies are intentionally not stored.

## Track state

| Track | Status | Questions | Hints | Static APT events | Notable noise |
|---|---|---:|---:|---:|---:|
| Easy | validated | 180 | 360 | 1,113 | 25 |
| Medium | authoring | 170 | 510 | 65 | 60 |
| Hard | authoring | 150 | 450 | 75 | 120 |

The Medium/Hard static campaigns are intentionally fixed, but still need target-Splunk parser/CIM/reference-query validation before promotion to `validated`.

## Difficulty model

- **Easy:** clearer pivots and more useful detection coverage.
- **Medium:** multi-region correlation, staging, partial finding coverage, and more alert noise.
- **Hard:** sparse useful findings, legitimate lookalikes, global/OT-adjacent pivots, and heavy alert noise.

## Documentation

- `docs/QUICKSTART.md` — shortest generate/load workflow
- `docs/GENERATE_AND_LOAD.md` — what generation changes and preserves
- `docs/SPLUNK_LOAD.md` — loader behavior and troubleshooting
- `docs/QUESTION_BANK.md` — canonical question schema and authoring rules
- `docs/SCENARIO_AUTHORING.md` — static-campaign authoring contract
- `docs/TA_COMPATIBILITY.md` — Splunk source/sourcetype contracts
- `VALIDATION.md` — current validation status
- `CHANGELOG.md` — consolidated history

All identities, infrastructure, and activity are fictional. The repo contains inert defensive telemetry, not live exploit payloads, malware, credentials, or operational exfiltration tooling.
