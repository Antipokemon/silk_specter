# SILK SPECTER engineering contract

Read this before changing generators, scenarios, questions, detections, or Splunk ingest metadata.

## Mission and safety

SILK SPECTER is a defensive Splunk investigation/CTF in the fictional Asteron Utilities Group environment. Actor behavior is represented only as inert synthetic telemetry. Do not add live exploit payloads, malware, real credentials, or operational exfiltration tooling.

## Quality gates

- `easy`: validated
- `medium`: authoring / target-Splunk runtime validation pending
- `hard`: authoring / target-Splunk runtime validation pending

Never mark Medium or Hard validated because local code/tests pass. Promotion requires fresh-index parsing, relevant CIM checks, question reference-query validation, and notable validation in the target Splunk lab.

## Canonical sources

```text
config/scenarios/<track>.json                 status/window/seed/index
scenario_data/<track>/attack_events.jsonl     fixed answer-bearing APT evidence
question_bank/<track>/questions.csv           canonical questions/reference SPL
question_bank/<track>/answers.csv             canonical answers/types
question_bank/<track>/hints.csv               canonical hints
generator/                                    background/noise + static-event loading
dataset/<track>/                              generated participant corpus
splunk/detections/<track>/                    detection searches
instructor/findings/                          expected finding dispositions
docs/TA_COMPATIBILITY.md                      parser/source contracts
```

Do not create parallel question/answer/hint copies under `instructor/` or `participant/`. Do not create separate static-event ground-truth CSV copies; `scenario_data/<track>/attack_events.jsonl` is the source of truth.

## Static evidence contract

Answer-bearing APT evidence is immutable during ordinary generation. Background volume may change, but the generator must not change static hosts, users, IPs, times, filenames, hashes, byte counts, commands, source/sourcetype, or other values used by questions/reference searches.

If static evidence must change, update and revalidate all affected questions, answers, hints, findings, and detections together.

## Question contract

`question_bank/<track>/questions.csv` contains runtime fields plus `Subject`, `ChallengeID`, `PrimarySourcetype`, `LearningObjective`, and `ReferenceSPL`. `answers.csv` includes `AnswerType`.

Multi-value questions must state the input delimiter with a generic example. Easy normally has two progressive hints; Medium/Hard normally have three.

## Difficulty contract

- Easy: clearer pivots, stronger useful finding coverage, less alert noise.
- Medium: multi-region correlation, staging/cleanup, benign admin lookalikes, partial findings.
- Hard: sparse useful findings, substantial benign overlap, global/OT-adjacent pivots, approved-service abuse.

Difficulty should come from ambiguity and correlation depth, not unrealistic missing telemetry.

## Splunk compatibility

Treat `docs/TA_COMPATIBILITY.md` as a non-regression contract. Vendor TA behavior wins over synthetic convenience. Fix the generator, not the vendor TA.

Important stable conventions include generic `XmlWinEventLog` with channel-specific `source`, Corelight-compatible `bro:*:json` sourcetypes, vendor-native firewall shapes, realistic CloudTrail service schemas, and the Event Hub Defender layout.

## Required checks

Before handing off changes:

```bash
make validate
```

For generation changes, smoke-test all tracks. For runtime/parser-sensitive changes, load a fresh Splunk index using `docs/QUICKSTART.md` and compare counts to the generated manifests.

## Documentation ownership

Keep the root README short. Operator steps belong in `docs/QUICKSTART.md`; generation behavior in `docs/GENERATE_AND_LOAD.md`; parser contracts in `docs/TA_COMPATIBILITY.md`; question rules in `docs/QUESTION_BANK.md`; scenario rules in `docs/SCENARIO_AUTHORING.md`.
