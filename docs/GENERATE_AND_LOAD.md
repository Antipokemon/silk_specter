# Generation model

## What is fixed

Each track has one canonical APT evidence file:

```text
scenario_data/<track>/attack_events.jsonl
```

Questions, answers, reference searches, and authored findings depend on these events. Normal generation must not modify them or shift the configured scenario window.

## What is generated

`generator/generate.py` combines the static campaign with track-specific background/enterprise activity and writes:

```text
dataset/<track>/
├── raw/
├── hec/events.jsonl
├── ingest_manifest.csv
├── expected_counts.csv
├── manifest.json
└── notables/
    ├── raw/notables.log
    ├── hec/events.jsonl
    ├── ingest_manifest.csv
    ├── expected_counts.csv
    └── manifest.json
```

Generated participant data contains no truth labels or instructor dispositions. The static campaign file is the ground-truth source for answer-bearing activity.

## Commands

```bash
make generate-easy
make generate-medium
make generate-hard
```

Direct equivalents:

```bash
python3 generator/generate.py --scenario easy --output dataset/easy
python3 generator/generate.py --scenario medium --allow-authoring --output dataset/medium
python3 generator/generate.py --scenario hard --allow-authoring --output dataset/hard
```

Noise volume can be overridden without changing the attack chain:

```bash
make generate-hard BACKGROUND_EVENTS=30000 ENTERPRISE_BACKGROUND_EVENTS=250000
```

Notable noise is deterministic and configured per track. The participant notable feed contains only event fields; expected dispositions remain under `instructor/findings/`.

For the end-to-end operator sequence, use [`QUICKSTART.md`](QUICKSTART.md).
