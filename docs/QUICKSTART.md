# Quick start

These are the normal steps for any track.

If this is a fresh Git clone, materialize the committed baseline datasets first:

```bash
git lfs pull
```

You can skip that download when you intend to regenerate the assigned track immediately.

## 1. Generate the track

From the repo root:

```bash
make generate-easy
# or
make generate-medium
# or
make generate-hard
```

Generation rebuilds `dataset/<track>/` from the fixed campaign plus deterministic noise. It does **not** change `scenario_data/<track>/attack_events.jsonl` or the question bank.

Optional larger noise volume:

```bash
make generate-medium BACKGROUND_EVENTS=20000 ENTERPRISE_BACKGROUND_EVENTS=150000
```

## 2. Run local validation

```bash
make validate
```

## 3. Create a fresh Splunk index and ingest the main data

Easy:

```bash
./scripts/load_to_splunk.sh easy asteron_easy_v001
```

Medium:

```bash
ALLOW_AUTHORING=1 ./scripts/load_to_splunk.sh medium asteron_medium_v001
```

Hard:

```bash
ALLOW_AUTHORING=1 ./scripts/load_to_splunk.sh hard asteron_hard_v001
```

The loader installs/updates `TA-asteron-v3`, restarts Splunk, asks for Splunk CLI login, creates the new index, and loads `dataset/<track>/hec/events.jsonl`.

Always use a fresh index name after changing or regenerating a corpus.

## 4. Ingest synthetic notables

If Splunk ES provides `index=notable`:

```bash
./scripts/load_notables.sh easy asteron_easy_v001 notable
./scripts/load_notables.sh medium asteron_medium_v001 notable
./scripts/load_notables.sh hard asteron_hard_v001 notable
```

For a non-ES lab, create a lab-only notable index:

```bash
CREATE_NOTABLE_INDEX=1 \
./scripts/load_notables.sh medium asteron_medium_v001 asteron_notable
```

## 5. Verify

Main event count:

```spl
| tstats count where index=asteron_medium_v001
```

Sourcetypes:

```spl
| tstats count where index=asteron_medium_v001 by sourcetype
| sort - count
```

Notables:

```spl
index=notable source=notable sourcetype=stash scenario=medium
| stats count by rule_name urgency
| sort - count
```

Use these files as the expected-count source of truth for the generated build:

```text
dataset/<track>/manifest.json
dataset/<track>/expected_counts.csv
dataset/<track>/notables/manifest.json
```

For loader details, see [`SPLUNK_LOAD.md`](SPLUNK_LOAD.md).
