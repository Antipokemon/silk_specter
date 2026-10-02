# Project status

| Track | Status | Static campaign | Questions | Hints | Target-Splunk validation |
|---|---|---:|---:|---:|---|
| Easy | validated | 1,113 events | 180 | 360 | complete baseline |
| Medium | authoring | 1,250 events | 170 | 510 | pending |
| Hard | authoring | 1,500 events | 150 | 450 | pending |

All tracks use the same contract:

- fixed APT evidence: `scenario_data/<track>/attack_events.jsonl`
- canonical CTF content: `question_bank/<track>/`
- generated participant corpus: `dataset/<track>/`
- track detections: `splunk/detections/<track>/`
- instructor static evidence summaries: `instructor/ground_truth/`
- instructor finding dispositions: `instructor/findings/`

Medium and Hard are authored but remain `authoring` until their fresh-index TA/CIM parsing and every reference answer search are verified in the target Splunk environment.

## Static difficulty normalization

- Easy: 1,113 static events; clear campaign-heavy evidence.
- Medium: 1,250 static events; 650 malicious/corroborating and 600 fixed benign lookalikes.
- Hard: 1,500 static events; 450 malicious/corroborating and 1,050 fixed benign/admin lookalikes across a broader source mix.

The original Medium 65-event and Hard 75-event answer-bearing spines are preserved inside those normalized corpora.
