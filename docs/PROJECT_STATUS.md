# Project status

| Track | Status | Static campaign | Questions | Hints | Target-Splunk validation |
|---|---|---:|---:|---:|---|
| Easy | validated | 1,113 events | 180 | 360 | complete baseline |
| Medium | authoring | 65 events | 170 | 510 | pending |
| Hard | authoring | 75 events | 150 | 450 | pending |

All tracks use the same contract:

- fixed APT evidence: `scenario_data/<track>/attack_events.jsonl`
- canonical CTF content: `question_bank/<track>/`
- generated participant corpus: `dataset/<track>/`
- track detections: `splunk/detections/<track>/`
- instructor finding dispositions: `instructor/findings/`

Medium and Hard are authored but remain `authoring` until their fresh-index TA/CIM parsing and every reference answer search are verified in the target Splunk environment.
