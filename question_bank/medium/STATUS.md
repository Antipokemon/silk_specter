# Medium question bank status

- Status: **authoring / runtime validation pending**
- Target questions: **170**
- Questions authored: **170**
- Hints: **3 progressive hints per question**
- Answer-bearing campaign evidence is static in `scenario_data/medium/attack_events.jsonl`.
- `generator/scenarios/medium.py` loads those committed records; it does not synthesize attack-chain evidence.
- Medium intentionally has reduced notable coverage: eight detection SPLs provide pivots, while multiple attack stages require raw-event correlation.
- Do not mark Medium `validated` until the static campaign and question bank pass Splunk TA/CIM and answer validation in a fresh index.
