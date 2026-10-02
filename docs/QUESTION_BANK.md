# Question bank

`question_bank/<track>/` is the **only committed source** for questions, answers, and hints.

## Files

```text
question_bank/<track>/questions.csv
question_bank/<track>/answers.csv
question_bank/<track>/hints.csv
question_bank/<track>/STATUS.md
```

`questions.csv` contains both runtime fields and instructor authoring metadata, including `Subject`, `ChallengeID`, `PrimarySourcetype`, `LearningObjective`, and `ReferenceSPL`.

`answers.csv` contains the answer plus `AnswerType`. `hints.csv` contains the progressive CTF hints.

Do not create synchronized copies under `instructor/` or `participant/`; those copies drift. The CTF registration/import process should use the files in `question_bank/<track>/` directly.

## Current banks

| Track | Questions | Hints per question | Status |
|---|---:|---:|---|
| Easy | 180 | 2 | validated |
| Medium | 170 | 3 | runtime validation pending |
| Hard | 150 | 3 | runtime validation pending |

## Authoring rules

1. The scenario index is given to the participant; do not ask them to discover it.
2. Evidence must exist before a question is accepted.
3. Every question needs a deterministic answer and a usable `ReferenceSPL`.
4. Answer-bearing values are stable interfaces: changing hosts, users, IPs, times, files, byte counts, source/sourcetype, or parser fields may invalidate questions.
5. Multi-value answers must show the expected delimiter without revealing the answer. Use examples such as `value1;value2` for sets or `value1>value2>value3` for ordered sequences.
6. Easy should explain unfamiliar sources/fields early. Medium and Hard should increasingly require correlation rather than IOC lookup.
7. Do not promote Medium/Hard until their reference searches have been validated against the target Splunk field extractions.
