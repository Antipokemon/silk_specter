# Question-bank architecture

Final target: **500 questions** across one persistent Asteron environment.

| Tier | Target | Training model |
|---|---:|---|
| Easy | 180 | discovery-first, 2 hints normally, clearer pivots/notables |
| Medium | 170 | multi-source/multi-region correlation, 3 hints normally, staging and partial detection coverage |
| Hard | 150 | global heterogeneous environment, sparse/ambiguous findings, legitimate lookalikes, 3 strategic hints |

Each scenario has `question_bank/<scenario>/questions.csv`, `answers.csv`, `hints.csv`, and `STATUS.md`.

## Authoring rules

1. Telemetry exists before the question is accepted.
2. Every question has a deterministic answer and instructor-only reference SPL.
3. Hints teach investigation, not the answer. Easy starts by teaching `tstats` discovery and gradually removes scaffolding.
4. Participant exports never contain answer, reference SPL, activity IDs, ATT&CK IDs, truth labels, or disposition ground truth.
5. Answer-bearing telemetry is an API: changing hosts, bytes, usernames, times, destinations, or source/sourcetype may invalidate questions and requires revalidation.
6. Do not create Medium/Hard answers before their distinct scenario data is authored and validated.

## Current state

Easy contains the 25-question validated starter pool. Medium and Hard intentionally ship with schema-only pools until their distinct campaigns exist.
