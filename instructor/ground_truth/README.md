# Instructor Ground Truth

**Instructor only. Do not distribute this directory to participants.**

The static campaign source of truth remains `scenario_data/<track>/attack_events.jsonl`.
This directory provides human-readable summaries for validating questions, answers, detections, and investigation paths.

## Files

For each normalized Medium/Hard track:

- `<track>_scenario.md` — campaign narrative, static corpus size, signal ratio, and canonical path.
- `<track>_evidence_matrix.csv` — one row per activity/truth grouping with time range, event count, hosts, sourcetypes, and ATT&CK techniques.
- `<track>_tactic_summary.csv` — malicious activity counts summarized by technique.

Easy retains the equivalent files for comparison. Notable-specific dispositions live in `instructor/findings/`.

## Normalized difficulty

| Track | Static events | Malicious/corroborating | Fixed benign lookalikes | Malicious ratio |
|---|---:|---:|---:|---:|
| Easy | 1,113 | 1,096 | 17 | 98.5% |
| Medium | 1,250 | 650 | 600 | 52.0% |
| Hard | 1,500 | 450 | 1,050 | 30.0% |

The original answer-bearing Medium and Hard event spines are preserved unchanged inside the expanded corpora. Difficulty increases through ambiguity, authorization context, and correlation requirements rather than by removing evidence.
