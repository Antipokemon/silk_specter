# Scenario authoring

## Core contract

Every track has two separate layers:

```text
scenario_data/<track>/attack_events.jsonl   fixed answer-bearing evidence
generator/*                                  regenerable background/noise
```

Once questions are authored, the static campaign is immutable unless the affected questions, answers, hints, findings, and reference searches are updated and revalidated together.

## Difficulty

**Easy** uses clearer pivots, stronger finding coverage, and less alert noise.

**Medium** uses multi-region correlation, legitimate admin lookalikes, deliberate staging/cleanup, and incomplete finding coverage.

**Hard** uses sparse useful findings, substantial benign overlap, global/OT-adjacent pivots, approved-service abuse, and proof-by-correlation rather than obvious IOCs.

## Time

The committed CTF tracks have fixed UTC windows in `config/scenarios/<track>.json`. Static campaign tracks must not be shifted with `--start` or `--end`, because questions and reference searches depend on their exact chronology.

## Correlation quality

A meaningful actor action should fan out into the telemetry sources that would realistically observe it: endpoint, authentication, Zeek/Corelight, firewall/NAT, cloud/application audit, EDR, file activity, or management tooling as appropriate. Difficulty should come from ambiguity and signal-to-noise, not from unrealistically missing telemetry.

## Workflow

1. Define the fixed scenario window and attack path.
2. Author source-native static events plus benign lookalikes.
3. Add expected detections/findings and dispositions.
4. Generate surrounding noise.
5. Author questions only against fixed evidence.
6. Run `make validate`.
7. Load a fresh Splunk index and validate TA/CIM parsing and reference searches.
8. Mark the track `validated` only after runtime validation passes.
