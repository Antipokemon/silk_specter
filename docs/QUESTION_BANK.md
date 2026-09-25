# Question-bank architecture

Final target: **500 questions** across one persistent Asteron environment.

| Tier | Target | Current | Training model |
|---|---:|---:|---|
| Easy | 180 | **180** | discovery-first, 2 progressive hints, clearer pivots/notables |
| Medium | 170 | 0 | multi-source/multi-region correlation, 3 hints normally, staging and partial detection coverage |
| Hard | 150 | 0 | global heterogeneous environment, sparse/ambiguous findings, legitimate lookalikes, 3 strategic hints |

## Authoring rules

1. The participant is given the scenario index. Do not spend questions asking them to discover the index.
2. Data must exist before a question is accepted.
3. Every question has a deterministic answer and instructor-only reference SPL.
4. Prefer precise language such as **Windows Security logs**, **DNS records**, **network connection records**, **firewall traffic**, or **endpoint-security alerts** rather than vague terms such as *telemetry*.
5. Easy is written for newer analysts: early hints explain what a log type/field means, then provide a progressively narrower search approach. Later Easy questions reduce scaffolding and require cross-source pivots.
6. Participant exports never contain answers, reference SPL, activity IDs, ATT&CK ground truth, or malicious/benign truth labels.
7. Answer-bearing data is an API: changing hosts, IPs, usernames, times, byte counts, filenames, destinations, source/sourcetype, or parser fields may invalidate questions.
8. Do not create Medium/Hard answers before their distinct scenario data exists and passes the same parser/CIM validation used for Easy.

## Current state

Easy contains the complete **180-question** bank tied to the validated Easy dataset. Medium and Hard intentionally remain schema-only until their separate campaigns are authored and validated.
